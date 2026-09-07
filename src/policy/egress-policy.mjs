import net from 'node:net';

export const EGRESS_ALLOW_SCHEMES = Object.freeze(['http:', 'https:']);

export const EGRESS_DENY_SCHEMES = Object.freeze([
  'file:',
  'ftp:',
  'data:',
  'javascript:',
  'chrome:',
  'chrome-extension:',
  'devtools:',
  'view-source:',
  'about:',
  'blob:',
  'ws:',
  'wss:'
]);

export const CLOUD_METADATA_HOSTS = Object.freeze([
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
  'instance-data-compute',
  'metadata.azure.internal'
]);

export const CLOUD_METADATA_IPS = Object.freeze(['169.254.169.254', '100.100.100.200']);

/** @param {string} label */
function parseNumericLabel(label) {
  if (/^0[xX][0-9a-fA-F]+$/.test(label)) return parseInt(label, 16);
  if (/^0[0-7]+$/.test(label) && label.length > 1) return parseInt(label, 8);
  if (/^\d+$/.test(label)) return parseInt(label, 10);
  return null;
}

/** @param {unknown} hostname */
export function normalizeHostnameIp(hostname) {
  const host = String(hostname || '').trim();
  if (!host) return null;
  if (net.isIP(host)) return host;
  if (host.includes(':')) return null;
  const labels = host.split('.');
  if (labels.length === 0 || labels.length > 4) return null;
  const parts = [];
  for (const label of labels) {
    if (label === '') return null;
    const num = parseNumericLabel(label);
    if (num == null || !Number.isSafeInteger(num) || num < 0) return null;
    parts.push(num);
  }
  let n;
  if (parts.length === 1) {
    if (parts[0] > 0xffffffff) return null;
    n = parts[0];
  } else if (parts.length === 2) {
    if (parts[0] > 255 || parts[1] > 0xffffff) return null;
    n = parts[0] * 0x1000000 + parts[1];
  } else if (parts.length === 3) {
    if (parts[0] > 255 || parts[1] > 255 || parts[2] > 0xffff) return null;
    n = parts[0] * 0x1000000 + parts[1] * 0x10000 + parts[2];
  } else {
    if (parts.some((x) => x > 255)) return null;
    n = ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
  }
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

/** @param {string} ip */
function ipv4ToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
}

/** @param {string} ip @param {string} base @param {number} bits */
function inCidr(ip, base, bits) {
  const size = Math.pow(2, 32 - bits);
  const start = Math.floor(ipv4ToInt(base) / size) * size;
  const n = ipv4ToInt(ip);
  return n >= start && n < start + size;
}

/** @param {string} ip */
function unwrapV6(ip) {
  const lower = ip.toLowerCase();
  if (lower.startsWith('::ffff:')) {
    const tail = ip.slice(7);
    if (net.isIPv4(tail)) return { kind: 'v4', ip: tail };
  }
  return { kind: 'v6', ip };
}

/** @param {unknown} rawIp */
export function classifyIp(rawIp) {
  let ip = String(rawIp || '').trim();
  if (!net.isIP(ip)) {
    const normalized = normalizeHostnameIp(ip);
    if (!normalized) return { kind: 'invalid' };
    ip = normalized;
  }
  if (net.isIPv6(ip)) {
    const unwrapped = unwrapV6(ip);
    if (unwrapped.kind === 'v4') return classifyIp(unwrapped.ip);
    const lower = ip.toLowerCase();
    if (lower === '::1') return { kind: 'v6', deny: true, reason: 'loopback' };
    if (lower === '::') return { kind: 'v6', deny: true, reason: 'unspecified' };
    const firstHextet = lower.split(':')[0] || '';
    const first = parseInt(firstHextet, 16);
    if (Number.isFinite(first)) {
      if (first >= 0xfe80 && first <= 0xfebf)
        return { kind: 'v6', deny: true, reason: 'link-local' };
      if (first >= 0xfec0 && first <= 0xfeff)
        return { kind: 'v6', deny: true, reason: 'site-local-deprecated' };
      if (first >= 0xfc00 && first <= 0xfdff)
        return { kind: 'v6', deny: false, private: true, reason: 'unique-local' };
      if (first >= 0xff00) return { kind: 'v6', deny: true, reason: 'multicast' };
    }
    return { kind: 'v6', deny: false, private: false };
  }
  if (inCidr(ip, '127.0.0.0', 8)) return { kind: 'v4', deny: true, reason: 'loopback' };
  if (inCidr(ip, '169.254.0.0', 16)) return { kind: 'v4', deny: true, reason: 'link-local' };
  if (inCidr(ip, '224.0.0.0', 4)) return { kind: 'v4', deny: true, reason: 'multicast' };
  if (inCidr(ip, '0.0.0.0', 8)) return { kind: 'v4', deny: true, reason: 'reserved' };
  if (inCidr(ip, '192.0.0.0', 24)) return { kind: 'v4', deny: true, reason: 'reserved' };
  if (inCidr(ip, '192.0.2.0', 24))
    return { kind: 'v4', deny: true, reason: 'reserved-documentation' };
  if (inCidr(ip, '198.51.100.0', 24))
    return { kind: 'v4', deny: true, reason: 'reserved-documentation' };
  if (inCidr(ip, '203.0.113.0', 24))
    return { kind: 'v4', deny: true, reason: 'reserved-documentation' };
  if (inCidr(ip, '192.88.99.0', 24)) return { kind: 'v4', deny: true, reason: 'reserved' };
  if (inCidr(ip, '240.0.0.0', 4)) return { kind: 'v4', deny: true, reason: 'reserved' };
  if (inCidr(ip, '10.0.0.0', 8) || inCidr(ip, '172.16.0.0', 12) || inCidr(ip, '192.168.0.0', 16)) {
    return { kind: 'v4', deny: false, private: true, reason: 'rfc1918' };
  }
  return { kind: 'v4', deny: false, private: false };
}

/** @param {unknown} urlString */
export function auditProjectionUrl(urlString) {
  try {
    const url = new URL(String(urlString));
    const path = url.pathname && url.pathname !== '/' ? url.pathname.slice(0, 128) : '/';
    return `${url.protocol}//${url.host.toLowerCase()}${path}`;
  } catch {
    return '(unparseable-url)';
  }
}

/**
 * @param {string} hostname
 * @param {ReadonlyArray<string>} list
 */
export function matchHostList(hostname, list) {
  const host = String(hostname || '')
    .toLowerCase()
    .replace(/\.$/, '');
  if (!host) return false;
  for (const entry of list || []) {
    const rule = String(entry || '')
      .toLowerCase()
      .replace(/\.$/, '');
    if (!rule) continue;
    if (host === rule || host.endsWith('.' + rule)) return true;
  }
  return false;
}

/**
 * @param {unknown} urlString
 * @param {{allowPrivateNetwork?: boolean, allowLoopback?: boolean, allowedHosts?: ReadonlyArray<string>, blockedHosts?: ReadonlyArray<string>, resolve?: ((hostname: string) => Promise<Array<string>>)|null, metadataIps?: ReadonlyArray<string>}} [options]
 */
export async function validateEgressUrl(
  urlString,
  {
    allowPrivateNetwork = false,
    allowLoopback = false,
    allowedHosts = [],
    blockedHosts = [],
    resolve = null,
    metadataIps = CLOUD_METADATA_IPS
  } = {}
) {
  const raw = String(urlString || '').trim();
  if (!raw) return { ok: false, error: 'URL_REQUIRED' };
  let url;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: 'URL_MALFORMED' };
  }
  if (!EGRESS_ALLOW_SCHEMES.includes(url.protocol)) {
    return { ok: false, error: 'URL_SCHEME_DENIED', scheme: url.protocol };
  }
  if (url.username || url.password) {
    return { ok: false, error: 'URL_CREDENTIALS_DENIED' };
  }
  const rawHostname = url.hostname;
  if (!rawHostname) return { ok: false, error: 'URL_HOST_REQUIRED' };
  const hostname =
    rawHostname.startsWith('[') && rawHostname.endsWith(']')
      ? rawHostname.slice(1, -1)
      : rawHostname;
  if (CLOUD_METADATA_HOSTS.includes(hostname.toLowerCase())) {
    return { ok: false, error: 'URL_METADATA_DENIED' };
  }
  // Host policy lists: blocklist first, then allowlist. Evaluated on the
  // hostname before DNS so policy intent survives rebind tricks; addresses
  // are still validated below.
  if (matchHostList(hostname, blockedHosts)) {
    return { ok: false, error: 'URL_HOST_DENIED' };
  }
  if (
    Array.isArray(allowedHosts) &&
    allowedHosts.length > 0 &&
    !matchHostList(hostname, allowedHosts)
  ) {
    return { ok: false, error: 'URL_HOST_DENIED' };
  }
  const literal = net.isIPv6(hostname) ? hostname : normalizeHostnameIp(hostname);
  if (literal) {
    return validateResolvedAddresses([literal], {
      allowPrivateNetwork,
      allowLoopback,
      metadataIps
    });
  }
  if (typeof resolve !== 'function') {
    return { ok: false, error: 'URL_DNS_VALIDATION_REQUIRED' };
  }
  let addresses;
  try {
    addresses = await resolve(hostname);
  } catch {
    return { ok: false, error: 'URL_DNS_FAILED_CLOSED' };
  }
  if (!Array.isArray(addresses) || addresses.length === 0) {
    return { ok: false, error: 'URL_DNS_FAILED_CLOSED' };
  }
  return validateResolvedAddresses(addresses, { allowPrivateNetwork, allowLoopback, metadataIps });
}

/**
 * @param {Array<unknown>} addresses
 * @param {{allowPrivateNetwork?: boolean, allowLoopback?: boolean, metadataIps?: ReadonlyArray<string>}} [options]
 */
export function validateResolvedAddresses(
  addresses,
  { allowPrivateNetwork = false, allowLoopback = false, metadataIps = CLOUD_METADATA_IPS } = {}
) {
  const normalized = [];
  for (const candidate of addresses) {
    const record = /** @type {{address?: unknown}} */ (candidate);
    const ip = typeof candidate === 'string' ? candidate : record?.address;
    const norm = normalizeHostnameIp(ip);
    normalized.push(norm || String(ip));
  }
  for (const ip of normalized) {
    if (metadataIps.includes(ip)) return { ok: false, error: 'URL_METADATA_DENIED', address: ip };
  }
  for (const ip of normalized) {
    const cls = classifyIp(ip);
    if (cls.kind === 'invalid') return { ok: false, error: 'URL_ADDRESS_INVALID', address: ip };
    if (cls.deny && !(allowLoopback === true && cls.reason === 'loopback'))
      return { ok: false, error: 'URL_ADDRESS_DENIED', reason: cls.reason, address: ip };
    if (cls.private && !allowPrivateNetwork) {
      return { ok: false, error: 'URL_PRIVATE_NETWORK_DENIED', reason: cls.reason, address: ip };
    }
  }
  return { ok: true, addresses: normalized };
}
