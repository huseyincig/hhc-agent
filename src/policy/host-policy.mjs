import crypto from 'node:crypto';

export const HOST_POLICY_CONTRACT_VERSION = '1.0.0';
export const HOST_POLICY_FEATURE = 'host_policy_v1';
export const BROWSER_POLICY_FEATURE = 'browser_policy_v1';
export const BROWSER_POLICY_V2_FEATURE = 'browser_policy_v2';
export const WORKSPACE_ROOTS_FEATURE = 'workspace_roots_v1';

export const HOST_POLICY_CAPABILITIES = Object.freeze([
  'automatic_client_updates',
  'browser_downloads',
  'browser_existing_attach',
  'browser_headed',
  'browser_private_network',
  'browser_script_exec',
  'browser_uploads',
  'directory_manage',
  'file_delete',
  'file_move',
  'file_read',
  'file_write',
  'gui_launch',
  'log_read',
  'package_management',
  'privileged_exec',
  'process_inspect',
  'process_terminate',
  'service_control',
  'service_status',
  'shell_exec',
  'system_snapshot'
]);

/** @param {unknown} v @returns {v is Record<string, unknown>} */
const isObject = (v) => Boolean(v && typeof v === 'object' && !Array.isArray(v));
/** @param {unknown} a @param {unknown} b */
const sameArray = (a, b) =>
  Array.isArray(a) &&
  Array.isArray(b) &&
  a.length === b.length &&
  a.every(/** @param {unknown} v @param {number} i */ (v, i) => v === b[i]);

/** @param {unknown} value @returns {Record<string, boolean>|null} */
function completeCapabilities(value) {
  if (!isObject(value)) return null;
  const keys = Object.keys(value).sort();
  if (!sameArray(keys, HOST_POLICY_CAPABILITIES)) return null;
  for (const key of keys) if (typeof value[key] !== 'boolean') return null;
  /** @type {Record<string, boolean>} */
  const out = {};
  for (const k of HOST_POLICY_CAPABILITIES) out[k] = value[k] === true;
  return out;
}

/** @param {unknown} policy */
export function canonicalPolicyPayload(policy) {
  if (!isObject(policy))
    throw Object.assign(new Error('HOST_POLICY_INVALID'), { code: 'HOST_POLICY_INVALID' });
  const capabilities = completeCapabilities(policy.capabilities);
  if (
    typeof policy.client_id !== 'string' ||
    !policy.client_id ||
    policy.contract_version !== HOST_POLICY_CONTRACT_VERSION ||
    !Number.isInteger(policy.revision) ||
    (typeof policy.revision === 'number' && policy.revision < 1) ||
    !['read_only', 'standard', 'full', 'custom'].includes(
      typeof policy.profile === 'string' ? policy.profile : ''
    ) ||
    !capabilities
  )
    throw Object.assign(new Error('HOST_POLICY_INVALID'), { code: 'HOST_POLICY_INVALID' });
  return JSON.stringify({
    client_id: policy.client_id,
    contract_version: policy.contract_version,
    revision: policy.revision,
    profile: policy.profile,
    capabilities
  });
}

/** @param {unknown} policy */
export function computePolicyDigest(policy) {
  return crypto
    .createHash('sha256')
    .update(Buffer.from(canonicalPolicyPayload(policy), 'utf8'))
    .digest('hex');
}
/** @param {unknown} roots */
function isValidRootsShape(roots) {
  if (!isObject(roots)) return false;
  for (const key of ['allowed_read_roots', 'allowed_write_roots']) {
    const list = roots[key];
    if (list !== undefined && (!Array.isArray(list) || list.some((x) => typeof x !== 'string')))
      return false;
  }
  return true;
}

/** @param {unknown} [job] */
export function policyExtraRoots(job) {
  const holder = /** @type {{agent_policy_roots?: unknown}} */ (job || {});
  const raw = holder.agent_policy_roots;
  const roots =
    raw && typeof raw === 'object' && !Array.isArray(raw)
      ? /** @type {Record<string, unknown>} */ (raw)
      : null;
  /** @param {string} key @returns {Array<string>} */
  const pick = (key) => {
    const list = roots?.[key];
    if (!Array.isArray(list)) return [];
    return list.filter(/** @param {unknown} x */ (x) => typeof x === 'string');
  };
  return { read: pick('allowed_read_roots'), write: pick('allowed_write_roots') };
}

/** @param {unknown} policy @param {string} clientId */
export function validatePolicy(policy, clientId) {
  if (!isObject(policy)) return { ok: false, error: 'HOST_POLICY_NOT_READY' };
  const base = ['capabilities', 'client_id', 'contract_version', 'digest', 'profile', 'revision'];
  const keys = Object.keys(policy).sort();
  const withRoots = [...base, 'roots'].sort();
  if (!sameArray(keys, base) && !sameArray(keys, withRoots))
    return { ok: false, error: 'HOST_POLICY_NOT_READY' };
  if (policy.roots !== undefined && !isValidRootsShape(policy.roots))
    return { ok: false, error: 'HOST_POLICY_NOT_READY' };
  if (policy.client_id !== clientId) return { ok: false, error: 'HOST_POLICY_NOT_READY' };
  if (typeof policy.digest !== 'string' || !/^[0-9a-f]{64}$/.test(policy.digest))
    return { ok: false, error: 'HOST_POLICY_DIGEST_MISMATCH' };
  let digest;
  try {
    digest = computePolicyDigest(policy);
  } catch {
    return { ok: false, error: 'HOST_POLICY_NOT_READY' };
  }
  if (digest !== policy.digest) return { ok: false, error: 'HOST_POLICY_DIGEST_MISMATCH' };
  return { ok: true, policy: structuredClone(policy) };
}

/** @param {string} tool @param {Record<string, unknown>} [payload] @param {string} [origin] */
export function requiredCapabilitiesForOperation(tool, payload = {}, origin = 'mcp') {
  if (tool === 'client_update')
    return origin === 'automatic_update' ? ['automatic_client_updates'] : [];
  /** @type {Record<string, Array<string>>} */
  const direct = {
    system_snapshot: ['system_snapshot'],
    log_read: ['log_read'],
    file_read: ['file_read'],
    file_list: ['file_read'],
    file_search: ['file_read'],
    service_status: ['service_status'],
    gui_launch: ['gui_launch'],
    gui_close: ['gui_launch'],
    browser_navigate: ['gui_launch'],
    browser_interact: ['gui_launch'],
    browser_snapshot: ['gui_launch'],
    shell_exec: ['shell_exec'],
    file_read_many: ['file_read'],
    file_stat: ['file_read'],
    directory_tree: ['file_read'],
    file_edit: ['file_write'],
    process_start: ['shell_exec'],
    process_output: ['shell_exec'],
    process_input: ['shell_exec'],
    process_list: ['shell_exec'],
    process_terminate: ['shell_exec'],
    service_list: ['service_status'],
    service_start: ['service_control'],
    service_stop: ['service_control'],
    service_restart: ['service_control'],
    log_follow_start: ['log_read'],
    log_follow_read: ['log_read'],
    log_follow_stop: ['log_read'],
    browser_create: ['gui_launch'],
    browser_close: ['gui_launch'],
    browser_find: ['gui_launch'],
    browser_tabs: ['gui_launch'],
    browser_take_screenshot: ['gui_launch'],
    browser_console_messages: ['gui_launch'],
    browser_network_requests: ['gui_launch'],
    browser_file_upload: ['gui_launch'],
    privileged_shell_exec: ['privileged_exec', 'shell_exec'],
    directory_create: ['directory_manage']
  };
  if (tool === 'browser_create') {
    const out = new Set(['gui_launch']);
    if (String(payload?.mode || 'managed').toLowerCase() === 'existing')
      out.add('browser_existing_attach');
    if (payload?.headless === false) out.add('browser_headed');
    return [...out].sort();
  }
  if (tool === 'browser_interact') {
    const action = String(payload?.action || '').toLowerCase();
    if (action === 'evaluate') return ['browser_script_exec', 'gui_launch'].sort();
    return ['gui_launch'];
  }
  if (tool === 'browser_file_upload') return ['browser_uploads', 'gui_launch'].sort();
  if (tool === 'file_write')
    return [
      ...new Set(['file_write', ...(payload.create_parents === true ? ['directory_manage'] : [])])
    ].sort();
  if (tool === 'file_move')
    return [
      ...new Set(['file_move', ...(payload.overwrite === true ? ['file_delete'] : [])])
    ].sort();
  if (tool === 'file_delete')
    return [
      ...new Set(['file_delete', ...(payload.recursive === true ? ['directory_manage'] : [])])
    ].sort();
  return [...(direct[tool] || [])].sort();
}

/** @param {Record<string, unknown>} [job] @returns {{ok: boolean, bound?: boolean, error?: string, policy_contract_version?: string, policy_revision?: number, policy_digest?: string, required_capabilities?: Array<string>, admission_origin?: string}} */
export function policyBindingFromJob(job) {
  const record = /** @type {Record<string, unknown>} */ (job || {});
  const fields = [
    'policy_contract_version',
    'policy_revision',
    'policy_digest',
    'required_capabilities',
    'admission_origin'
  ];
  const present = fields.filter((k) => record[k] != null);
  if (present.length === 0) return { ok: true, bound: false };
  if (present.length !== fields.length)
    return { ok: false, error: 'HOST_POLICY_CAPABILITY_BINDING_MISMATCH' };
  if (record.policy_contract_version !== HOST_POLICY_CONTRACT_VERSION)
    return { ok: false, error: 'HOST_POLICY_CAPABILITY_BINDING_MISMATCH' };
  const revision = record.policy_revision;
  if (typeof revision !== 'number' || !Number.isInteger(revision) || revision < 1)
    return { ok: false, error: 'HOST_POLICY_CAPABILITY_BINDING_MISMATCH' };
  const digest = record.policy_digest;
  if (typeof digest !== 'string' || !/^[0-9a-f]{64}$/.test(digest))
    return { ok: false, error: 'HOST_POLICY_CAPABILITY_BINDING_MISMATCH' };
  const origin = record.admission_origin;
  if (
    origin !== 'mcp' &&
    origin !== 'admin_api' &&
    origin !== 'automatic_update' &&
    origin !== 'system'
  )
    return { ok: false, error: 'HOST_POLICY_CAPABILITY_BINDING_MISMATCH' };
  const caps = record.required_capabilities;
  /** @param {unknown} x @returns {boolean} */
  const isNonString = (x) => typeof x !== 'string';
  if (!Array.isArray(caps) || caps.some(isNonString)) {
    return { ok: false, error: 'HOST_POLICY_CAPABILITY_BINDING_MISMATCH' };
  }
  const strings = /** @type {Array<string>} */ (caps.filter((x) => typeof x === 'string'));
  const required = [...new Set(strings)].sort();
  if (!sameArray(required, strings))
    return { ok: false, error: 'HOST_POLICY_CAPABILITY_BINDING_MISMATCH' };
  return {
    ok: true,
    bound: true,
    policy_contract_version:
      typeof record.policy_contract_version === 'string' ? record.policy_contract_version : '',
    policy_revision: revision,
    policy_digest: digest,
    required_capabilities: required,
    admission_origin: origin
  };
}

/** @param {Record<string, unknown>} [job] @param {{revision: number, digest: string, capabilities?: Record<string, boolean>}|null} [currentPolicy] @param {{transportProtected?: boolean}} [options] @returns {{ok: boolean, bound?: boolean, error?: string, denied_capabilities?: Array<string>, binding?: {policy_contract_version: string, policy_revision: number, policy_digest: string, required_capabilities: Array<string>, admission_origin: string}}} */
export function authorizeBoundJob(job, currentPolicy, { transportProtected = false } = {}) {
  const binding = policyBindingFromJob(job);
  if (!binding.ok) return binding;
  if (!binding.bound) return { ok: true, bound: false };

  const rawPayload = job?.request_payload;
  const payload = /** @type {Record<string, unknown>} */ (
    rawPayload && typeof rawPayload === 'object' && !Array.isArray(rawPayload) ? rawPayload : {}
  );
  const expected = requiredCapabilitiesForOperation(
    String(job?.tool || ''),
    payload,
    typeof binding.admission_origin === 'string' ? binding.admission_origin : 'mcp'
  );
  const manualUpdateException =
    job?.tool === 'client_update' &&
    binding.admission_origin === 'admin_api' &&
    expected.length === 0;
  // client_uninstall carries empty capabilities by contract (mirrors the
  // central admission exemption and planClientUninstallAuthorization).
  // 'mcp' origin mirrors the dispatcher mcp:admin scope gate.
  const adminUninstallException =
    job?.tool === 'client_uninstall' &&
    (binding.admission_origin === 'admin_api' || binding.admission_origin === 'mcp') &&
    expected.length === 0;
  const boundCaps = binding.required_capabilities;
  if (
    !Array.isArray(boundCaps) ||
    !sameArray(expected, boundCaps) ||
    (!manualUpdateException && !adminUninstallException && expected.length === 0)
  ) {
    return { ok: false, error: 'HOST_POLICY_CAPABILITY_BINDING_MISMATCH' };
  }

  if (!currentPolicy) return { ok: false, error: 'HOST_POLICY_NOT_READY' };
  const boundRevision = binding.policy_revision;
  const boundDigest = binding.policy_digest;
  const boundRequired = binding.required_capabilities;
  if (
    typeof boundRevision !== 'number' ||
    typeof boundDigest !== 'string' ||
    !Array.isArray(boundRequired)
  ) {
    return { ok: false, error: 'HOST_POLICY_CAPABILITY_BINDING_MISMATCH' };
  }
  if (boundRevision > currentPolicy.revision) return { ok: false, error: 'HOST_POLICY_NOT_READY' };
  if (boundRevision < currentPolicy.revision || boundDigest !== currentPolicy.digest) {
    return { ok: false, error: 'HOST_POLICY_REVISION_STALE' };
  }

  /** @param {string} cap @returns {boolean} */
  const isDenied = (cap) => currentPolicy.capabilities?.[cap] !== true;
  const denied = boundRequired.filter(isDenied);
  if (denied.length) return { ok: false, error: 'HOST_POLICY_DENIED', denied_capabilities: denied };
  if (boundRequired.includes('privileged_exec') && !transportProtected) {
    return { ok: false, error: 'PRIVILEGED_TRANSPORT_REQUIRED' };
  }
  return {
    ok: true,
    bound: true,
    binding: {
      policy_contract_version:
        typeof binding.policy_contract_version === 'string' ? binding.policy_contract_version : '',
      policy_revision: boundRevision,
      policy_digest: boundDigest,
      required_capabilities: [...boundRequired],
      admission_origin:
        typeof binding.admission_origin === 'string' ? binding.admission_origin : 'mcp'
    }
  };
}

/** @param {Record<string, unknown>} [job] */
export function policyBindingRecord(job) {
  const binding = policyBindingFromJob(job);
  if (!binding.ok || !binding.bound) return null;
  const revision = binding.policy_revision;
  const digest = binding.policy_digest;
  const required = binding.required_capabilities;
  const contractVersion = binding.policy_contract_version;
  const origin = binding.admission_origin;
  if (
    typeof revision !== 'number' ||
    typeof digest !== 'string' ||
    !Array.isArray(required) ||
    typeof contractVersion !== 'string' ||
    typeof origin !== 'string'
  ) {
    return null;
  }
  return {
    tool: String(job?.tool || ''),
    policy_contract_version: contractVersion,
    policy_revision: revision,
    policy_digest: digest,
    required_capabilities: [...required],
    admission_origin: origin
  };
}

/**
 * Operator policy-signature pins (SYN-POL-001). kid → SPKI PEM. Rotation adds
 * a new kid here via agent update BEFORE central starts signing with it; old
 * kids stay until no signed envelope in the wild references them.
 */
export const POLICY_VERIFY_KEYS = Object.freeze({
  'hhc-policy-v1':
    '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA03tlTmMHj60dcA+vQIwMcQjFLa2h7fyWVt8s66PAPsY=\n-----END PUBLIC KEY-----\n'
});
export const POLICY_SIG_TTL_MS = 24 * 3600 * 1000;
export const POLICY_SIG_SKEW_MS = 5 * 60 * 1000;

/**
 * Verify a central policy-signature envelope against the policy object.
 * The envelope travels as a SIBLING of `policy` (never inside it — the
 * structural validator is key-strict and old agents must keep ignoring it).
 * @param {unknown} policy policy object as received
 * @param {unknown} sig envelope `{v,kid,issued_at,expires_at,sig}`
 * @param {string} clientId expected owner (binding)
 * @param {{nowMs?: number, keys?: Record<string,string>}} [options]
 */
export function verifyPolicySignature(
  policy,
  sig,
  clientId,
  { nowMs = Date.now(), keys = POLICY_VERIFY_KEYS } = {}
) {
  if (!isObject(sig)) return { ok: false, error: 'HOST_POLICY_UNSIGNED' };
  const { v, kid, issued_at, expires_at, sig: b64 } = /** @type {Record<string, unknown>} */ (sig);
  if (v !== 1) return { ok: false, error: 'HOST_POLICY_BAD_SIGNATURE' };
  const pem = typeof kid === 'string' ? keys[kid] : undefined;
  if (typeof pem !== 'string' || !pem) return { ok: false, error: 'HOST_POLICY_UNKNOWN_KEY' };
  let payload;
  try {
    payload = canonicalPolicyPayload(policy);
  } catch {
    return { ok: false, error: 'HOST_POLICY_NOT_READY' };
  }
  let body;
  try {
    body = JSON.parse(payload);
  } catch {
    return { ok: false, error: 'HOST_POLICY_NOT_READY' };
  }
  if (body.client_id !== clientId) return { ok: false, error: 'HOST_POLICY_NOT_READY' };
  const issued = Date.parse(String(issued_at || ''));
  const expires = Date.parse(String(expires_at || ''));
  if (!Number.isFinite(issued) || !Number.isFinite(expires))
    return { ok: false, error: 'HOST_POLICY_BAD_SIGNATURE' };
  if (expires - issued > POLICY_SIG_TTL_MS + POLICY_SIG_SKEW_MS)
    return { ok: false, error: 'HOST_POLICY_BAD_SIGNATURE' };
  if (nowMs + POLICY_SIG_SKEW_MS < issued || nowMs - POLICY_SIG_SKEW_MS > expires)
    return { ok: false, error: 'HOST_POLICY_EXPIRED' };
  try {
    const ok = crypto.verify(
      null,
      Buffer.from(payload, 'utf8'),
      crypto.createPublicKey(pem),
      Buffer.from(String(b64 || ''), 'base64url')
    );
    if (!ok) return { ok: false, error: 'HOST_POLICY_BAD_SIGNATURE' };
  } catch {
    return { ok: false, error: 'HOST_POLICY_BAD_SIGNATURE' };
  }
  return { ok: true };
}
