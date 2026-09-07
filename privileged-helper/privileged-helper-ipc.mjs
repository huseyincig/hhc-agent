import net from 'node:net';
export const PRIVILEGED_HELPER_MAX_FRAME_BYTES = 128 * 1024;
export const PRIVILEGED_HELPER_ENDPOINTS = Object.freeze({
  linux: '/run/hhc/privileged-helper-v1.sock',
  darwin: '/var/run/hhc/privileged-helper-v1.sock',
  win32: '\\\\.\\pipe\\HHCPrivilegedV1'
});
export const PRIVILEGED_HELPER_PEER_IDENTITIES = Object.freeze({
  linux: '_hhc',
  darwin: '_hhc',
  win32: 'S-1-5-19'
});

/**
 * @param {string} [platform]
 */
export function privilegedHelperEndpoint(platform = process.platform) {
  const endpoint =
    PRIVILEGED_HELPER_ENDPOINTS[/** @type {'linux' | 'darwin' | 'win32'} */ (platform)];
  if (!endpoint) throw new Error('PRIVILEGED_HELPER_PLATFORM_UNSUPPORTED');
  return endpoint;
}

/**
 * @param {string} [platform]
 */
export function privilegedHelperPeerExpectation(platform = process.platform) {
  const identity =
    PRIVILEGED_HELPER_PEER_IDENTITIES[/** @type {'linux' | 'darwin' | 'win32'} */ (platform)];
  if (!identity) throw new Error('PRIVILEGED_HELPER_PLATFORM_UNSUPPORTED');
  if (platform === 'win32')
    return {
      transport: 'named_pipe',
      identity,
      credential_check: 'windows_token',
      acl: 'SYSTEM:F;LOCAL SERVICE:RW'
    };
  return {
    transport: 'unix_socket',
    identity,
    credential_check: 'peer_credentials',
    parent_mode: '0750',
    socket_mode: '0660'
  };
}
/**
 * @param {unknown} peer
 * @param {object} [options]
 * @param {string} [options.platform]
 * @param {string} [options.identity]
 */
export function verifyPrivilegedHelperPeer(peer, { platform = process.platform, identity } = {}) {
  let expected;
  try {
    expected = privilegedHelperPeerExpectation(platform);
  } catch {
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  }
  const wanted = identity || expected.identity;
  if (!peer || typeof peer !== 'object' || Array.isArray(peer))
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  const peerRecord = /** @type {Record<string, unknown>} */ (peer);
  if (peerRecord.transport !== expected.transport || peerRecord.credential_verified !== true)
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  if (String(peerRecord.identity || '') !== wanted)
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_DENIED' };
  return { ok: true, peer: { transport: expected.transport, identity: wanted } };
}

/**
 * @param {unknown} value
 */
export function encodePrivilegedHelperFrame(value) {
  const body = Buffer.from(JSON.stringify(value) + '\n', 'utf8');
  if (body.length > PRIVILEGED_HELPER_MAX_FRAME_BYTES)
    throw new Error('PRIVILEGED_HELPER_FRAME_TOO_LARGE');
  return body;
}

/**
 * @param {unknown} value
 */
export function decodePrivilegedHelperFrame(value) {
  const body = Buffer.isBuffer(value) ? value : Buffer.from(/** @type {string} */ (value || ''));
  if (body.length === 0 || body.length > PRIVILEGED_HELPER_MAX_FRAME_BYTES)
    throw new Error('PRIVILEGED_HELPER_FRAME_INVALID');
  const text = body.toString('utf8');
  if (!text.endsWith('\n') || text.indexOf('\n') !== text.length - 1)
    throw new Error('PRIVILEGED_HELPER_FRAME_INVALID');
  let parsed;
  try {
    parsed = JSON.parse(text.slice(0, -1));
  } catch {
    throw new Error('PRIVILEGED_HELPER_FRAME_INVALID');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
    throw new Error('PRIVILEGED_HELPER_FRAME_INVALID');
  return parsed;
}

/**
 * @param {unknown} request
 * @param {object} [options]
 * @param {string} [options.platform]
 * @param {string} [options.endpoint]
 * @param {number} [options.timeoutMs]
 */
export function invokePrivilegedHelper(
  request,
  {
    platform = process.platform,
    endpoint = privilegedHelperEndpoint(platform),
    timeoutMs = 5000
  } = {}
) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(endpoint);
    let data = Buffer.alloc(0),
      settled = false;
    /**
     * @param {unknown} [error]
     * @param {unknown} [value]
     */
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      error ? reject(error) : resolve(value);
    };
    const timer = setTimeout(() => finish(new Error('PRIVILEGED_HELPER_TIMEOUT')), timeoutMs);
    socket.on('data', (chunk) => {
      data = Buffer.concat([data, Buffer.from(chunk)]);
      if (data.length > PRIVILEGED_HELPER_MAX_FRAME_BYTES)
        finish(new Error('PRIVILEGED_HELPER_FRAME_TOO_LARGE'));
    });
    socket.once('connect', () => {
      try {
        socket.write(encodePrivilegedHelperFrame(request));
      } catch (error) {
        finish(error);
      }
    });
    socket.once('end', () => {
      try {
        finish(null, decodePrivilegedHelperFrame(data));
      } catch (error) {
        finish(error);
      }
    });
    socket.once('error', () => finish(new Error('PRIVILEGED_HELPER_NOT_AVAILABLE')));
  });
}
