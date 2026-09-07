import { spawn } from 'node:child_process';

const UINT_RE = /^[0-9]+$/;

/**
 * @param {NodeJS.ReadableStream} stream
 * @param {number} [max]
 */
function collectLimited(stream, max = 4096) {
  return new Promise((resolve) => {
    /** @type {Array<Buffer>} */
    const chunks = [];
    let size = 0;
    stream.on('data', (/** @type {Buffer} */ chunk) => {
      if (size >= max) return;
      const b = Buffer.from(chunk),
        take = b.subarray(0, max - size);
      chunks.push(take);
      size += take.length;
    });
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

/**
 * @param {unknown} socket
 * @param {object} [options]
 * @param {string} [options.binary]
 * @param {number} [options.timeoutMs]
 * @returns {Promise<{ok: false, error: string} | {ok: true, credentials: {pid: number, uid: number, gid: number}}>}
 */
export async function readLinuxPeerCredentials(socket, { binary, timeoutMs = 1000 } = {}) {
  if (process.platform !== 'linux')
    return { ok: false, error: 'PRIVILEGED_HELPER_PLATFORM_UNSUPPORTED' };
  const socketRecord = /** @type {Record<string, unknown>} */ (socket || {});
  if (
    !socket ||
    typeof socket !== 'object' ||
    typeof socketRecord.destroy !== 'function' ||
    !binary
  )
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  let child;
  try {
    child = spawn(/** @type {string} */ (binary), [], {
      stdio: ['ignore', 'pipe', 'pipe', /** @type {any} */ (socket)],
      env: { PATH: '/usr/bin:/bin' }
    });
  } catch {
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  }
  const stdoutP = collectLimited(/** @type {NodeJS.ReadableStream} */ (child.stdout)),
    stderrP = collectLimited(/** @type {NodeJS.ReadableStream} */ (child.stderr));
  const exitP = new Promise((resolve) => {
    child.once('error', () => resolve(null));
    child.once('exit', (code) => resolve(code));
  });
  const timer = setTimeout(
    () => {
      try {
        child.kill('SIGKILL');
      } catch {}
    },
    Math.max(50, Math.min(5000, Number(timeoutMs) || 1000))
  );
  const [code, stdout] = await Promise.all([exitP, stdoutP, stderrP]).then(([c, o]) => [c, o]);
  clearTimeout(timer);
  if (code !== 0) return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  let parsed;
  try {
    parsed = JSON.parse(stdout.trim());
  } catch {
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  }
  if (
    !parsed ||
    !UINT_RE.test(String(parsed.pid)) ||
    !UINT_RE.test(String(parsed.uid)) ||
    !UINT_RE.test(String(parsed.gid))
  )
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  const pid = Number(parsed.pid),
    uid = Number(parsed.uid),
    gid = Number(parsed.gid);
  if (
    !Number.isSafeInteger(pid) ||
    pid <= 0 ||
    !Number.isSafeInteger(uid) ||
    uid < 0 ||
    !Number.isSafeInteger(gid) ||
    gid < 0
  )
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  return { ok: true, credentials: { pid, uid, gid } };
}

/**
 * @param {unknown} socket
 * @param {object} [options]
 * @param {string} [options.binary]
 * @param {number} [options.expectedUid]
 * @param {number} [options.expectedGid]
 * @param {string} [options.identity]
 * @returns {Promise<{ok: false, error: string} | {ok: true, peer: {transport: string, identity: string, credential_verified: boolean, pid: number, uid: number, gid: number}}>}
 */
export async function verifyLinuxHelperPeer(
  socket,
  { binary, expectedUid, expectedGid, identity = '_hhc' } = {}
) {
  if (
    typeof expectedUid !== 'number' ||
    !Number.isSafeInteger(expectedUid) ||
    expectedUid < 0 ||
    typeof expectedGid !== 'number' ||
    !Number.isSafeInteger(expectedGid) ||
    expectedGid < 0
  )
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_UNVERIFIED' };
  const result = await readLinuxPeerCredentials(socket, { binary });
  if (!result.ok) return result;
  if (result.credentials.uid !== expectedUid || result.credentials.gid !== expectedGid)
    return { ok: false, error: 'PRIVILEGED_HELPER_PEER_DENIED' };
  return {
    ok: true,
    peer: {
      transport: 'unix_socket',
      identity,
      credential_verified: true,
      pid: result.credentials.pid,
      uid: result.credentials.uid,
      gid: result.credentials.gid
    }
  };
}
