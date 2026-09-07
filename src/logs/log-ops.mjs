// Stateful log-follow handles for the HHC agent (MCP 5.2.0).
// The server issues opaque log_ handles; the agent tracks byte offsets
// per handle with TTL. Prefer over repeated log_read polling.
import fs from 'node:fs/promises';

/** @type {Map<string, {file: string, ttlMs: number, updatedMs: number}>} */
const follows = new Map();
const FOLLOW_TTL_MS = 30 * 60 * 1000;

/** @param {number} [nowMs] */
export function reapFollows(nowMs = Date.now()) {
  let reaped = 0;
  for (const [id, f] of follows) {
    if (nowMs - f.updatedMs > f.ttlMs) {
      follows.delete(id);
      reaped++;
    }
  }
  return reaped;
}

/** For tests. */
export function clearFollows() {
  follows.clear();
}

/**
 * @param {unknown} job
 */
function payloadOf(job) {
  const r = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  return /** @type {Record<string, unknown>} */ (r.request_payload || r.payload || {});
}

const ok = (/** @type {unknown} */ result_payload) => ({
  status: 'completed',
  exit_code: 0,
  stdout: '',
  stderr: '',
  error: null,
  duration_ms: 0,
  result_payload
});
const fail = (/** @type {unknown} */ error) => ({
  status: 'failed',
  exit_code: null,
  stdout: '',
  stderr: '',
  error: String(error),
  duration_ms: 0,
  result_payload: {}
});

/**
 * @param {object} [options]
 * @param {Record<string, string>} [options.logSources] name -> absolute file
 */
export function makeLogFollowHandlers({ logSources = {} } = {}) {
  /**
   * @param {string} source
   * @param {string} [explicitPath]
   */
  const resolveFile = (source, explicitPath) => {
    if (explicitPath && typeof explicitPath === 'string' && explicitPath.length <= 4096)
      return explicitPath;
    const file = logSources[source];
    if (!file) throw new Error('LOG_SOURCE_NOT_ALLOWED');
    return file;
  };
  /**
   * @param {string} file
   * @param {number} cursor
   * @param {number} maxBytes
   */
  const readFrom = async (file, cursor, maxBytes) => {
    const st = await fs.stat(file);
    let offset = Math.max(0, cursor);
    let truncatedReset = false;
    if (offset > st.size) {
      offset = 0;
      truncatedReset = true;
    }
    const len = Math.min(st.size - offset, maxBytes);
    if (len <= 0) return { content: '', cursor: st.size, eof: true, truncatedReset };
    const handle = await fs.open(file, 'r');
    try {
      const buffer = Buffer.alloc(len);
      const { bytesRead } = await handle.read(buffer, 0, len, offset);
      return {
        content: buffer.subarray(0, bytesRead).toString('utf8'),
        cursor: offset + bytesRead,
        eof: offset + bytesRead >= st.size,
        truncatedReset
      };
    } finally {
      await handle.close();
    }
  };
  return {
    log_follow_start: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        const handle = String(p.handle || '');
        if (!/^log_[0-9a-f]{32}$/.test(handle)) return fail('INVALID_HANDLE');
        const file = resolveFile(String(p.source || ''), /** @type {string|undefined} */ (p.path));
        const maxLines = Math.max(1, Math.min(1000, Number(p.max_lines ?? 200)));
        const st = await fs.stat(file);
        const tailBytes = Math.min(st.size, maxLines * 512);
        const start = await readFrom(file, Math.max(0, st.size - tailBytes), 65536);
        follows.set(handle, { file, ttlMs: FOLLOW_TTL_MS, updatedMs: Date.now() });
        return ok({ handle, content: start.content, cursor: start.cursor, eof: start.eof });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown, code?: unknown}} */ (e);
        return fail(errorRecord?.code === 'ENOENT' ? 'LOG_SOURCE_NOT_FOUND' : errorRecord?.message);
      }
    },
    log_follow_read: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        const handle = String(p.handle || '');
        const f = follows.get(handle);
        if (!f) return fail('UNKNOWN_HANDLE');
        f.updatedMs = Date.now();
        const maxBytes = Math.max(1, Math.min(262144, Number(p.max_bytes ?? 65536)));
        const r = await readFrom(f.file, Math.max(0, Number(p.cursor ?? 0)), maxBytes);
        return ok({ handle, ...r });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown, code?: unknown}} */ (e);
        return fail(errorRecord?.code === 'ENOENT' ? 'LOG_SOURCE_NOT_FOUND' : errorRecord?.message);
      }
    },
    log_follow_stop: async (/** @type {unknown} */ job) => {
      const p = payloadOf(job);
      follows.delete(String(p.handle || ''));
      return ok({ stopped: true });
    }
  };
}
