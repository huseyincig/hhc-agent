// Durable process sessions for the HHC agent (MCP 5.2.0).
// A session outlives any single MCP connection: the server hands out an
// opaque process_id, the agent owns the OS process + buffers. Reaped by
// exit, explicit terminate, or idle TTL. No shell is ever involved here:
// argv is spawned directly (see process_start contract).
import { spawn } from 'node:child_process';

/** @type {Map<string, ProcessSession>} */
const sessions = new Map();

const DEFAULT_IDLE_TTL_MS = 10 * 60 * 1000;

/**
 * @typedef {object} ProcessSession
 * @property {import('node:child_process').ChildProcess} child
 * @property {number} pid
 * @property {string} started_at
 * @property {Array<Buffer>} stdoutChunks
 * @property {Array<Buffer>} stderrChunks
 * @property {number} stdoutBytes
 * @property {number} stderrBytes
 * @property {boolean} exited
 * @property {number|null} exitCode
 * @property {unknown} exitSignal
 * @property {number} lastActivityMs
 * @property {number} idleTtlMs
 * @param {string} id
 */
export function getSession(id) {
  const s = sessions.get(id);
  if (!s) return null;
  if (Date.now() - s.lastActivityMs > s.idleTtlMs && s.exited) {
    sessions.delete(id);
    return null;
  }
  return s;
}

/** @param {number} [nowMs] */
export function reapSessions(nowMs = Date.now()) {
  let reaped = 0;
  for (const [id, s] of sessions) {
    if (s.exited && nowMs - s.lastActivityMs > s.idleTtlMs) {
      sessions.delete(id);
      reaped++;
    }
  }
  return reaped;
}

/** For tests: drop everything. */
export function clearSessions() {
  sessions.clear();
}

/**
 * @param {string} executable
 * @param {Array<string>} args
 * @param {{cwd?: string, env?: Record<string,string>, timeoutMs?: number, idleTtlMs?: number}} [options]
 */
export function startSession(
  executable,
  args,
  { cwd, env, timeoutMs = 300000, idleTtlMs = DEFAULT_IDLE_TTL_MS } = {}
) {
  const child = spawn(executable, args, {
    cwd,
    env: env ? { ...process.env, ...env } : process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
    windowsHide: true
  });
  const now = Date.now();
  /** @type {ProcessSession} */
  const session = {
    child,
    pid: child.pid || 0,
    started_at: new Date(now).toISOString(),
    stdoutChunks: [],
    stderrChunks: [],
    stdoutBytes: 0,
    stderrBytes: 0,
    exited: false,
    exitCode: null,
    exitSignal: null,
    lastActivityMs: now,
    idleTtlMs
  };
  child.stdout?.on('data', (chunk) => {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (session.stdoutBytes < 4 * 1024 * 1024) {
      session.stdoutChunks.push(buf);
      session.stdoutBytes += buf.length;
    }
    session.lastActivityMs = Date.now();
  });
  child.stderr?.on('data', (chunk) => {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (session.stderrBytes < 4 * 1024 * 1024) {
      session.stderrChunks.push(buf);
      session.stderrBytes += buf.length;
    }
    session.lastActivityMs = Date.now();
  });
  child.once('error', () => {
    session.exited = true;
    session.lastActivityMs = Date.now();
  });
  child.once('exit', (code, signal) => {
    session.exited = true;
    session.exitCode = code;
    session.exitSignal = signal;
    session.lastActivityMs = Date.now();
  });
  const timeout = setTimeout(() => {
    try {
      terminateSessionTree(child, process.platform, true);
    } catch {}
  }, timeoutMs);
  if (timeout.unref) timeout.unref();
  return session;
}

/**
 * @param {ProcessSession} session
 * @param {number} stdoutCursor
 * @param {number} stderrCursor
 * @param {number} maxBytes
 */
export function readSession(session, stdoutCursor, stderrCursor, maxBytes) {
  const out = Buffer.concat(session.stdoutChunks);
  const err = Buffer.concat(session.stderrChunks);
  const stdout = out.subarray(
    Math.min(stdoutCursor, out.length),
    Math.min(out.length, Math.min(stdoutCursor, out.length) + maxBytes)
  );
  const stderr = err.subarray(
    Math.min(stderrCursor, err.length),
    Math.min(err.length, Math.min(stderrCursor, err.length) + maxBytes)
  );
  session.lastActivityMs = Date.now();
  return {
    stdout: stdout.toString('utf8'),
    stderr: stderr.toString('utf8'),
    stdout_cursor: out.length,
    stderr_cursor: err.length,
    exited: session.exited,
    exit_code: session.exitCode
  };
}

/**
 * @param {ProcessSession} session
 * @param {string} data
 */
export function writeSession(session, data) {
  if (session.exited) return { ok: false, error: 'PROCESS_EXITED' };
  if (!session.child.stdin || session.child.stdin.destroyed)
    return { ok: false, error: 'PROCESS_STDIN_CLOSED' };
  session.child.stdin.write(data);
  session.lastActivityMs = Date.now();
  return { ok: true };
}

/**
 * @param {import('node:child_process').ChildProcess|undefined|null} child
 * @param {string} [platform]
 * @param {boolean} [force]
 */
export function terminateSessionTree(child, platform = process.platform, force = false) {
  if (!child?.pid) return;
  if (platform === 'win32') {
    const line = 'taskkill /PID ' + child.pid + ' /T /F >NUL 2>&1';
    try {
      spawn(process.env.ComSpec || process.env.COMSPEC || 'cmd.exe', ['/d', '/s', '/c', line], {
        stdio: 'ignore'
      }).unref();
    } catch {}
    return;
  }
  try {
    process.kill(-child.pid, force ? 'SIGKILL' : 'SIGTERM');
  } catch {
    try {
      child.kill(force ? 'SIGKILL' : 'SIGTERM');
    } catch {}
  }
}

/**
 * Register a spawned session under an id (server-issued handle).
 * @param {string} id
 * @param {ProcessSession} session
 */
export function trackSession(id, session) {
  sessions.set(id, session);
  return session;
}

/**
 * @param {string} id
 */
export function dropSession(id) {
  return sessions.delete(id);
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
 * OS-native process listing (system scope). Best-effort parsing, capped.
 * @param {string} [platform]
 */
export async function listSystemProcesses(platform = process.platform) {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const run = promisify(execFile);
  /**
   * @param {string} cmd
   * @param {Array<string>} args
   */
  const capture = async (cmd, args) => {
    const { stdout } = await run(cmd, args, {
      timeout: 15000,
      windowsHide: true,
      maxBuffer: 2 * 1024 * 1024
    });
    return stdout;
  };
  const out = [];
  if (platform === 'win32') {
    const stdout = await capture('tasklist', ['/FO', 'CSV', '/NH']);
    for (const line of stdout.split(/\r?\n/)) {
      const m = line.match(/^"([^"]+)",\s*"(\d+)"/);
      if (m) out.push({ pid: Number(m[2]), name: m[1] });
      if (out.length >= 500) break;
    }
    return out;
  }
  const stdout = await capture(
    'ps',
    platform === 'darwin'
      ? ['-ax', '-o', 'pid,ppid,comm,etime,pcpu,pmem']
      : ['-eo', 'pid,ppid,comm,etime,pcpu,pmem']
  );
  for (const line of stdout.split('\n').slice(1)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 6 || !/^\d+$/.test(parts[0] || '')) continue;
    out.push({
      pid: Number(parts[0]),
      ppid: Number(parts[1]),
      name: parts[2],
      elapsed: parts[3],
      cpu_percent: Number(parts[4]),
      mem_percent: Number(parts[5])
    });
    if (out.length >= 500) break;
  }
  return out;
}

export function makeProcessHandlers() {
  return {
    process_start: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        const executable = String(p.executable || '');
        if (!executable || executable.includes('\0') || executable.length > 1024)
          throw new Error('INVALID_EXECUTABLE');
        const rawArgs = p.args === undefined ? [] : p.args;
        if (!Array.isArray(rawArgs) || rawArgs.length > 64) throw new Error('INVALID_ARGS');
        const args = rawArgs.map(String);
        const processId = String(p.process_id || '');
        if (!/^prc_[0-9a-f]{32}$/.test(processId)) throw new Error('INVALID_PROCESS_ID');
        const session = startSession(executable, args, {
          cwd: typeof p.cwd === 'string' ? p.cwd : undefined,
          env:
            p.env && typeof p.env === 'object'
              ? /** @type {Record<string, string>} */ (p.env)
              : undefined,
          timeoutMs: Math.max(1000, Math.min(3600000, Number(p.timeout_seconds ?? 300) * 1000)),
          idleTtlMs: Math.max(
            30000,
            Math.min(3600000, Number(p.idle_timeout_seconds ?? 600) * 1000)
          )
        });
        trackSession(processId, session);
        reapSessions();
        return ok({
          process_id: processId,
          status: session.exited ? 'failed' : 'running',
          pid: session.pid,
          started_at: session.started_at,
          stdout_cursor: 0,
          stderr_cursor: 0
        });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    process_output: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        const session = getSession(String(p.process_id || ''));
        if (!session) return fail('UNKNOWN_HANDLE');
        const r = readSession(
          session,
          Math.max(0, Number(p.stdout_cursor ?? 0)),
          Math.max(0, Number(p.stderr_cursor ?? 0)),
          Math.max(1, Math.min(262144, Number(p.max_bytes ?? 65536)))
        );
        return ok({
          status: session.exited ? (session.exitCode === 0 ? 'completed' : 'failed') : 'running',
          ...r,
          exit_code: session.exitCode
        });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    process_input: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        const session = getSession(String(p.process_id || ''));
        if (!session) return fail('UNKNOWN_HANDLE');
        const w = writeSession(session, String(p.data || ''));
        if (!w.ok) return fail(w.error);
        return ok({ written: true });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    process_terminate: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        const id = String(p.process_id || '');
        const session = getSession(id);
        if (!session) return fail('UNKNOWN_HANDLE');
        terminateSessionTree(session.child, process.platform, p.force === true);
        session.exited = true;
        session.lastActivityMs = Date.now();
        dropSession(id);
        return ok({ terminated: true, forced: p.force === true });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    process_list: async (/** @type {unknown} */ job) => {
      try {
        const p = payloadOf(job);
        if (p.scope === 'system') {
          const all = await listSystemProcesses();
          const rawLimit = p.limit === undefined || p.limit === null ? NaN : Number(p.limit);
          const limit = Number.isFinite(rawLimit)
            ? Math.max(1, Math.min(5000, Math.floor(rawLimit)))
            : NaN;
          const processes = Number.isFinite(limit) ? all.slice(0, limit) : all;
          return ok({
            scope: 'system',
            processes,
            total_count: all.length,
            truncated: processes.length < all.length
          });
        }
        return fail('SCOPE_INVALID');
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    }
  };
}
