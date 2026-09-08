// Durable process sessions for the HHC agent (MCP 5.2.0).
// A session outlives any single MCP connection: the server hands out an
// opaque process_id, the agent owns the OS process + buffers. Reaped by
// exit, explicit terminate, or idle TTL. No shell is ever involved here:
// argv is spawned directly (see process_start contract).
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

/** @type {Map<string, ProcessSession>} */
const sessions = new Map();

const DEFAULT_IDLE_TTL_MS = 10 * 60 * 1000;
const STREAM_CAP_BYTES = 4 * 1024 * 1024;
const SWEEP_KILL_GRACE_MS = 3000;
const SWEEP_VERIFY_TOLERANCE_MS = 120 * 1000;

/**
 * @typedef {object} ProcessSession
 * @property {import('node:child_process').ChildProcess} child
 * @property {number} pid
 * @property {string} started_at
 * @property {Array<Buffer>} stdoutChunks
 * @property {Array<Buffer>} stderrChunks
 * @property {number} stdoutBytes
 * @property {number} stderrBytes
 * @property {number} stdoutDroppedBytes bytes discarded past the stream cap
 * @property {number} stderrDroppedBytes bytes discarded past the stream cap
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
 * Process start-time check against a record (PID-reuse guard for the boot
 * sweep). Linux reads /proc directly; others parse `ps -o lstart` with a
 * tolerance window; unparseable → null (caller skips, never kills blind).
 * @param {number} pid
 * @param {string} startedAtIso
 * @param {{platform?: string, execFile?: any}} [options]
 */
export async function verifyProcessStartTime(
  pid,
  startedAtIso,
  { platform = process.platform, execFile = null } = {}
) {
  const expected = Date.parse(String(startedAtIso || ''));
  if (!Number.isFinite(expected)) return null;
  try {
    if (platform === 'linux') {
      const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
      const afterComm = stat
        .slice(stat.lastIndexOf(')') + 1)
        .trim()
        .split(/\s+/);
      // field 22 (1-based) after comm = starttime in clock ticks.
      const ticks = Number(afterComm[19]);
      if (!Number.isFinite(ticks)) return null;
      const btime = Number(
        fs
          .readFileSync('/proc/stat', 'utf8')
          .split('\n')
          .find((l) => l.startsWith('btime'))
          ?.split(/\s+/)[1]
      );
      const ticksPerSec = 100;
      if (!Number.isFinite(btime)) return null;
      const actualMs = (btime + ticks / ticksPerSec) * 1000;
      return Math.abs(actualMs - expected) <= SWEEP_VERIFY_TOLERANCE_MS;
    }
    const { execFile: ef } = execFile || (await import('node:child_process'));
    const { promisify } = await import('node:util');
    const run = promisify(ef);
    const { stdout } = await run(
      platform === 'win32' ? 'powershell' : 'ps',
      platform === 'win32'
        ? [
            '-NoProfile',
            '-Command',
            `(Get-Process -Id ${pid}).StartTime.ToUniversalTime().ToString('o')`
          ]
        : ['-o', 'lstart=', '-p', String(pid)],
      { timeout: 10000 }
    );
    const actualMs = Date.parse(String(stdout || '').trim());
    if (!Number.isFinite(actualMs)) return null;
    return Math.abs(actualMs - expected) <= SWEEP_VERIFY_TOLERANCE_MS;
  } catch {
    return null;
  }
}

/**
 * Boot sweep (SYN-PROC-004): adopt-or-kill processes recorded by a previous
 * agent incarnation. Only kills pids that are BOTH alive AND start-time
 * verified (PID-reuse guard); dead records are dropped; unverifiable records
 * are left for the next boot with action `skipped`.
 * @param {{stateDir?: string|null, platform?: string}} [options]
 */
export async function sweepOrphanedSessions({ stateDir = null, platform = process.platform } = {}) {
  /** @type {Array<{id: string, pid: number, action: string}>} */
  const out = [];
  if (!stateDir) return out;
  const file = path.join(stateDir, 'process-sessions.json');
  /** @type {Record<string, {pid?: unknown, started_at?: unknown}>} */
  let all = {};
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) all = parsed;
  } catch {
    return out;
  }
  const keep = /** @type {Record<string, {pid?: unknown, started_at?: unknown}>} */ ({});
  for (const [id, rec] of Object.entries(all)) {
    const pid = Math.floor(Number(rec?.pid));
    if (!Number.isInteger(pid) || pid < 2 || !isPidAlive(pid, platform)) continue;
    let verified = false;
    try {
      verified =
        (await verifyProcessStartTime(pid, String(rec?.started_at || ''), { platform })) === true;
    } catch {
      verified = false;
    }
    if (!verified) {
      keep[id] = rec;
      out.push({ id, pid, action: 'skipped-unverifiable' });
      continue;
    }
    await terminateSessionTreeAsync(
      { pid },
      { platform, force: false, graceMs: SWEEP_KILL_GRACE_MS }
    );
    if (isPidAlive(pid, platform))
      await terminateSessionTreeAsync({ pid }, { platform, force: true, graceMs: 0 });
    out.push({ id, pid, action: isPidAlive(pid, platform) ? 'kill-failed' : 'killed' });
    if (!isPidAlive(pid, platform)) continue;
    keep[id] = rec;
  }
  try {
    fs.writeFileSync(file, JSON.stringify(keep), { mode: 0o600 });
  } catch {}
  return out;
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
    stdoutDroppedBytes: 0,
    stderrDroppedBytes: 0,
    exited: false,
    exitCode: null,
    exitSignal: null,
    lastActivityMs: now,
    idleTtlMs
  };
  child.stdout?.on('data', (chunk) => {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (session.stdoutBytes < STREAM_CAP_BYTES) {
      const room = STREAM_CAP_BYTES - session.stdoutBytes;
      if (buf.length <= room) {
        session.stdoutChunks.push(buf);
        session.stdoutBytes += buf.length;
      } else {
        if (room > 0) {
          session.stdoutChunks.push(buf.subarray(0, room));
          session.stdoutBytes += room;
        }
        session.stdoutDroppedBytes += buf.length - room;
      }
    } else {
      session.stdoutDroppedBytes += buf.length;
    }
    session.lastActivityMs = Date.now();
  });
  child.stderr?.on('data', (chunk) => {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (session.stderrBytes < STREAM_CAP_BYTES) {
      const room = STREAM_CAP_BYTES - session.stderrBytes;
      if (buf.length <= room) {
        session.stderrChunks.push(buf);
        session.stderrBytes += buf.length;
      } else {
        if (room > 0) {
          session.stderrChunks.push(buf.subarray(0, room));
          session.stderrBytes += room;
        }
        session.stderrDroppedBytes += buf.length - room;
      }
    } else {
      session.stderrDroppedBytes += buf.length;
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
  const stdoutCut = Math.min(stdoutCursor, out.length) + maxBytes < out.length;
  const stderrCut = Math.min(stderrCursor, err.length) + maxBytes < err.length;
  return {
    stdout: stdout.toString('utf8'),
    stderr: stderr.toString('utf8'),
    stdout_cursor: out.length,
    stderr_cursor: err.length,
    stdout_truncated: session.stdoutDroppedBytes > 0 || stdoutCut,
    stdout_dropped_bytes: session.stdoutDroppedBytes,
    stderr_truncated: session.stderrDroppedBytes > 0 || stderrCut,
    stderr_dropped_bytes: session.stderrDroppedBytes,
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
    // argv-form taskkill (no cmd.exe string): tree kill, forced. Graceful
    // escalation lives in terminateSessionTreeAsync below.
    try {
      spawn('taskkill', ['/PID', String(Math.floor(Number(child.pid))), '/T', '/F'], {
        stdio: 'ignore',
        windowsHide: true
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
 * @param {number} pid
 * @param {string} [platform]
 */
function isPidAlive(pid, platform = process.platform) {
  if (!Number.isInteger(pid) || pid < 2) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** @param {number} ms */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Graceful termination with bounded escalation (SYN-PROC-002): signal gently,
 * wait up to graceMs polling liveness, then force. Never throws; reports how
 * the process actually died so callers (and models) can tell signaled apart
 * from killed.
 * @param {import('node:child_process').ChildProcess|{pid?: unknown, kill?: unknown}|undefined|null} child
 * @param {{platform?: string, force?: boolean, graceMs?: number}} [options]
 */
export async function terminateSessionTreeAsync(
  child,
  { platform = process.platform, force = false, graceMs = 5000 } = {}
) {
  const pid = Math.floor(Number(child?.pid));
  if (!Number.isInteger(pid) || pid < 2) return { signaled: false, signal: null, graceful: false };
  const grace = Math.max(0, Math.min(30000, Math.floor(Number(graceMs ?? 5000) || 0)));
  const gentle = force ? 'SIGKILL' : platform === 'win32' ? null : 'SIGTERM';
  if (platform === 'win32') {
    // Native taskkill via argv (no shell string): gentle pass without /F,
    // escalate with /F after the grace window unless force skips the wait.
    try {
      const args = force ? ['/PID', String(pid), '/T', '/F'] : ['/PID', String(pid), '/T'];
      spawn('taskkill', args, { stdio: 'ignore', windowsHide: true }).unref();
    } catch {}
    if (!force && grace > 0) {
      const deadline = Date.now() + grace;
      while (Date.now() < deadline) {
        if (!isPidAlive(pid, platform))
          return { signaled: true, signal: 'TASKKILL', graceful: true };
        await sleep(100);
      }
    }
    if (!force && isPidAlive(pid, platform)) {
      try {
        spawn('taskkill', ['/PID', String(pid), '/T', '/F'], {
          stdio: 'ignore',
          windowsHide: true
        }).unref();
      } catch {}
      return { signaled: true, signal: 'TASKKILL/F', graceful: false };
    }
    return { signaled: true, signal: force ? 'TASKKILL/F' : 'TASKKILL', graceful: !force };
  }
  try {
    process.kill(-pid, force ? 'SIGKILL' : 'SIGTERM');
  } catch {
    try {
      process.kill(pid, force ? 'SIGKILL' : 'SIGTERM');
    } catch {
      try {
        /** @type {{kill?: (signal?: string) => unknown}} */ (child)?.kill?.(
          force ? 'SIGKILL' : 'SIGTERM'
        );
      } catch {
        return { signaled: false, signal: null, graceful: false };
      }
    }
  }
  if (!force && grace > 0) {
    const deadline = Date.now() + grace;
    while (Date.now() < deadline) {
      if (!isPidAlive(pid, platform)) return { signaled: true, signal: gentle, graceful: true };
      await sleep(100);
    }
  }
  if (!force && isPidAlive(pid, platform)) {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      try {
        process.kill(pid, 'SIGKILL');
      } catch {
        try {
          /** @type {{kill?: (signal?: string) => unknown}} */ (child)?.kill?.('SIGKILL');
        } catch {}
      }
    }
    return { signaled: true, signal: 'SIGKILL', graceful: false };
  }
  return { signaled: true, signal: gentle, graceful: !force };
}

/**
 * Register a spawned session under an id (server-issued handle).
 * @param {string} id
 * @param {ProcessSession} session
 * @param {string|null} [stateDir] when given, persist {pid,started_at} for boot sweep
 */
export function trackSession(id, session, stateDir = null) {
  sessions.set(id, session);
  if (stateDir) {
    try {
      const file = path.join(stateDir, 'process-sessions.json');
      /** @type {Record<string, unknown>} */
      let all = {};
      try {
        all = JSON.parse(fs.readFileSync(file, 'utf8')) || {};
      } catch {}
      if (!all || typeof all !== 'object' || Array.isArray(all)) all = {};
      all[id] = { pid: session.pid, started_at: session.started_at };
      fs.mkdirSync(stateDir, { recursive: true });
      fs.writeFileSync(file, JSON.stringify(all), { mode: 0o600 });
    } catch {}
  }
  return session;
}

/**
 * @param {string} id
 * @param {string|null} [stateDir]
 */
export function dropSession(id, stateDir = null) {
  const gone = sessions.delete(id);
  if (stateDir) {
    try {
      const file = path.join(stateDir, 'process-sessions.json');
      const all = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (all && typeof all === 'object' && !Array.isArray(all) && all[id]) {
        delete all[id];
        fs.writeFileSync(file, JSON.stringify(all), { mode: 0o600 });
      }
    } catch {}
  }
  return gone;
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

export function makeProcessHandlers(
  /** @type {{stateDir?: string|null}} */ { stateDir = null } = {}
) {
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
        trackSession(processId, session, stateDir);
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
        // SYN-PROC-002: graceful by default (SIGTERM + bounded wait, then
        // SIGKILL); force skips the wait. Reports how it actually died.
        const rawGrace = p.grace_ms === undefined || p.grace_ms === null ? NaN : Number(p.grace_ms);
        const graceMs = Number.isFinite(rawGrace)
          ? Math.max(0, Math.min(30000, Math.floor(rawGrace)))
          : 5000;
        const outcome = await terminateSessionTreeAsync(session.child, {
          platform: process.platform,
          force: p.force === true,
          graceMs
        });
        session.exited = true;
        session.lastActivityMs = Date.now();
        dropSession(id, stateDir);
        return ok({
          terminated: true,
          forced: p.force === true,
          signal: outcome.signal,
          graceful: outcome.graceful
        });
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
