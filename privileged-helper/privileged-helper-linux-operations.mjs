import { spawn } from 'node:child_process';
import fs from 'node:fs';

const MAX_OUTPUT = 1024 * 1024;
const UNINSTALL_TIMEOUT_MS = 120000;
/**
 * @param {Array<Buffer>} chunks
 * @param {Buffer} chunk
 * @param {{bytes: number, truncated: boolean}} state
 */
function boundedPush(chunks, chunk, state) {
  const b = Buffer.from(chunk),
    remaining = Math.max(0, MAX_OUTPUT - state.bytes);
  if (remaining > 0) chunks.push(b.subarray(0, remaining));
  state.bytes += Math.min(remaining, b.length);
  if (b.length > remaining) state.truncated = true;
}
/**
 * @param {unknown} payload
 */
function validatePayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  const rec = /** @type {Record<string, unknown>} */ (payload);
  const allowed = ['command', 'cwd', 'timeout_seconds'];
  if (Object.keys(rec).some((k) => !allowed.includes(k)))
    throw new Error('PRIVILEGED_PAYLOAD_INVALID');
  if (typeof rec.command !== 'string' || !rec.command.trim() || rec.command.length > 65536)
    throw new Error('PRIVILEGED_COMMAND_INVALID');
  const cwd = rec.cwd ?? '/opt/hhc';
  if (typeof cwd !== 'string' || !cwd.startsWith('/') || cwd.length > 4096)
    throw new Error('PRIVILEGED_CWD_INVALID');
  const timeout = Number(rec.timeout_seconds ?? 30);
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 3600)
    throw new Error('PRIVILEGED_TIMEOUT_INVALID');
  return { command: rec.command, cwd, timeout };
}
/**
 * @param {unknown} payload
 */
export function executeLinuxPrivilegedShell(payload) {
  const { command, cwd, timeout } = validatePayload(payload),
    started = Date.now();
  return new Promise((resolve) => {
    let child,
      settled = false;
    /** @type {Array<Buffer>} */
    const out = [],
      /** @type {Array<Buffer>} */
      err = [],
      os = { bytes: 0, truncated: false },
      es = { bytes: 0, truncated: false },
      finish =
        /** @type {(status: string, code: number | null, error: unknown) => void} */
        (
          (status, code, error) => {
            if (settled) return;
            settled = true;
            resolve({
              status,
              exit_code: code ?? null,
              stdout: Buffer.concat(out).toString('utf8'),
              stderr: Buffer.concat(err).toString('utf8'),
              duration_ms: Date.now() - started,
              error: error ?? null,
              stdout_truncated: os.truncated,
              stderr_truncated: es.truncated
            });
          }
        );
    try {
      child = spawn('/bin/sh', ['-lc', command], {
        cwd,
        env: {
          PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
          LANG: 'C.UTF-8'
        },
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch {
      return finish('failed', null, 'PRIVILEGED_EXEC_SPAWN_FAILED');
    }
    child.stdout.on('data', (c) => boundedPush(out, c, os));
    child.stderr.on('data', (c) => boundedPush(err, c, es));
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeout * 1000);
    child.once('error', () => {
      clearTimeout(timer);
      finish('failed', null, 'PRIVILEGED_EXEC_SPAWN_FAILED');
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (timedOut) return finish('timeout', code, 'PRIVILEGED_EXEC_TIMEOUT');
      finish(
        code === 0 ? 'completed' : 'failed',
        code,
        code === 0 ? null : 'PRIVILEGED_EXEC_NONZERO'
      );
    });
  });
}
export function linuxPrivilegedHelperHandlers({ uninstallScript = '/opt/hhc/uninstall.sh' } = {}) {
  return Object.freeze({
    privileged_shell_exec: executeLinuxPrivilegedShell,
    client_uninstall: (/** @type {unknown} */ payload) =>
      executeLinuxPrivilegedUninstall(payload, { script: uninstallScript })
  });
}

/**
 * Execute the canonical platform uninstall script. The script path is fixed
 * by the daemon wiring (never taken from the request) so a signed envelope
 * cannot redirect privileged execution anywhere else. Note the script stops
 * the agent itself, so a successful run is observed centrally as the host
 * going dark rather than as a delivered job result.
 *
 * @param {unknown} _payload (ignored by design)
 * @param {object} [options]
 * @param {string} [options.script]
 */
export function executeLinuxPrivilegedUninstall(
  _payload,
  { script = '/opt/hhc/uninstall.sh' } = {}
) {
  const started = Date.now();
  if (!fs.existsSync(script)) {
    return Promise.resolve({
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      duration_ms: 0,
      error: 'PRIVILEGED_UNINSTALL_SCRIPT_MISSING',
      stdout_truncated: false,
      stderr_truncated: false
    });
  }
  return new Promise((resolve) => {
    let child,
      settled = false;
    /** @type {Array<Buffer>} */
    const out = [],
      /** @type {Array<Buffer>} */
      err = [],
      os = { bytes: 0, truncated: false },
      es = { bytes: 0, truncated: false },
      finish =
        /** @type {(status: string, code: number | null, error: unknown) => void} */
        (
          (status, code, error) => {
            if (settled) return;
            settled = true;
            resolve({
              status,
              exit_code: code ?? null,
              stdout: Buffer.concat(out).toString('utf8'),
              stderr: Buffer.concat(err).toString('utf8'),
              duration_ms: Date.now() - started,
              error: error ?? null,
              stdout_truncated: os.truncated,
              stderr_truncated: es.truncated
            });
          }
        );
    try {
      // Spawn the script directly so the kernel honors its shebang
      // (uninstall-linux.sh requires bash; forcing /bin/sh is undefined).
      child = spawn(script, [], {
        env: {
          PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
          LANG: 'C.UTF-8'
        },
        stdio: ['ignore', 'pipe', 'pipe']
      });
    } catch {
      return finish('failed', null, 'PRIVILEGED_EXEC_SPAWN_FAILED');
    }
    child.stdout.on('data', (c) => boundedPush(out, c, os));
    child.stderr.on('data', (c) => boundedPush(err, c, es));
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, UNINSTALL_TIMEOUT_MS);
    child.once('error', () => {
      clearTimeout(timer);
      finish('failed', null, 'PRIVILEGED_EXEC_SPAWN_FAILED');
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (timedOut) return finish('timeout', code, 'PRIVILEGED_EXEC_TIMEOUT');
      finish(
        code === 0 ? 'completed' : 'failed',
        code,
        code === 0 ? null : 'PRIVILEGED_UNINSTALL_NONZERO'
      );
    });
  });
}
