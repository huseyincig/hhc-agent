import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { hhcLayout } from '../src/client/hhc-paths.mjs';

const APPS = new Set([
  'default_browser',
  'edge',
  'chrome',
  'explorer',
  'notepad',
  'code',
  'cursor',
  'terminal'
]);
/**
 * Broker-reported executable stems for PID re-correlation (win32 only).
 * default_browser launches an unknown browser; terminal may be wt.exe or a
 * fallback powershell shared with unrelated processes — both are skipped to
 * avoid attributing a foreign PID.
 */
const GUI_EXE_BY_APP = Object.freeze({
  edge: ['msedge'],
  chrome: ['chrome'],
  explorer: ['explorer'],
  notepad: ['notepad'],
  code: ['Code'],
  cursor: ['Cursor']
});
/**
 * Re-correlate a broker-reported GUI PID (win32 only). Single-instance and
 * Store-packaged apps (Win11 Notepad, browsers) often exit the spawned
 * launcher and activate another process, leaving a stale PID behind. When
 * the reported PID is dead, fall back to the newest same-name process;
 * otherwise (or off Windows) the broker value is returned untouched.
 * @param {string} app
 * @param {unknown} pid
 * @param {string} [platform]
 */
export async function resolveGuiPid(app, pid, platform = process.platform) {
  const id = Number(pid);
  if (platform !== 'win32') return Number.isInteger(id) && id > 0 ? id : null;
  const names = /** @type {Record<string, Array<string>>} */ (GUI_EXE_BY_APP)[app];
  try {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const run = promisify(execFile);
    const ps = async (/** @type {string} */ script) => {
      const { stdout } = await run(
        'powershell.exe',
        ['-NoProfile', '-NonInteractive', '-Command', script],
        { timeout: 15000, windowsHide: true }
      );
      return String(stdout || '').trim();
    };
    if (Number.isInteger(id) && id > 0) {
      const probe = await ps(
        `$p = Get-Process -Id ${id} -ErrorAction SilentlyContinue; if ($p) { 'ALIVE' } else { 'DEAD' }`
      );
      if (probe.includes('ALIVE')) return id;
    }
    if (!names) return Number.isInteger(id) && id > 0 ? id : null;
    const found = await ps(
      `$c = Get-Process -Name ${names.join(',')} -ErrorAction SilentlyContinue | Sort-Object StartTime -Descending | Select-Object -First 1; if ($c) { $c.Id } else { '' }`
    );
    const remapped = Number(found);
    if (Number.isInteger(remapped) && remapped > 0) return remapped;
  } catch {}
  return Number.isInteger(id) && id > 0 ? id : null;
}
/**
 * @param {unknown} result_payload
 */
const ok = (result_payload) => ({
  status: 'completed',
  exit_code: 0,
  stdout: '',
  stderr: '',
  error: null,
  duration_ms: 0,
  result_payload
});
/**
 * @param {unknown} error
 */
const fail = (error) => ({
  status: 'failed',
  exit_code: null,
  stdout: '',
  stderr: '',
  error: String(error),
  duration_ms: 0,
  result_payload: {}
});
/**
 * @param {number} ms
 */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/**
 * @param {unknown} text
 */
const parseJsonText = (text) => JSON.parse(String(text).replace(/^\uFEFF/, ''));

/**
 * PIDs this agent incarnation launched via gui_launch (pid -> unix ms).
 * gui_close only accepts these: closing foreign PIDs would exceed the
 * granted privilege (launch allowlisted apps, not manage the session).
 */
const launchedGuiPids = /** @type {Map<number, number>} */ (new Map());
const LAUNCHED_PID_TTL_MS = 24 * 60 * 60 * 1000;
const LAUNCHED_PID_MAX = 1000;
/** @param {unknown} pid */
function trackLaunchedGuiPid(pid) {
  const id = Number(pid);
  if (!Number.isInteger(id) || id <= 0) return;
  launchedGuiPids.set(id, Date.now());
  if (launchedGuiPids.size > LAUNCHED_PID_MAX) {
    const oldest = [...launchedGuiPids.entries()].sort(
      (/** @type {[number, number]} */ a, /** @type {[number, number]} */ b) => a[1] - b[1]
    )[0];
    if (oldest) launchedGuiPids.delete(oldest[0]);
  }
}
/** @param {unknown} pid */
function untrackLaunchedGuiPid(pid) {
  launchedGuiPids.delete(Number(pid));
}
/** @param {unknown} pid */
function isLaunchedGuiPid(pid) {
  const id = Number(pid);
  if (!Number.isInteger(id) || id <= 0) return false;
  const at = launchedGuiPids.get(id);
  if (at === undefined) return false;
  if (Date.now() - at > LAUNCHED_PID_TTL_MS) {
    launchedGuiPids.delete(id);
    return false;
  }
  return true;
}
/**
 * @param {string} app
 * @param {unknown} target
 */
function cleanTarget(app, target) {
  const value = String(target || '').trim();
  if (['default_browser', 'edge', 'chrome'].includes(app)) {
    if (!value) throw new Error('GUI_URL_REQUIRED');
    const u = new URL(value);
    if (!['http:', 'https:'].includes(u.protocol)) throw new Error('GUI_URL_SCHEME_NOT_ALLOWED');
    return u.toString();
  }
  if (app === 'explorer' && value.length > 4096) throw new Error('GUI_TARGET_TOO_LONG');
  return value;
}

/**
 * @param {ReturnType<typeof import('../src/client/hhc-paths.mjs').hhcLayout>} layout
 * @param {string} username
 */
async function liveBrokers(layout, username) {
  const dir = path.join(layout.data, 'gui-brokers');
  let rows = [];
  try {
    rows = await fs.readdir(dir);
  } catch {
    return [];
  }
  const now = Date.now(),
    out = [];
  for (const name of rows.filter((x) => x.endsWith('.json'))) {
    try {
      const b = parseJsonText(await fs.readFile(path.join(dir, name), 'utf8'));
      const ts = Date.parse(b.last_seen || '');
      if (!Number.isFinite(ts) || now - ts > 10000) continue;
      if (username && String(b.username || '').toLowerCase() !== username.toLowerCase()) continue;
      out.push(b);
    } catch {}
  }
  return out.sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen));
}

/**
 * @param {object} [options]
 * @param {ReturnType<typeof import('../src/client/hhc-paths.mjs').hhcLayout>} [options.layout]
 * @param {string} [options.platform]
 */
export function makeGuiLaunchHandler({ layout = hhcLayout(), platform = process.platform } = {}) {
  return async (/** @type {unknown} */ job) => {
    const started = Date.now();
    try {
      if (platform !== 'win32') throw new Error('GUI_LAUNCH_WINDOWS_ONLY');
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
          jobRecord.request_payload || jobRecord.payload || {}
        ),
        app = String(p.application || '');
      if (!APPS.has(app)) throw new Error('GUI_APPLICATION_NOT_ALLOWED');
      const target = cleanTarget(app, p.target),
        username = p.username ? String(p.username) : '';
      const brokers = await liveBrokers(layout, username);
      if (!brokers.length) throw new Error('GUI_BROKER_NOT_AVAILABLE');
      const broker = brokers[0],
        id = crypto.randomUUID(),
        queue = path.join(layout.data, 'gui-queue', String(broker.session_id)),
        results = path.join(layout.data, 'gui-results');
      await fs.mkdir(queue, { recursive: true });
      await fs.mkdir(results, { recursive: true });
      const req = { id, application: app, target, created_at: new Date().toISOString() };
      const tmp = path.join(queue, `.${id}.tmp`),
        file = path.join(queue, `${id}.json`);
      await fs.writeFile(tmp, JSON.stringify(req) + '\n', { mode: 0o640 });
      await fs.rename(tmp, file);
      const resultFile = path.join(results, `${id}.json`),
        deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        try {
          const r = parseJsonText(await fs.readFile(resultFile, 'utf8'));
          await fs.rm(resultFile, { force: true });
          if (!r.ok) throw new Error(r.error || 'GUI_LAUNCH_FAILED');
          const finalPid = await resolveGuiPid(app, r.pid, platform);
          trackLaunchedGuiPid(finalPid);
          return {
            ...ok({
              application: app,
              target,
              user: r.username,
              session_id: r.session_id,
              pid: finalPid
            }),
            duration_ms: Date.now() - started
          };
        } catch (e) {
          const errorCode = e && typeof e === 'object' && 'code' in e ? e.code : undefined;
          if (errorCode !== 'ENOENT') throw e;
        }
        await sleep(150);
      }
      throw new Error('GUI_BROKER_TIMEOUT');
    } catch (e) {
      const errorRecord = /** @type {{message?: unknown}} */ (e);
      return { ...fail(errorRecord?.message), duration_ms: Date.now() - started };
    }
  };
}

/**
 * Close a GUI application previously launched via gui_launch (win32 only —
 * the broker lives in the interactive user session). Only PIDs recorded by
 * trackLaunchedGuiPid are accepted; anything else fails closed with
 * GUI_PID_NOT_MANAGED instead of touching foreign processes.
 * @param {object} [options]
 * @param {ReturnType<typeof import('../src/client/hhc-paths.mjs').hhcLayout>} [options.layout]
 * @param {string} [options.platform]
 */
export function makeGuiCloseHandler({ layout = hhcLayout(), platform = process.platform } = {}) {
  return async (/** @type {unknown} */ job) => {
    const started = Date.now();
    try {
      if (platform !== 'win32') throw new Error('GUI_CLOSE_WINDOWS_ONLY');
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      const pid = Number(p.pid);
      if (!Number.isInteger(pid) || pid <= 0) throw new Error('GUI_PID_REQUIRED');
      if (!isLaunchedGuiPid(pid)) throw new Error('GUI_PID_NOT_MANAGED');
      const brokers = await liveBrokers(layout, '');
      if (!brokers.length) throw new Error('GUI_BROKER_NOT_AVAILABLE');
      const broker = brokers[0],
        id = crypto.randomUUID(),
        queue = path.join(layout.data, 'gui-queue', String(broker.session_id)),
        results = path.join(layout.data, 'gui-results');
      await fs.mkdir(queue, { recursive: true });
      await fs.mkdir(results, { recursive: true });
      const req = { id, action: 'close', pid, created_at: new Date().toISOString() };
      const tmp = path.join(queue, `.${id}.tmp`),
        file = path.join(queue, `${id}.json`);
      await fs.writeFile(tmp, JSON.stringify(req) + '\n', { mode: 0o640 });
      await fs.rename(tmp, file);
      const resultFile = path.join(results, `${id}.json`),
        deadline = Date.now() + 15000;
      while (Date.now() < deadline) {
        try {
          const r = parseJsonText(await fs.readFile(resultFile, 'utf8'));
          await fs.rm(resultFile, { force: true });
          if (!r.ok) throw new Error(r.error || 'GUI_CLOSE_FAILED');
          untrackLaunchedGuiPid(pid);
          return {
            ...ok({ pid, closed: r.closed === true }),
            duration_ms: Date.now() - started
          };
        } catch (e) {
          const errorCode = e && typeof e === 'object' && 'code' in e ? e.code : undefined;
          if (errorCode !== 'ENOENT') throw e;
        }
        await sleep(150);
      }
      throw new Error('GUI_BROKER_TIMEOUT');
    } catch (e) {
      const errorRecord = /** @type {{message?: unknown}} */ (e);
      return { ...fail(errorRecord?.message), duration_ms: Date.now() - started };
    }
  };
}
