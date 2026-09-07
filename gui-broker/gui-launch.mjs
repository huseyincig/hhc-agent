import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { hhcLayout } from '../src/client/hhc-paths.mjs';

const APPS = new Set(['default_browser', 'edge', 'chrome', 'explorer', 'notepad']);
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
          return {
            ...ok({
              application: app,
              target,
              user: r.username,
              session_id: r.session_id,
              pid: r.pid ?? null
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
