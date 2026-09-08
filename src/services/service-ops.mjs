// Platform service abstraction (MCP 5.2.0): systemd / SCM / launchd
// differences stay here so models only see service_list/start/stop.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isServiceStatusAllowed } from '../structured-ops/structured-ops.mjs';

const run = promisify(execFile);
const SERVICE_RE = /^[\w@.\-:]{1,128}$/;

/**
 * @param {string} service
 */
function checkName(service) {
  if (typeof service !== 'string' || !SERVICE_RE.test(service)) throw new Error('INVALID_SERVICE');
}

/**
 * @param {string} platform
 */
async function listServices(platform) {
  if (platform === 'win32') {
    const { stdout } = await run('sc', ['query', 'type=', 'service', 'state=', 'all'], {
      timeout: 20000,
      windowsHide: true
    });
    const services = [];
    for (const m of stdout.matchAll(/SERVICE_NAME:\s*(\S+)/g))
      services.push({ name: m[1], state: 'unknown' });
    return services.slice(0, 200);
  }
  if (platform === 'darwin') {
    const { stdout } = await run('launchctl', ['list'], { timeout: 20000 });
    return stdout
      .split('\n')
      .slice(1)
      .map((l) => l.trim().split(/\s+/).pop())
      .filter(Boolean)
      .slice(0, 200)
      .map((name) => ({ name, state: 'unknown' }));
  }
  const { stdout } = await run(
    'systemctl',
    ['list-units', '--type=service', '--all', '--no-legend', '--no-pager'],
    { timeout: 20000 }
  );
  return stdout
    .split('\n')
    .map((l) => l.trim().split(/\s+/)[0])
    .filter((n) => n && n.endsWith('.service'))
    .slice(0, 200)
    .map((name) => ({ name, state: 'unknown' }));
}

/**
 * @param {string} platform
 * @param {'start'|'stop'|'restart'} op
 * @param {string} service
 */
async function controlService(platform, op, service) {
  checkName(service);
  const runOne = async (/** @type {string} */ action) => {
    if (platform === 'win32') {
      const verb = action === 'start' ? 'start' : 'stop';
      await run('sc', [verb, service], { timeout: 30000, windowsHide: true });
      return;
    }
    if (platform === 'darwin') {
      if (action === 'start') await run('launchctl', ['start', service], { timeout: 30000 });
      else await run('launchctl', ['stop', service], { timeout: 30000 });
      return;
    }
    await run('systemctl', [action, service], { timeout: 30000 });
  };
  if (op === 'restart') {
    await runOne('stop').catch(() => {});
    await runOne('start');
    return { restarted: true };
  }
  await runOne(op);
  return { [op === 'start' ? 'started' : 'stopped']: true };
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
 * @param {string} [platform]
 * @param {object} [options]
 * @param {Array<string>} [options.serviceUnits]
 */
export function makeServiceHandlers(platform = process.platform, { serviceUnits = [] } = {}) {
  return {
    service_list: async () => {
      try {
        const services = await listServices(platform);
        return ok({
          services: services.map((s) => ({
            ...s,
            queryable: isServiceStatusAllowed(s?.name, serviceUnits)
          }))
        });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    service_start: async (/** @type {unknown} */ job) => {
      try {
        const service = String(payloadOf(job).service || '');
        const detail = await controlService(platform, 'start', service);
        return ok({ service, ...detail });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    service_stop: async (/** @type {unknown} */ job) => {
      try {
        const service = String(payloadOf(job).service || '');
        const detail = await controlService(platform, 'stop', service);
        return ok({ service, ...detail });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    service_restart: async (/** @type {unknown} */ job) => {
      try {
        const service = String(payloadOf(job).service || '');
        const detail = await controlService(platform, 'restart', service);
        return ok({ service, ...detail });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    }
  };
}
