import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { spawn } from 'node:child_process';
import { hhcLayout } from '../client/hhc-paths.mjs';
import { resolveBrowserRuntime, stageBrowserInstall } from '../browser/browser-runtime.mjs';

export const REQUIRED_UPDATE_FILES = [
  'launcher.mjs',
  'singleton.mjs',
  'gui-launch.mjs',
  'browser-adapter.mjs',
  'browser-manager.mjs',
  'browser-jobs.mjs',
  'browser-runtime.mjs',
  'egress-policy.mjs',
  'client.mjs',
  'ws-client.mjs',
  'structured-ops.mjs',
  'mutation-ops.mjs',
  'process-sessions.mjs',
  'service-ops.mjs',
  'log-ops.mjs',
  'host-policy.mjs',
  'device-proof.mjs',
  'lifecycle.mjs',
  'updater.mjs',
  'hhc-paths.mjs',
  'privileged-helper-contract.mjs',
  'privileged-helper-core.mjs',
  'privileged-helper-ipc.mjs',
  'linux-peer-credentials.mjs',
  'privileged-helper-linux-daemon.mjs',
  'privileged-helper-linux-operations.mjs',
  'privileged-helper-bootstrap.mjs',
  'privileged-helper-client.mjs',
  'privileged-helper-linux-readiness.mjs',
  'package.json'
];
const REQUIRED = REQUIRED_UPDATE_FILES;
/**
 * @param {unknown} v
 */
const validVersion = (v) => /^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(String(v || ''));

/**
 * @param {string} a
 * @param {string} b
 * @returns {number} negative when a < b, zero when equal, positive when a > b
 */
export function compareAgentVersions(a, b) {
  const core = (/** @type {string} */ v) => String(v).split(/[+-]/, 1)[0].split('.').map(Number);
  const [a1 = 0, a2 = 0, a3 = 0] = core(a);
  const [b1 = 0, b2 = 0, b3 = 0] = core(b);
  if (a1 !== b1) return a1 - b1;
  if (a2 !== b2) return a2 - b2;
  if (a3 !== b3) return a3 - b3;
  const pre = (/** @type {string} */ v) => (String(v).includes('-') ? 0 : 1);
  return pre(a) - pre(b);
}
/**
 * @param {string | Buffer} b
 */
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
/**
 * @param {string} p
 */
const exists = async (p) => {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
};
/**
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {string} cwd
 */
const run = (cmd, args, cwd) =>
  new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '',
      err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.once('error', reject);
    p.once('close', (code) =>
      code === 0
        ? resolve({ out, err })
        : reject(new Error(`${cmd} exited ${code}: ${err.slice(0, 500)}`))
    );
  });
/**
 * @param {unknown} error
 */
const fail = (error) => ({
  status: 'failed',
  exit_code: null,
  stdout: '',
  stderr: '',
  error,
  duration_ms: 0,
  result_payload: {}
});
/**
 * @param {Buffer} buf
 * @param {number} start
 * @param {number} length
 */
function tarString(buf, start, length) {
  return buf
    .subarray(start, start + length)
    .toString('utf8')
    .replace(/\0.*$/s, '')
    .trim();
}
/**
 * @param {Buffer} buf
 * @param {number} start
 * @param {number} length
 */
function tarOctal(buf, start, length) {
  const v = tarString(buf, start, length).replace(/\s/g, '');
  return v ? parseInt(v, 8) : 0;
}
/**
 * @param {Buffer} gzipBytes
 * @param {string} destination
 */
export async function extractReleaseArchive(gzipBytes, destination) {
  const tar = zlib.gunzipSync(gzipBytes, { maxOutputLength: 64 * 1024 * 1024 });
  let offset = 0,
    entries = 0;
  await fs.mkdir(destination, { recursive: true });
  while (offset + 512 <= tar.length) {
    const h = tar.subarray(offset, offset + 512);
    if (h.every((x) => x === 0)) break;
    const name = tarString(h, 0, 100),
      prefix = tarString(h, 345, 155),
      type = String.fromCharCode(h[156] || 48),
      size = tarOctal(h, 124, 12);
    const rel = (prefix ? prefix + '/' : '') + name;
    if (!rel) throw new Error('UPDATE_TAR_EMPTY_PATH');
    const normalized = path.posix.normalize(rel.replace(/\\/g, '/'));
    if (
      normalized.startsWith('/') ||
      normalized === '..' ||
      normalized.startsWith('../') ||
      normalized.includes('/../')
    )
      throw new Error('UPDATE_TAR_PATH_ESCAPE');
    if (!['0', '\0', '5'].includes(type)) throw new Error('UPDATE_TAR_UNSAFE_TYPE:' + type);
    const target = path.join(destination, ...normalized.split('/'));
    const destRoot = path.resolve(destination) + path.sep;
    if (!(path.resolve(target) + (type === '5' ? path.sep : '')).startsWith(destRoot))
      throw new Error('UPDATE_TAR_PATH_ESCAPE');
    offset += 512;
    if (size < 0 || offset + size > tar.length) throw new Error('UPDATE_TAR_TRUNCATED');
    if (type === '5') await fs.mkdir(target, { recursive: true });
    else {
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, tar.subarray(offset, offset + size), { mode: 0o640 });
    }
    entries++;
    if (entries > 1000) throw new Error('UPDATE_TAR_TOO_MANY_ENTRIES');
    offset += Math.ceil(size / 512) * 512;
  }
  return entries;
}

/**
 * @param {object} options
 * @param {string} options.serverUrl
 * @param {(method: string, url: string, options: Record<string, unknown>) => Promise<Record<string, string>>} options.authHeaders
 * @param {string} [options.clientId]
 * @param {string} [options.currentVersion]
 * @param {ReturnType<typeof import('../client/hhc-paths.mjs').hhcLayout>} [options.layout]
 */
export function makeUpdateHandler(options) {
  const { serverUrl, authHeaders, currentVersion } = options,
    layout = options.layout || hhcLayout();
  /**
   * @param {unknown} job
   */
  const handler = async (job) => {
    const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
    const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      ),
      version = String(p.version || ''),
      expected = String(p.sha256 || '').toLowerCase(),
      packageUrl = String(p.package_url || '');
    if (!validVersion(version)) return fail('INVALID_UPDATE_VERSION');
    if (
      currentVersion &&
      validVersion(currentVersion) &&
      compareAgentVersions(version, String(currentVersion)) <= 0
    )
      return fail('UPDATE_VERSION_NOT_NEWER');
    if (!/^[a-f0-9]{64}$/.test(expected)) return fail('INVALID_UPDATE_SHA256');
    if (!packageUrl.startsWith('/')) return fail('INVALID_UPDATE_URL');
    const dir = path.join(layout.clientReleases, version),
      archive = path.join(dir, 'client.tar.gz'),
      stage = path.join(dir, 'stage');
    try {
      await fs.rm(dir, { recursive: true, force: true });
      await fs.mkdir(stage, { recursive: true });
      if (typeof authHeaders !== 'function') throw new Error('DEVICE_AUTH_REQUIRED');
      const requestUrl = serverUrl + packageUrl,
        headers = await authHeaders('GET', requestUrl, { json: false });
      const r = await fetch(requestUrl, { headers, signal: AbortSignal.timeout(30000) });
      if (!r.ok) throw new Error(`UPDATE_DOWNLOAD_HTTP_${r.status}`);
      const body = Buffer.from(await r.arrayBuffer());
      if (sha256(body) !== expected) throw new Error('UPDATE_SHA256_MISMATCH');
      await fs.writeFile(archive, body, { mode: 0o640 });
      await extractReleaseArchive(body, stage);
      for (const name of REQUIRED)
        if (!(await exists(path.join(stage, name)))) throw new Error(`UPDATE_FILE_MISSING:${name}`);
      const pkg = JSON.parse(await fs.readFile(path.join(stage, 'package.json'), 'utf8'));
      if (pkg.version !== version) throw new Error('UPDATE_VERSION_MISMATCH');
      for (const name of REQUIRED.filter((x) => x.endsWith('.mjs')))
        await run(process.execPath, ['--check', name], stage);
      // Bundled browser runtime (when the release carries one) must agree
      // with the staged code pin; a mismatched bundle fails the update
      // instead of stranding the host with a dead engine. Absent bundle is
      // legal (air-gapped rebuilds fall back to the standalone OTA path).
      if (await exists(path.join(stage, 'browser-runtime', 'playwright-core', 'package.json'))) {
        const bundledPkg = JSON.parse(
          await fs.readFile(path.join(stage, 'browser-runtime', 'playwright-core', 'package.json'), 'utf8')
        );
        const stagedPin = await fs.readFile(path.join(stage, 'browser-runtime.mjs'), 'utf8');
        const pinVersion = stagedPin.match(/playwright:\s*'([^']+)'/)?.[1];
        if (!pinVersion || String(bundledPkg.version || '') !== pinVersion)
          throw new Error('UPDATE_BROWSER_RUNTIME_MISMATCH');
      }
      // Browser runtime stages alongside the core update (never blocks it):
      // boot promotion converges both atomically across the restart.
      /** @type {{staged: boolean, error?: string, current?: boolean, playwright?: string, browsers?: string|null}} */
      let browserRuntime = { staged: false };
      if (p.browser_runtime && typeof p.browser_runtime === 'object') {
        try {
          browserRuntime = await stageBrowserRuntimeUpdate({
            serverUrl,
            authHeaders,
            layout,
            spec: p.browser_runtime
          });
        } catch (error) {
          const message =
            error && typeof error === 'object' && 'message' in error && error.message
              ? String(error.message)
              : String(error);
          browserRuntime = { staged: false, error: message };
        }
      }
      return {
        status: 'completed',
        exit_code: 0,
        stdout: '',
        stderr: '',
        error: null,
        duration_ms: 0,
        result_payload: {
          version,
          sha256: expected,
          stage_dir: stage,
          activation_pending: true,
          browser_runtime_staged: browserRuntime
        }
      };
    } catch (error) {
      const message =
        error && typeof error === 'object' && 'message' in error && error.message
          ? String(error.message)
          : String(error);
      return fail(message);
    }
  };
  return handler;
}
/**
 * @param {string} source
 * @param {string} destination
 */
async function moveDirContents(source, destination) {
  await fs.mkdir(source, { recursive: true });
  await fs.mkdir(destination, { recursive: true });
  for (const name of await fs.readdir(source))
    await fs.rename(path.join(source, name), path.join(destination, name));
}

/**
 * @param {string} stage
 * @param {object} [options]
 * @param {ReturnType<typeof import('../client/hhc-paths.mjs').hhcLayout>} [options.layout]
 * @param {string} [options.previous]
 */
export async function swapAppContents(stage, { layout = hhcLayout(), previous } = {}) {
  if (!previous) throw new Error('UPDATE_BACKUP_PATH_REQUIRED');
  await fs.mkdir(layout.app, { recursive: true });
  await fs.mkdir(previous, { recursive: true });
  await moveDirContents(layout.app, previous);
  try {
    await moveDirContents(stage, layout.app);
  } catch (error) {
    try {
      await moveDirContents(layout.app, stage);
    } catch {}
    await moveDirContents(previous, layout.app);
    throw error;
  }
}

/**
 * Stages a browser-runtime OTA payload next to (never inside) the live
 * runtime. The staged payload activates at boot only when its Playwright
 * version equals the running code pin, so a core update and its runtime
 * converge atomically across the restart. Staging failure never blocks the
 * core update: the new code boots with the previous runtime and the health
 * gate hides browser tools with a clear mismatch error instead.
 * @param {object} options
 * @param {string} options.serverUrl
 * @param {unknown} options.authHeaders
 * @param {ReturnType<typeof import('../client/hhc-paths.mjs').hhcLayout>} options.layout
 * @param {unknown} options.spec
 */
export async function stageBrowserRuntimeUpdate({ serverUrl, authHeaders, layout, spec }) {
  const rec = /** @type {Record<string, unknown>} */ (spec && typeof spec === 'object' ? spec : {});
  const playwright = String(rec.playwright || '');
  const expected = String(rec.sha256 || '').toLowerCase();
  const packageUrl = String(rec.package_url || '');
  if (!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(playwright))
    return { staged: false, error: 'INVALID_BROWSER_RUNTIME_VERSION' };
  if (!/^[a-f0-9]{64}$/.test(expected)) return { staged: false, error: 'INVALID_UPDATE_SHA256' };
  if (!packageUrl.startsWith('/')) return { staged: false, error: 'INVALID_UPDATE_URL' };
  const rt = resolveBrowserRuntime({ root: layout.root });
  // Fast path: the live runtime already satisfies the offered pin.
  try {
    const livePkg = JSON.parse(
      (await fs.readFile(path.join(rt.coreDir, 'package.json'), 'utf8')).toString()
    );
    if (String(livePkg.version || '') === playwright) return { staged: false, current: true };
  } catch {}
  if (typeof authHeaders !== 'function') throw new Error('DEVICE_AUTH_REQUIRED');
  const requestUrl = serverUrl + packageUrl;
  const headers = await authHeaders('GET', requestUrl, { json: false });
  const r = await fetch(requestUrl, { headers, signal: AbortSignal.timeout(120000) });
  if (!r.ok) throw new Error(`UPDATE_DOWNLOAD_HTTP_${r.status}`);
  const body = Buffer.from(await r.arrayBuffer());
  if (sha256(body) !== expected) throw new Error('UPDATE_SHA256_MISMATCH');
  const staged = path.join(rt.base, 'browser-runtime.staging');
  await fs.rm(staged, { recursive: true, force: true });
  const tmpExtract = `${staged}.extract`;
  await fs.rm(tmpExtract, { recursive: true, force: true });
  try {
    await extractReleaseArchive(body, tmpExtract);
    // Payload archives carry a top-level browser-runtime/ dir; the staging
    // area mirrors the live layout (playwright-core/ directly inside).
    await fs.rename(path.join(tmpExtract, 'browser-runtime'), staged);
  } finally {
    await fs.rm(tmpExtract, { recursive: true, force: true });
  }
  const stagedPkg = JSON.parse(
    await fs.readFile(path.join(staged, 'playwright-core', 'package.json'), 'utf8')
  );
  if (String(stagedPkg.version || '') !== playwright) throw new Error('UPDATE_VERSION_MISMATCH');
  // Browsers stage alongside (no OS-deps at OTA time — installer-only),
  // without promoting: boot promotion validates before touching live paths.
  const browsers = await stageBrowserInstall({
    coreDir: path.join(staged, 'playwright-core'),
    browsersDir: rt.browsersDir,
    stagingDir: rt.stagingDir,
    withDeps: false,
    promote: false
  });
  if (!browsers.ok) throw new Error(browsers.error || 'BROWSER_INSTALLATION_MISSING');
  return { staged: true, playwright, browsers: browsers.revision || null };
}

/**
 * @param {object} options
 * @param {ReturnType<typeof import('../client/hhc-paths.mjs').hhcLayout>} options.layout
 * @param {string} options.stage
 * @param {string} options.previous
 * @param {string} options.failed
 * @param {string} options.marker
 * @param {string} options.lock
 * @param {number} options.parentPid
 */
export function windowsActivationHelperSource({
  layout,
  stage,
  previous,
  failed,
  marker,
  lock,
  parentPid
}) {
  /** @param {unknown} x */
  const v = (x) => JSON.stringify(x);
  return `import fs from 'node:fs';import path from 'node:path';\nconst sleep=ms=>new Promise(r=>setTimeout(r,ms));\nconst app=${v(layout.app)},stage=${v(stage)},previous=${v(previous)},failed=${v(failed)},marker=${v(marker)},lock=${v(lock)},clientLock=${v(layout.lockFile)},pidFile=${v(layout.pidFile)},parentPid=${Number(parentPid)};\nconst alive=pid=>{if(!Number.isInteger(pid)||pid<2)return false;try{process.kill(pid,0);return true}catch{return false}};\nconst move=(a,b)=>{fs.mkdirSync(a,{recursive:true});fs.mkdirSync(b,{recursive:true});for(const n of fs.readdirSync(a))fs.renameSync(path.join(a,n),path.join(b,n))};\nfor(let i=0;i<200&&alive(parentPid);i++)await sleep(100);\nif(alive(parentPid)){fs.rmSync(lock,{force:true});process.exit(3)};fs.rmSync(clientLock,{force:true});\ntry{move(app,previous);move(stage,app);fs.rmSync(lock,{force:true})}catch(e){try{if(fs.existsSync(previous)){move(app,stage);move(previous,app)}}catch{};fs.rmSync(lock,{force:true});process.exit(2)}\nawait sleep(25000);if(fs.existsSync(marker))process.exit(0);\ntry{fs.writeFileSync(lock,'rollback\\n');let pid=0;try{pid=Number(fs.readFileSync(pidFile,'utf8').trim())}catch{};if(alive(pid))try{process.kill(pid,'SIGTERM')}catch{};for(let i=0;i<100&&alive(pid);i++)await sleep(100);move(app,failed);move(previous,app)}catch{}finally{fs.rmSync(lock,{force:true})}\n`;
}

/**
 * @param {unknown} result
 * @param {object} [options]
 * @param {ReturnType<typeof import('../client/hhc-paths.mjs').hhcLayout>} [options.layout]
 */
export async function activatePreparedUpdate(result, { layout = hhcLayout() } = {}) {
  const resultRecord = /** @type {{result_payload?: {version?: unknown, stage_dir?: unknown}}} */ (
    result || {}
  );
  const version = String(resultRecord.result_payload?.version || ''),
    stage = String(resultRecord.result_payload?.stage_dir || '');
  const releasePrefix = path.resolve(layout.clientReleases) + path.sep;
  if (!validVersion(version) || !path.resolve(stage).startsWith(releasePrefix))
    throw new Error('INVALID_UPDATE_ACTIVATION');
  const stamp = Date.now(),
    previous = path.join(layout.clientBackups, `previous-${stamp}`),
    failed = path.join(layout.clientBackups, `failed-${stamp}`);
  const marker = path.join(layout.data, `healthy-${version}-${stamp}`),
    watchdog = path.join(layout.tmp, `watchdog-${stamp}.mjs`);
  await fs.mkdir(layout.clientBackups, { recursive: true });
  await fs.mkdir(layout.data, { recursive: true });
  await fs.mkdir(layout.tmp, { recursive: true });
  const activation = {
    version,
    app_dir: layout.app,
    previous_dir: previous,
    failed_dir: failed,
    healthy_marker: marker,
    activated_at: new Date().toISOString()
  };
  await fs.writeFile(layout.updateState, JSON.stringify(activation, null, 2) + '\n', {
    mode: 0o640
  });
  if (process.platform === 'win32') {
    const supervisor = path.join(layout.root, 'hhc-supervisor.ps1'),
      lock = path.join(layout.data, 'update-switch.lock');
    if (!(await exists(supervisor))) throw new Error('WINDOWS_UPDATE_SUPERVISOR_REQUIRED');
    await fs.writeFile(lock, `update ${version}\n`, { mode: 0o640 });
    await fs.writeFile(
      watchdog,
      windowsActivationHelperSource({
        layout,
        stage,
        previous,
        failed,
        marker,
        lock,
        parentPid: process.pid
      }),
      { mode: 0o700 }
    );
    const child = spawn(process.execPath, [watchdog], {
      cwd: layout.root,
      detached: true,
      stdio: 'ignore'
    });
    child.unref();
    setTimeout(() => process.kill(process.pid, 'SIGTERM'), 800).unref();
    return activation;
  }
  await fs.writeFile(watchdog, watchdogSource({ layout, previous, failed, marker }), {
    mode: 0o700
  });
  await swapAppContents(stage, { layout, previous });
  const child = spawn(process.execPath, [watchdog], { detached: true, stdio: 'ignore' });
  child.unref();
  setTimeout(() => process.kill(process.pid, 'SIGTERM'), 800).unref();
  return activation;
}

export async function markUpdateHealthy(layout = hhcLayout(), version = '') {
  try {
    const p = JSON.parse(await fs.readFile(layout.updateState, 'utf8'));
    if (p.version !== version || p.app_dir !== layout.app || !p.healthy_marker) return false;
    await fs.writeFile(p.healthy_marker, new Date().toISOString() + '\n', { mode: 0o640 });
    return true;
  } catch {
    return false;
  }
}

/**
 * @param {object} options
 * @param {ReturnType<typeof import('../client/hhc-paths.mjs').hhcLayout>} options.layout
 * @param {string} options.previous
 * @param {string} options.failed
 * @param {string} options.marker
 */
function watchdogSource({ layout, previous, failed, marker }) {
  const app = JSON.stringify(layout.app),
    prev = JSON.stringify(previous),
    bad = JSON.stringify(failed),
    mark = JSON.stringify(marker),
    pidFile = JSON.stringify(layout.pidFile);
  return `import fs from 'node:fs';import path from 'node:path';\nconst sleep=ms=>new Promise(r=>setTimeout(r,ms));const move=(a,b)=>{fs.mkdirSync(a,{recursive:true});fs.mkdirSync(b,{recursive:true});for(const n of fs.readdirSync(a))fs.renameSync(path.join(a,n),path.join(b,n))};await sleep(25000);\nif(fs.existsSync(${mark}))process.exit(0);\ntry{move(${app},${bad});move(${prev},${app});const pid=Number(fs.readFileSync(${pidFile},'utf8').trim());if(Number.isInteger(pid)&&pid>1)try{process.kill(pid,'SIGTERM')}catch{}}catch{}\n`;
}

export function updaterPolicy(layout = hhcLayout()) {
  return {
    integrity: 'sha256',
    activation: 'idle-only-after-result-ack',
    rollback: '25s detached watchdog',
    root: layout.root,
    app_dir: layout.app,
    releases_dir: layout.clientReleases,
    backups_dir: layout.clientBackups,
    mutable_data_outside_app: true
  };
}
