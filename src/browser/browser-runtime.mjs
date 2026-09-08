import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { hhcLayout } from '../client/hhc-paths.mjs';

// Pinned browser runtime. playwright-core is platform-independent JS; the
// Chromium binary revision is coupled to it via the payload's browsers.json.
// Bump BOTH together; the installer/OTA refuses to activate a new runtime
// whose browser revision is not installed AND launch-validated.
export const BROWSER_RUNTIME_PIN = Object.freeze({
  playwright: '1.63.0',
  chromiumRevision: '1243'
});

// Central browser policy defaults. No magic numbers in the manager: every
// tunable below is overridden by (in order) explicit tool args, the projected
// host-policy capabilities, then these defaults.
export const BROWSER_DEFAULTS = Object.freeze({
  mode: 'managed',
  headless: true,
  viewport: { width: 1280, height: 800 },
  actionTimeoutMs: 5000,
  navigationTimeoutMs: 60000,
  settleMs: 500,
  maxTimeoutMs: 120000,
  idleTimeoutMs: 15 * 60 * 1000,
  maxLifetimeMs: 2 * 60 * 60 * 1000,
  maxSessionsPerClient: 5,
  maxConsoleEntries: 500,
  maxNetworkEntries: 500,
  maxSnapshotChars: 20000,
  maxScreenshotBytes: 131072,
  maxDownloadBytes: 50 * 1024 * 1024,
  sweepIntervalMs: 60 * 1000
});

/**
 * @param {string} dir
 * @param {string} name
 */
function readJsonFile(dir, name) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
  } catch {
    return null;
  }
}

/**
 * Deterministic Chromium executable resolution (SYN-BRW-002). Playwright
 * resolves the binary through process-global registry state (memoized at
 * first import/launch), which makes launches hostage to import order and
 * early env values. HHC resolves the exact file itself with plain fs checks
 * and passes executablePath explicitly, so a launch can never consult stale
 * registry state. Returns the first hit plus the full tried list for
 * diagnostics (surfaced on launch failure).
 * Layout mirrors Playwright 1.63 EXECUTABLE_PATHS (linux/mac/win, x64/arm64,
 * headless-shell vs full, with legacy chrome-linux fallback).
 * @param {{browsersDir?: string|null, revision?: string|null, headless?: boolean, platform?: string, arch?: string}} [options]
 */
export function resolveChromiumExecutable({
  browsersDir = null,
  revision = null,
  headless = true,
  platform = process.platform,
  arch = process.arch
} = {}) {
  const tried = [];
  const rev = String(revision || BROWSER_RUNTIME_PIN.chromiumRevision || '');
  const root = String(browsersDir || '');
  const isMac = platform === 'darwin';
  const isWin = platform === 'win32';
  const arm = arch === 'arm64';
  /** @type {Array<Array<string>>} */
  let candidates = [];
  if (headless) {
    if (isWin)
      candidates = [
        [
          `chromium_headless_shell-${rev}`,
          'chrome-headless-shell-win64',
          'chrome-headless-shell.exe'
        ]
      ];
    else if (isMac)
      candidates = [
        [
          `chromium_headless_shell-${rev}`,
          arm ? 'chrome-headless-shell-mac-arm64' : 'chrome-headless-shell-mac-x64',
          'chrome-headless-shell'
        ]
      ];
    else
      candidates = [
        [
          `chromium_headless_shell-${rev}`,
          arm ? 'chrome-headless-shell-linux-arm64' : 'chrome-headless-shell-linux64',
          'chrome-headless-shell'
        ]
      ];
  } else if (isWin) candidates = [[`chromium-${rev}`, 'chrome-win64', 'chrome.exe']];
  else if (isMac)
    candidates = [
      [
        `chromium-${rev}`,
        arm ? 'chrome-mac-arm64' : 'chrome-mac-x64',
        'Google Chrome for Testing.app',
        'Contents',
        'MacOS',
        'Google Chrome for Testing'
      ]
    ];
  else if (arm) candidates = [[`chromium-${rev}`, 'chrome-linux-arm64', 'chrome']];
  else
    candidates = [
      [`chromium-${rev}`, 'chrome-linux64', 'chrome'],
      [`chromium-${rev}`, 'chrome-linux', 'chrome']
    ];
  if (root) {
    for (const parts of candidates) {
      const full = path.join(root, ...parts);
      tried.push(full);
      try {
        const st = fs.statSync(full);
        if (!st.isFile()) continue;
        if (!isWin) {
          try {
            fs.accessSync(full, fs.constants.X_OK);
          } catch {
            continue;
          }
        }
        return { ok: true, executablePath: full, tried };
      } catch {}
    }
  }
  return { ok: false, executablePath: null, tried };
}

/**
 * @param {{root?: string|null, dataDir?: string|null, env?: NodeJS.ProcessEnv}} [options]
 */
export function resolveBrowserRuntime(options = {}) {
  const env = options.env || process.env;
  let data = options.dataDir || env.HHC_BROWSER_DATA_DIR || null;
  if (!data) {
    try {
      data = hhcLayout(options.root || undefined).data;
    } catch {
      data = null;
    }
  }
  if (!data) data = env.HHC_BROWSER_DATA_DIR || path.join(os.tmpdir(), 'hhc-browser');
  const base = path.join(path.resolve(data), 'browser');
  const runtime = path.join(base, 'browser-runtime');
  return Object.freeze({
    base,
    runtime,
    coreDir: env.HHC_PLAYWRIGHT_CORE_PATH || path.join(runtime, 'playwright-core'),
    browsersDir: env.PLAYWRIGHT_BROWSERS_PATH || path.join(base, 'playwright-browsers'),
    stagingDir: path.join(base, 'playwright-browsers.staging'),
    profilesDir: path.join(base, 'profiles'),
    downloadsDir: path.join(base, 'downloads'),
    pin: BROWSER_RUNTIME_PIN
  });
}

/** @type {Record<string, any>|null} */
let cachedCore = null;
/** @type {string|null} */
let cachedCoreKey = null;

/**
 * Loads the vendored playwright-core from an explicit path only. Never a
 * bare specifier: production hosts must not resolve an ambient copy.
 * @param {string} coreDir
 */
export async function loadPlaywrightCore(coreDir) {
  if (cachedCore && cachedCoreKey === coreDir) return cachedCore;
  let mod = null;
  for (const entry of ['index.mjs', 'index.js']) {
    try {
      const full = path.join(coreDir, entry);
      if (!fs.existsSync(full)) continue;
      mod = await import(full);
      break;
    } catch {
      mod = null;
    }
  }
  if (!mod || !mod.chromium) throw new Error('BROWSER_RUNTIME_MISSING');
  const pkg = readJsonFile(coreDir, 'package.json');
  const version = String(pkg?.version || '');
  if (version !== BROWSER_RUNTIME_PIN.playwright) throw new Error('BROWSER_VERSION_MISMATCH');
  cachedCore = { ...mod, __version: version, __coreDir: coreDir };
  cachedCoreKey = coreDir;
  return cachedCore;
}

/** @param {string} coreDir */
export function expectedChromiumRevision(coreDir) {
  try {
    const browsers = JSON.parse(fs.readFileSync(path.join(coreDir, 'browsers.json'), 'utf8'));
    const entry = (browsers?.browsers || []).find(
      (/** @type {Record<string, any>} */ b) => b?.name === 'chromium'
    );
    if (entry?.revision) return String(entry.revision);
  } catch {}
  return BROWSER_RUNTIME_PIN.chromiumRevision;
}

/** @param {string} browsersDir */
export function installedChromiumRevisions(browsersDir) {
  try {
    return fs
      .readdirSync(browsersDir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && /^chromium-/.test(e.name))
      .map((e) => e.name.replace(/^chromium-/, ''));
  } catch {
    return [];
  }
}

/** @param {string} p */
function rmrf(p) {
  try {
    fs.rmSync(p, { recursive: true, force: true });
  } catch {}
  return null;
}

/**
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {Record<string, string>} [env]
 * @param {number} [timeoutMs]
 */
function runCmd(cmd, args, env, timeoutMs = 600000) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      env: { ...process.env, ...(env || {}) },
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      try {
        child.kill('SIGKILL');
      } catch {}
      resolve({ ok: false, out, err: (err + '\nINSTALL_TIMEOUT').slice(-2000) });
    }, timeoutMs);
    if (timer.unref) timer.unref();
    child.stdout.on('data', (d) => {
      out += String(d);
    });
    child.stderr.on('data', (d) => {
      err += String(d);
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ ok: false, out, err: String((e && e.message) || e).slice(-2000) });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0, out: out.slice(-2000), err: err.slice(-2000) });
    });
  });
}

/**
 * Moves staged browser revision dirs into the live browsers dir (.prev kept
 * for one generation). Shared by the installer path and boot promotion.
 * @param {string} browsersDir
 * @param {string} stagingDir
 */
export function promoteStagedBrowserDirs(browsersDir, stagingDir) {
  try {
    fs.mkdirSync(browsersDir, { recursive: true });
    const staged = fs.readdirSync(stagingDir);
    let moved = 0;
    for (const name of staged) {
      if (!/^(chromium-|chromium_headless_shell-|ffmpeg-)/.test(name)) continue;
      const target = path.join(browsersDir, name);
      if (/^chromium-/.test(name)) {
        rmrf(path.join(browsersDir, `${name}.prev`));
        if (fs.existsSync(target)) fs.renameSync(target, path.join(browsersDir, `${name}.prev`));
      } else {
        rmrf(target);
      }
      try {
        fs.renameSync(path.join(stagingDir, name), target);
        moved++;
      } catch {}
    }
    return { ok: moved > 0, moved };
  } catch {
    return { ok: false, moved: 0 };
  }
}

/**
 * Staged browser install: downloads into a staging directory, validates by
 * launching a blank page, and only then promotes the revision directory into
 * the live browsers dir. The previous revision is kept as .prev for rollback.
 * Never breaks the running revision on validation failure.
 * @param {{coreDir: string, browsersDir: string, stagingDir: string, withDeps?: boolean, timeoutMs?: number, promote?: boolean}} options
 */
export async function stageBrowserInstall(options) {
  const { coreDir, browsersDir, stagingDir } = options;
  const promote = options.promote !== false;
  const cli = path.join(coreDir, 'cli.js');
  if (!fs.existsSync(cli)) return { ok: false, error: 'BROWSER_RUNTIME_MISSING' };
  const revision = expectedChromiumRevision(coreDir);
  rmrf(stagingDir);
  try {
    fs.mkdirSync(stagingDir, { recursive: true });
  } catch {
    return { ok: false, error: 'BROWSER_INSTALLATION_MISSING' };
  }
  const args = ['install'];
  // OS dependencies only on Linux and only when running privileged; never
  // implied on Windows/macOS, and never during OTA (installer-only).
  if (options.withDeps === true && process.platform === 'linux') args.push('--with-deps');
  args.push('chromium');
  const installed = await runCmd(
    process.execPath,
    [cli, ...args],
    { PLAYWRIGHT_BROWSERS_PATH: stagingDir },
    options.timeoutMs || 600000
  );
  if (!installed.ok) {
    rmrf(stagingDir);
    return { ok: false, error: 'BROWSER_INSTALLATION_MISSING', detail: installed.err };
  }
  const staged = installedChromiumRevisions(stagingDir);
  if (!staged.includes(revision)) {
    rmrf(stagingDir);
    return { ok: false, error: 'BROWSER_VERSION_MISMATCH', detail: staged.join(',') };
  }
  // Validate BEFORE promoting: launch a blank page from the staged revision.
  const probe = await validateBrowserLaunch({
    coreDir,
    browsersDir: stagingDir,
    headless: true,
    timeoutMs: 60000
  });
  if (!probe.ok) {
    rmrf(stagingDir);
    return { ok: false, error: 'BROWSER_LAUNCH_FAILED', detail: probe.error };
  }
  if (!promote)
    return { ok: true, revision, playwright: BROWSER_RUNTIME_PIN.playwright, staged: true };
  const promoted = promoteStagedBrowserDirs(browsersDir, stagingDir);
  rmrf(stagingDir);
  if (!promoted.ok) return { ok: false, error: 'BROWSER_INTERNAL_ERROR' };
  return { ok: true, revision, playwright: BROWSER_RUNTIME_PIN.playwright };
}

/**
 * Playwright resolves browsers via PLAYWRIGHT_BROWSERS_PATH at launch time.
 * The manager calls this once with the HHC-managed dir; an operator-set
 * value is never overridden.
 * @param {string} browsersDir
 */
export function applyBrowsersPathEnv(browsersDir) {
  if (!process.env.PLAYWRIGHT_BROWSERS_PATH) {
    process.env.PLAYWRIGHT_BROWSERS_PATH = browsersDir;
  }
  return process.env.PLAYWRIGHT_BROWSERS_PATH;
}

/**
 * Boot-time activation of the app-bundled browser runtime (OTA vehicle for
 * pin changes: client.tar.gz carries browser-runtime/). When the bundled
 * payload version equals the running code pin and the live data runtime
 * differs, the bundle is copied to staging and promoted through the same
 * validated path as OTA staging. A bundle that disagrees with the pin is
 * ignored (fail-closed; the health gate reports the mismatch).
 * @param {{appDir: string, base: string}} options
 */
export async function activateBundledBrowserRuntime({ appDir, base }) {
  try {
    const bundledPkg = readJsonFile(
      path.join(appDir, 'browser-runtime', 'playwright-core'),
      'package.json'
    );
    if (!bundledPkg || String(bundledPkg.version || '') !== BROWSER_RUNTIME_PIN.playwright)
      return { promoted: false, reason: 'pin-mismatch' };
    const livePkg = readJsonFile(
      path.join(base, 'browser-runtime', 'playwright-core'),
      'package.json'
    );
    if (livePkg && String(livePkg.version || '') === BROWSER_RUNTIME_PIN.playwright)
      return { promoted: false, reason: 'current' };
    const staged = path.join(base, 'browser-runtime.staging');
    rmrf(staged);
    fs.mkdirSync(staged, { recursive: true });
    const bundled = path.join(appDir, 'browser-runtime');
    for (const entry of fs.readdirSync(bundled)) {
      fs.cpSync(path.join(bundled, entry), path.join(staged, entry), { recursive: true });
    }
    return activateStagedBrowserRuntime(base);
  } catch {
    return { promoted: false, reason: 'BROWSER_INTERNAL_ERROR' };
  }
}

/**
 * Background convergence for the managed Chromium binary (OTA vehicle is
 * the bundled/standalone runtime JS; the ~150 MB binary follows on first
 * boot when missing). Never blocks boot or hello: browser tools stay hidden
 * behind the health gate until the binary validates. No OS dependencies are
 * ever installed here (installer-only); download failures just retry on the
 * next boot and are logged.
 * @param {string} base
 * @returns {Promise<{installed: boolean, revision?: string, error?: string}>}
 */
export async function ensureManagedBrowsers(base) {
  try {
    const browsersDir = path.join(base, 'playwright-browsers');
    const revision = expectedChromiumRevision(
      path.join(base, 'browser-runtime', 'playwright-core')
    );
    if (installedChromiumRevisions(browsersDir).includes(revision))
      return { installed: true, revision };
    const coreDir = path.join(base, 'browser-runtime', 'playwright-core');
    if (!fs.existsSync(path.join(coreDir, 'cli.js')))
      return { installed: false, error: 'BROWSER_RUNTIME_MISSING' };
    const staged = await stageBrowserInstall({
      coreDir,
      browsersDir,
      stagingDir: path.join(base, 'playwright-browsers.staging'),
      withDeps: false,
      promote: true
    });
    if (!staged.ok)
      return { installed: false, error: staged.error || 'BROWSER_INSTALLATION_MISSING' };
    return { installed: true, revision: staged.revision || revision };
  } catch {
    return { installed: false, error: 'BROWSER_INTERNAL_ERROR' };
  }
}

/**
 * Boot-time promotion of a staged browser runtime (OTA path). The staged
 * payload activates only when its Playwright version equals the running
 * code pin: old code ignores newer staging, new code ignores stale staging.
 *
 * The runtime JS and the browser binaries promote INDEPENDENTLY: a pin
 * match always promotes the JS (validating the binary would deadlock fresh
 * hosts, where the binary can only arrive after the JS is live). Missing
 * binaries are reported, stay hidden behind the health gate, and converge
 * via ensureManagedBrowsers on this and every later boot. The previous
 * runtime is kept as .prev for one generation.
 * @param {string} base
 */
export async function activateStagedBrowserRuntime(base) {
  const live = path.join(base, 'browser-runtime');
  const staged = path.join(base, 'browser-runtime.staging');
  const prev = path.join(base, 'browser-runtime.prev');
  const stagedCore = path.join(staged, 'playwright-core');
  const pkg = readJsonFile(stagedCore, 'package.json');
  if (!pkg || String(pkg.version || '') !== BROWSER_RUNTIME_PIN.playwright) {
    if (fs.existsSync(staged)) rmrf(staged);
    return { promoted: false, reason: 'pin-mismatch' };
  }
  const browsersDir = path.join(base, 'playwright-browsers');
  const stagingDir = path.join(base, 'playwright-browsers.staging');
  const revision = expectedChromiumRevision(stagedCore);
  // Promote the JS first: it is what the health gate and all later steps
  // execute. Binaries follow opportunistically below.
  try {
    rmrf(prev);
    if (fs.existsSync(live)) fs.renameSync(live, prev);
    fs.renameSync(staged, live);
  } catch {
    return { promoted: false, reason: 'BROWSER_INTERNAL_ERROR' };
  }
  // Binaries: live already has them, or staging validated them, or they
  // converge later via ensureManagedBrowsers (never a promotion blocker).
  let browsers = 'absent';
  try {
    if (installedChromiumRevisions(browsersDir).includes(revision)) {
      browsers = 'live';
    } else if (installedChromiumRevisions(stagingDir).includes(revision)) {
      const probe = await validateBrowserLaunch({
        coreDir: path.join(live, 'playwright-core'),
        browsersDir: stagingDir,
        headless: true,
        timeoutMs: 60000
      });
      if (probe.ok) {
        const promoted = promoteStagedBrowserDirs(browsersDir, stagingDir);
        browsers = promoted.ok ? 'promoted' : 'validation-failed';
      } else {
        browsers = probe.error || 'BROWSER_LAUNCH_FAILED';
      }
      rmrf(stagingDir);
    }
  } catch {
    browsers = 'BROWSER_INTERNAL_ERROR';
  }
  return { promoted: true, playwright: BROWSER_RUNTIME_PIN.playwright, revision, browsers };
}

/**
 * Launch validation: blank page open + title read + clean close.
 * @param {{coreDir: string, browsersDir: string, headless?: boolean, timeoutMs?: number}} options
 */
export async function validateBrowserLaunch(options) {
  const started = Date.now();
  applyBrowsersPathEnv(options.browsersDir);
  const timeoutMs = options.timeoutMs || 60000;
  let core = null;
  try {
    core = await loadPlaywrightCore(options.coreDir);
  } catch (e) {
    return {
      ok: false,
      error:
        e && typeof e === 'object' && 'message' in e ? String(e.message) : 'BROWSER_RUNTIME_MISSING'
    };
  }
  if (!core) return { ok: false, error: 'BROWSER_RUNTIME_MISSING' };
  let browser = null;
  try {
    browser = await core.chromium.launch({
      headless: options.headless !== false,
      timeout: Math.min(timeoutMs, 60000),
      args: ['--no-first-run', '--no-default-browser-check', '--disable-dev-shm-usage']
    });
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto('about:blank', { timeout: Math.min(timeoutMs, 30000) });
    await page.title();
    await ctx.close();
    await browser.close();
    browser = null;
    return {
      ok: true,
      duration_ms: Date.now() - started,
      playwright: BROWSER_RUNTIME_PIN.playwright,
      revision: expectedChromiumRevision(options.coreDir)
    };
  } catch (e) {
    try {
      if (browser) await browser.close();
    } catch {}
    const msg = e && typeof e === 'object' && 'message' in e ? String(e.message) : '';
    if (/executable doesn't exist|Executable doesn't exist/i.test(msg))
      return { ok: false, error: 'BROWSER_INSTALLATION_MISSING' };
    return { ok: false, error: 'BROWSER_LAUNCH_FAILED' };
  }
}

/**
 * Lightweight startup health: import + pin + executable presence. No launch
 * (launch validation runs on first browser_create and is cached).
 * @param {{coreDir?: string, browsersDir?: string}} [options]
 */
export async function browserHealth(options = {}) {
  const rt = resolveBrowserRuntime();
  const coreDir = options.coreDir || rt.coreDir;
  const browsersDir = options.browsersDir || rt.browsersDir;
  let version = null;
  try {
    const core = await loadPlaywrightCore(coreDir);
    version = core ? core.__version : null;
    if (!core) throw new Error('BROWSER_RUNTIME_MISSING');
  } catch (e) {
    return {
      available: false,
      error:
        e && typeof e === 'object' && 'message' in e ? String(e.message) : 'BROWSER_NOT_AVAILABLE',
      playwright: null,
      revision: null,
      installed: []
    };
  }
  const revision = expectedChromiumRevision(coreDir);
  const installed = installedChromiumRevisions(browsersDir);
  if (!installed.includes(revision))
    return {
      available: false,
      error: 'BROWSER_INSTALLATION_MISSING',
      playwright: version,
      revision,
      installed
    };
  return { available: true, error: null, playwright: version, revision, installed };
}

/**
 * @param {string} p
 */
export function ensureDir(p) {
  try {
    fs.mkdirSync(p, { recursive: true, mode: 0o700 });
  } catch {}
  return p;
}
