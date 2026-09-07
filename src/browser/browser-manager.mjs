import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  BROWSER_DEFAULTS,
  BROWSER_RUNTIME_PIN,
  resolveBrowserRuntime,
  loadPlaywrightCore,
  applyBrowsersPathEnv,
  validateBrowserLaunch,
  ensureDir,
  expectedChromiumRevision
} from './browser-runtime.mjs';
import { validateEgressUrl, auditProjectionUrl, matchHostList } from '../policy/egress-policy.mjs';
import { hhcLayout } from '../client/hhc-paths.mjs';

// Interactive ARIA roles that always deserve a stable ref.
const WIDGET_ROLES = new Set([
  'button',
  'link',
  'textbox',
  'searchbox',
  'combobox',
  'listbox',
  'checkbox',
  'radio',
  'switch',
  'slider',
  'spinbutton',
  'menuitem',
  'menuitemcheckbox',
  'menuitemradio',
  'tab',
  'treeitem',
  'option',
  'gridcell',
  'rowheader',
  'columnheader',
  'heading',
  'img'
]);
const SKIP_ROLES = new Set(['none', 'presentation', 'generic']);
/** @type {Record<string, number>} */
export const CONSOLE_SEVERITY = Object.freeze({ error: 0, warning: 1, info: 2, debug: 3 });
// AX roles that getByRole cannot query (Chromium-internal text roles and
// roleless containers). Refs on these resolve through visible text instead.
const TEXT_FALLBACK_ROLES = new Set([
  'StaticText',
  'InlineTextBox',
  'text',
  'generic',
  'none',
  'presentation',
  'node'
]);
const STATIC_RESOURCE_TYPES = new Set(['image', 'font', 'stylesheet', 'media']);

/**
 * Playwright API surfaces (structural, intentionally loose: the vendored
 * playwright-core is loaded by explicit path at runtime, never bundled, so
 * static binding to its .d.ts would lie about availability).
 * @typedef {Record<string, any>} PWBrowser
 * @typedef {Record<string, any>} PWBContext
 * @typedef {Record<string, any>} PWPage
 * @typedef {Record<string, any>} PWLocator
 * @typedef {Record<string, any>} PWDialog
 * @typedef {Record<string, any>} PWDownload
 * @typedef {{page: PWPage, url: string, title: string}} PageRecord
 * @typedef {{role: string, name: string, index: number, nameIndex: number, pageId: string, revision: number}} RefEntry
 */

/**
 * @param {unknown} text
 */
export function redactSecretText(text) {
  let out = String(text || '');
  out = out.replace(/hhc_[0-9a-f]{64}/g, 'hhc_[REDACTED]');
  out = out.replace(/brw_[0-9a-f]{32}/g, 'brw_[REDACTED]');
  out = out.replace(/prc_[0-9a-f]{32}/g, 'prc_[REDACTED]');
  out = out.replace(/log_[0-9a-f]{32}/g, 'log_[REDACTED]');
  out = out.replace(/Bearer\s+[A-Za-z0-9\-._~+/=]{8,}/gi, 'Bearer [REDACTED]');
  out = out.replace(
    /(password|passwd|secret|api[_-]?key|access[_-]?token|session[_-]?token)\s*[:=]\s*\S+/gi,
    '$1=[REDACTED]'
  );
  out = out.replace(
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    '[PRIVATE KEY REDACTED]'
  );
  return out;
}

/**
 * @param {unknown} job
 */
export function policyFromJob(job) {
  const record = /** @type {Record<string, unknown>} */ (job || {});
  const payload = /** @type {Record<string, unknown>} */ (
    record.request_payload || record.payload || {}
  );
  const caps = /** @type {Record<string, unknown>} */ (record.agent_policy_capabilities || {});
  const roots =
    /** @type {{read?: Array<string>, write?: Array<string>}|Record<string, unknown>|null} */ (
      record.agent_policy_roots || null
    );
  const net = /** @type {Record<string, unknown>} */ (
    payload.browser_network_policy && typeof payload.browser_network_policy === 'object'
      ? payload.browser_network_policy
      : {}
  );
  const readRoots = Array.isArray(roots?.read)
    ? roots.read.filter((x) => typeof x === 'string')
    : Array.isArray(/** @type {Record<string, unknown>} */ (roots)?.allowed_read_roots)
      ? /** @type {Array<string>} */ (
          /** @type {Record<string, unknown>} */ (roots).allowed_read_roots
        ).filter((x) => typeof x === 'string')
      : [];
  return {
    payload,
    scriptExec: caps.browser_script_exec === true,
    privateNetwork: caps.browser_private_network === true,
    uploads: caps.browser_uploads === true,
    downloads: caps.browser_downloads === true,
    headed: caps.browser_headed === true,
    existingAttach: caps.browser_existing_attach === true,
    readRoots,
    network: {
      allowPrivateNetwork:
        net.allow_private_networks === true || caps.browser_private_network === true,
      allowLoopback:
        net.allow_loopback === true
          ? true
          : net.allow_loopback === false
            ? false
            : caps.browser_private_network === true,
      allowedHosts: Array.isArray(net.allowed_hosts)
        ? net.allowed_hosts.filter((x) => typeof x === 'string')
        : [],
      blockedHosts: Array.isArray(net.blocked_hosts)
        ? net.blocked_hosts.filter((x) => typeof x === 'string')
        : []
    }
  };
}

/**
 * @param {string} sessionId
 * @param {string} filename
 */
function sanitizeDownloadName(sessionId, filename) {
  const base = path.basename(String(filename || 'download')).replace(/[\0\\/]/g, '_');
  // Collapse dot-runs (no '..' traversal lookalikes, no hidden files) and
  // strip anything outside a conservative portable set.
  const clean =
    base
      .replace(/\.\.+/g, '_')
      .replace(/^\.+/, '')
      .replace(/[^A-Za-z0-9._-]/g, '_')
      .slice(0, 128) || 'download';
  return `${sessionId}_${Date.now().toString(36)}_${clean}`;
}

/**
 * @param {unknown} p
 * @param {Array<string>} readRoots
 * @param {string} downloadsDir
 * @returns {{ok: true, path: string, size: number}|{ok: false, error: string}}
 */
export function resolveUploadPath(p, readRoots, downloadsDir) {
  const raw = String(p || '');
  if (!raw) return { ok: false, error: 'BROWSER_UPLOAD_DENIED' };
  if (!path.isAbsolute(raw)) return { ok: false, error: 'BROWSER_UPLOAD_DENIED' };
  if (raw.includes('\0')) return { ok: false, error: 'BROWSER_UPLOAD_DENIED' };
  let real = null;
  try {
    real = fs.realpathSync(raw);
  } catch {
    return { ok: false, error: 'BROWSER_UPLOAD_DENIED' };
  }
  let st = null;
  try {
    st = fs.statSync(real);
  } catch {
    return { ok: false, error: 'BROWSER_UPLOAD_DENIED' };
  }
  if (!st.isFile()) return { ok: false, error: 'BROWSER_UPLOAD_DENIED' };
  if (st.size > BROWSER_DEFAULTS.maxDownloadBytes)
    return { ok: false, error: 'BROWSER_UPLOAD_DENIED' };
  const inside = (/** @type {string} */ root) => {
    const rel = path.relative(path.resolve(root), real);
    return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
  };
  if (inside(path.resolve(downloadsDir))) return { ok: true, path: real, size: st.size };
  for (const root of readRoots || []) {
    try {
      if (inside(root)) return { ok: true, path: real, size: st.size };
    } catch {}
  }
  return { ok: false, error: 'BROWSER_UPLOAD_DENIED' };
}

class BrowserSession {
  /**
   * @param {string} id
   * @param {Record<string, any>} [options]
   */
  constructor(id, options = {}) {
    this.id = id;
    this.mode = options.mode || 'managed';
    this.state = 'creating';
    /** @type {PWBrowser|null} */
    this.browser = options.browser || null;
    this.ownsBrowser = options.ownsBrowser !== false;
    /** @type {PWBContext|null} */
    this.context = null;
    /** @type {Map<string, PageRecord>} */
    this.pages = new Map();
    /** @type {string|null} */
    this.currentPageId = null;
    this.pageSeq = 0;
    /** @type {Map<string, RefEntry>} */
    this.refs = new Map();
    /** @type {string|null} */
    this.snapshotId = null;
    this.pageRevision = 0;
    /** @type {Map<string, Record<string, any>>} */
    this.cdpSessions = new Map();
    /** @type {Array<{seq: number, type: string, text: string, url: string|null, ts: string}>} */
    this.console = [];
    this.consoleSeq = 0;
    /** @type {Array<{seq: number, method: string, url: string, status: number|null, resource_type: string, duration_ms: number|null, failed: boolean}>} */
    this.network = [];
    this.networkSeq = 0;
    /** @type {Array<{filename: string, path: string, size_bytes: number, status: string}>} */
    this.downloads = [];
    /** @type {Record<string, any>|null} */
    this.pendingDialog = null;
    this.includeStatic = false;
    this.createdAt = Date.now();
    this.lastUsed = Date.now();
    this.headless = options.headless !== false;
    this.viewport = options.viewport || { ...BROWSER_DEFAULTS.viewport };
    this.locale = options.locale || null;
    this.timezone = options.timezone || null;
    this.userAgent = options.userAgent || null;
    this.profileId = options.profileId || null;
    this.downloadsDir = options.downloadsDir || null;
    this.playwrightVersion = options.playwrightVersion || null;
    this.browserRevision = options.browserRevision || null;
    /** @type {Promise<unknown>} */
    this.queue = Promise.resolve();
    this.policy = options.policy || null;
  }

  touch() {
    this.lastUsed = Date.now();
  }

  /**
   * Serialize ops per session; sessions stay independent.
   * @param {() => Promise<unknown>} fn
   */
  enqueue(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  currentPage() {
    const known =
      this.currentPageId && this.pages.has(this.currentPageId) ? this.currentPageId : null;
    const id = known || [...this.pages.keys()][0] || null;
    if (!id) return null;
    const rec = this.pages.get(id);
    if (!rec) return null;
    this.currentPageId = id;
    return { pageId: id, page: rec.page, url: rec.url, title: rec.title };
  }
}

export class BrowserManager {
  /**
   * @param {{dataDir?: string|null, root?: string|null, env?: NodeJS.ProcessEnv}} [options]
   */
  constructor(options = {}) {
    this.rt = resolveBrowserRuntime(options);
    /** @type {Record<string, any>|null} */
    this.core = null;
    /** @type {Map<string, BrowserSession>} */
    this.sessions = new Map();
    /** @type {Map<string, PWBrowser>} */
    this.managedBrowsers = new Map();
    /** @type {Map<string, string>} */
    this.profileLocks = new Map();
    this.launchValidated = false;
    this.sweeper = null;
    this.shuttingDown = false;
  }

  paths() {
    return this.rt;
  }

  startSweeper() {
    if (this.sweeper) return;
    this.sweeper = setInterval(() => {
      this.sweep().catch(() => {});
    }, BROWSER_DEFAULTS.sweepIntervalMs);
    if (this.sweeper.unref) this.sweeper.unref();
  }

  async coreApi() {
    if (this.core) return this.core;
    applyBrowsersPathEnv(this.rt.browsersDir);
    const loaded = await loadPlaywrightCore(this.rt.coreDir);
    if (!loaded) throw new Error('BROWSER_RUNTIME_MISSING');
    this.core = loaded;
    return loaded;
  }

  versions() {
    return {
      playwright: BROWSER_RUNTIME_PIN.playwright,
      revision: expectedChromiumRevision(this.rt.coreDir)
    };
  }

  /**
   * @param {string} id
   */
  sessionState(id) {
    const s = this.sessions.get(id);
    return s ? s.state : 'closed';
  }

  async sweep() {
    const now = Date.now();
    const ids = [...this.sessions.keys()];
    // Evict over-limit sessions first (oldest idle), then expired ones.
    const byIdle = ids
      .map((id) => /** @type {[string, BrowserSession]} */ ([id, this.sessions.get(id)]))
      .filter(([, s]) => s && s.id !== 'default')
      .sort((a, b) => (a[1]?.lastUsed || 0) - (b[1]?.lastUsed || 0));
    let excess = Math.max(0, byIdle.length - BROWSER_DEFAULTS.maxSessionsPerClient);
    for (const [id, s] of byIdle) {
      if (excess <= 0) break;
      if (s && s.state !== 'closing' && s.state !== 'closed') {
        await this.closeSession(id, 'evicted').catch(() => {});
        excess--;
      }
    }
    for (const [id, s] of this.sessions) {
      if (!s || s.state === 'closing' || s.state === 'closed') continue;
      if (
        now - s.lastUsed > BROWSER_DEFAULTS.idleTimeoutMs ||
        now - s.createdAt > BROWSER_DEFAULTS.maxLifetimeMs
      ) {
        await this.closeSession(id, 'expired').catch(() => {});
      }
    }
    // Shut down orphan managed browsers with no live sessions.
    for (const [key, browser] of this.managedBrowsers) {
      const inUse = [...this.sessions.values()].some(
        (s) => s.mode === 'managed' && s.browser === browser && s.state !== 'closed'
      );
      if (!inUse) {
        this.managedBrowsers.delete(key);
        try {
          await browser.close();
        } catch {}
      }
    }
  }

  /**
   * @param {{headless?: boolean, policy?: object}} [options]
   */
  async managedBrowser(options = {}) {
    const key = options.headless === false ? 'headed' : 'headless';
    const live = this.managedBrowsers.get(key);
    if (live) {
      try {
        if (live.isConnected && live.isConnected()) return live;
      } catch {}
      this.managedBrowsers.delete(key);
    }
    const core = await this.coreApi();
    if (!this.launchValidated) {
      const probe = await validateBrowserLaunch({
        coreDir: this.rt.coreDir,
        browsersDir: this.rt.browsersDir,
        headless: key === 'headless',
        timeoutMs: 60000
      });
      if (!probe.ok) throw new Error(probe.error || 'BROWSER_LAUNCH_FAILED');
      this.launchValidated = true;
    }
    const launchArgs = [
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-background-networking',
      '--disable-client-side-phishing-detection',
      '--disable-default-apps',
      '--disable-dev-shm-usage',
      '--disable-extensions',
      '--disable-sync',
      '--disable-translate',
      '--metrics-recording-only',
      '--safebrowsing-disable-auto-update'
    ];
    // NOTE: no --no-sandbox by policy. Sandbox stays enabled; deployments
    // that truly need otherwise must document and gate it explicitly.
    let browser = null;
    try {
      browser = await core.chromium.launch({
        headless: key === 'headless',
        timeout: 60000,
        args: launchArgs
      });
    } catch (e) {
      const msg = e && typeof e === 'object' && 'message' in e ? String(e.message) : '';
      if (/executable doesn't exist|Executable doesn't exist/i.test(msg))
        throw Object.assign(new Error('BROWSER_INSTALLATION_MISSING'), { cause: e });
      throw Object.assign(new Error('BROWSER_LAUNCH_FAILED'), { cause: e });
    }
    try {
      browser.on('disconnected', () => {
        this.managedBrowsers.delete(key);
        for (const s of this.sessions.values()) {
          if (s.browser === browser && s.state !== 'closed') s.state = 'lost';
        }
      });
    } catch {}
    this.managedBrowsers.set(key, browser);
    return browser;
  }

  /**
   * @param {string} id
   * @param {Record<string, any>} [options]
   */
  async createSession(id, options = {}) {
    const existing = this.sessions.get(id);
    if (existing && existing.state !== 'closed' && existing.state !== 'lost') return existing;
    if (existing) this.sessions.delete(id);
    const mode = String(options.mode || 'managed').toLowerCase();
    if (mode !== 'managed' && mode !== 'existing') throw new Error('BROWSER_UNSUPPORTED_MODE');
    if (mode === 'existing' && options.policy?.existingAttach !== true)
      throw new Error('BROWSER_POLICY_DENIED');
    if (options.headless === false && options.policy?.headed !== true)
      throw new Error('BROWSER_POLICY_DENIED');
    const session = new BrowserSession(id, {
      mode,
      headless: options.headless !== false,
      viewport: options.viewport || { ...BROWSER_DEFAULTS.viewport },
      locale: options.locale || null,
      timezone: options.timezone || null,
      userAgent: options.userAgent || null,
      profileId: options.profileId || null,
      policy: options.policy || null,
      downloadsDir: options.downloadsDir || null,
      playwrightVersion: BROWSER_RUNTIME_PIN.playwright,
      browserRevision: expectedChromiumRevision(this.rt.coreDir)
    });
    this.sessions.set(id, session);
    this.startSweeper();
    try {
      if (mode === 'existing') await this.attachExisting(session, options);
      else await this.launchManaged(session, options);
      session.state = 'ready';
    } catch (e) {
      session.state = 'error';
      this.sessions.delete(id);
      throw e;
    }
    return session;
  }

  /**
   * @param {BrowserSession} session
   * @param {Record<string, any>} [options]
   */
  async launchManaged(session, options = {}) {
    const core = await this.coreApi();
    const profileId = options.profileId || null;
    if (profileId) {
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(profileId)) throw new Error('BROWSER_POLICY_DENIED');
      if (this.profileLocks.has(profileId)) throw new Error('BROWSER_PROFILE_IN_USE');
      this.profileLocks.set(profileId, session.id);
      const userDataDir = path.join(this.rt.profilesDir, profileId);
      ensureDir(this.rt.profilesDir);
      let context = null;
      try {
        context = await core.chromium.launchPersistentContext(userDataDir, {
          headless: session.headless,
          viewport: session.viewport,
          ...(session.locale ? { locale: session.locale } : {}),
          ...(session.timezone ? { timezoneId: session.timezone } : {}),
          ...(session.userAgent ? { userAgent: session.userAgent } : {}),
          acceptDownloads: true,
          downloadsPath: session.downloadsDir || path.join(this.rt.downloadsDir, session.id),
          timeout: 60000,
          args: ['--no-first-run', '--no-default-browser-check', '--disable-dev-shm-usage']
        });
      } catch (e) {
        this.profileLocks.delete(profileId);
        const msg = e && typeof e === 'object' && 'message' in e ? String(e.message) : '';
        if (/executable doesn't exist|Executable doesn't exist/i.test(msg))
          throw Object.assign(new Error('BROWSER_INSTALLATION_MISSING'), { cause: e });
        throw Object.assign(new Error('BROWSER_LAUNCH_FAILED'), { cause: e });
      }
      session.browser = context.browser() || null;
      session.ownsBrowser = true;
      if (session.browser) {
        try {
          session.browser.on('disconnected', () => {
            if (session.state !== 'closed') session.state = 'lost';
          });
        } catch {}
      }
      session.context = context;
    } else {
      const browser = await this.managedBrowser({ headless: session.headless });
      session.browser = browser;
      session.ownsBrowser = false;
      let context = null;
      try {
        context = await browser.newContext({
          viewport: session.viewport,
          ...(session.locale ? { locale: session.locale } : {}),
          ...(session.timezone ? { timezoneId: session.timezone } : {}),
          ...(session.userAgent ? { userAgent: session.userAgent } : {}),
          acceptDownloads: true,
          downloadsPath: session.downloadsDir || path.join(this.rt.downloadsDir, session.id)
        });
      } catch {
        throw new Error('BROWSER_LAUNCH_FAILED');
      }
      session.context = context;
    }
    ensureDir(session.downloadsDir || path.join(this.rt.downloadsDir, session.id));
    session.downloadsDir = session.downloadsDir || path.join(this.rt.downloadsDir, session.id);
    if (!session.context) throw new Error('BROWSER_LAUNCH_FAILED');
    this.wireContext(session, session.context);
    await this.newPage(session, null);
  }

  /**
   * @param {BrowserSession} session
   * @param {Record<string, any>} [options]
   */
  async attachExisting(session, options = {}) {
    const endpoint = String(options.cdpEndpoint || '').trim();
    if (!endpoint) throw new Error('BROWSER_EXISTING_ATTACH_FAILED');
    if (!/^https?:\/\//.test(endpoint)) throw new Error('BROWSER_EXISTING_ATTACH_FAILED');
    const core = await this.coreApi();
    let browser = null;
    try {
      browser = await core.chromium.connectOverCDP(endpoint, { timeout: 30000 });
    } catch {
      throw new Error('BROWSER_EXISTING_ATTACH_FAILED');
    }
    session.browser = browser;
    session.ownsBrowser = false;
    const contexts = typeof browser.contexts === 'function' ? browser.contexts() : [];
    // Existing mode reuses the operator's default context: no storage
    // isolation is promised here. Managed mode is the isolated default.
    session.context = contexts[0] || null;
    if (!session.context) {
      try {
        if (browser.close) await browser.close();
      } catch {}
      throw new Error('BROWSER_EXISTING_ATTACH_FAILED');
    }
    try {
      browser.on('disconnected', () => {
        if (session.state !== 'closed') session.state = 'lost';
      });
    } catch {}
    session.downloadsDir = session.downloadsDir || path.join(this.rt.downloadsDir, session.id);
    ensureDir(session.downloadsDir);
    if (!session.context) throw new Error('BROWSER_EXISTING_ATTACH_FAILED');
    this.wireContext(session, session.context);
    const pages = typeof session.context.pages === 'function' ? session.context.pages() : [];
    if (pages.length === 0) await this.newPage(session, null);
    else {
      for (const page of pages) this.trackPage(session, page);
    }
  }

  /**
   * @param {BrowserSession} session
   * @param {PWBContext} context
   */
  wireContext(session, context) {
    try {
      context.setDefaultTimeout(BROWSER_DEFAULTS.actionTimeoutMs);
    } catch {}
    try {
      context.setDefaultNavigationTimeout(BROWSER_DEFAULTS.navigationTimeoutMs);
    } catch {}
    try {
      context.on('console', (/** @type {Record<string, any>} */ msg) => {
        try {
          const type = String((msg && msg.type && msg.type()) || 'log');
          const rank = CONSOLE_SEVERITY[type] !== undefined ? type : 'debug';
          let locUrl = null;
          try {
            locUrl = (msg.location && msg.location() && msg.location().url) || null;
          } catch {}
          session.console.push({
            seq: ++session.consoleSeq,
            type: rank,
            text: redactSecretText(String((msg && msg.text && msg.text()) || '')).slice(0, 2000),
            url: typeof locUrl === 'string' ? auditProjectionUrl(locUrl) : null,
            ts: new Date().toISOString()
          });
          if (session.console.length > BROWSER_DEFAULTS.maxConsoleEntries)
            session.console.splice(0, session.console.length - BROWSER_DEFAULTS.maxConsoleEntries);
        } catch {}
      });
    } catch {}
    const pending = new Map();
    try {
      context.on('request', (/** @type {Record<string, any>} */ req) => {
        try {
          pending.set(req, Date.now());
        } catch {}
      });
      const finish = (
        /** @type {Record<string, any>} */ req,
        /** @type {number|null} */ status,
        /** @type {boolean} */ failed
      ) => {
        try {
          const startedAt = pending.get(req) || Date.now();
          pending.delete(req);
          let rawUrl = '';
          try {
            rawUrl = req.url();
          } catch {}
          const type = (() => {
            try {
              return String(req.resourceType());
            } catch {
              return 'other';
            }
          })();
          if (
            !failed &&
            (status === null || status < 400) &&
            STATIC_RESOURCE_TYPES.has(type) &&
            session.includeStatic !== true
          )
            return;
          session.network.push({
            seq: ++session.networkSeq,
            method: (() => {
              try {
                return String(req.method());
              } catch {
                return '';
              }
            })(),
            url: auditProjectionUrl(rawUrl),
            status,
            resource_type: type,
            duration_ms: Date.now() - startedAt,
            failed: Boolean(failed)
          });
          if (session.network.length > BROWSER_DEFAULTS.maxNetworkEntries)
            session.network.splice(0, session.network.length - BROWSER_DEFAULTS.maxNetworkEntries);
        } catch {}
      };
      context.on('response', (/** @type {Record<string, any>} */ res) => {
        try {
          finish(res.request(), res.status(), false);
        } catch {}
      });
      context.on('requestfailed', (/** @type {Record<string, any>} */ req) =>
        finish(req, null, true)
      );
    } catch {}
    try {
      context.on('page', (/** @type {PWPage} */ page) => {
        try {
          this.trackPage(session, page);
        } catch {}
      });
    } catch {}
    try {
      context.on('dialog', (/** @type {PWDialog} */ dialog) => {
        try {
          const record = {
            type: (() => {
              try {
                return String(dialog.type());
              } catch {
                return '';
              }
            })(),
            message: redactSecretText(
              (() => {
                try {
                  return String(dialog.message());
                } catch {
                  return '';
                }
              })()
            ).slice(0, 2000),
            url: session.currentPage()?.url || null,
            ts: new Date().toISOString(),
            handled: false
          };
          if (session.pendingDialog?.timer) clearTimeout(session.pendingDialog.timer);
          const timer = setTimeout(() => {
            try {
              if (session.pendingDialog?.dialog === dialog) {
                session.pendingDialog = { ...record, handled: true, accept: false };
                dialog.dismiss().catch(() => {});
              }
            } catch {}
          }, 3000);
          if (timer.unref) timer.unref();
          session.pendingDialog = { dialog, timer, ...record };
        } catch {
          try {
            dialog.dismiss().catch(() => {});
          } catch {}
        }
      });
    } catch {}
  }

  /**
   * @param {BrowserSession} session
   * @param {PWPage} page
   */
  trackPage(session, page) {
    for (const [id, rec] of session.pages) {
      if (rec.page === page) {
        session.currentPageId = session.currentPageId || id;
        return id;
      }
    }
    const pageId = 'pg_' + crypto.randomBytes(6).toString('hex');
    session.pages.set(pageId, { page, url: 'about:blank', title: '' });
    if (!session.currentPageId) session.currentPageId = pageId;
    try {
      page.on('close', () => {
        try {
          session.pages.delete(pageId);
          session.cdpSessions.delete(pageId);
          if (session.currentPageId === pageId) session.currentPageId = null;
        } catch {}
      });
    } catch {}
    try {
      page.on('download', (/** @type {PWDownload} */ dl) => {
        this.handleDownload(session, dl).catch(() => {});
      });
    } catch {}
    return pageId;
  }

  /**
   * @param {BrowserSession} session
   * @param {string|null} url
   */
  async newPage(session, url) {
    if (!session.context) throw new Error('BROWSER_SESSION_LOST');
    const page = await session.context.newPage();
    const pageId = this.trackPage(session, page);
    session.currentPageId = pageId;
    if (url) {
      try {
        await page.goto(url, { timeout: BROWSER_DEFAULTS.navigationTimeoutMs });
      } catch {}
    }
    return { pageId, page };
  }

  /**
   * @param {BrowserSession} session
   * @param {PWDownload} dl
   */
  async handleDownload(session, dl) {
    const allowed = session.policy?.downloads === true;
    let suggested = 'download';
    try {
      suggested = (await dl.suggestedFilename()) || suggested;
    } catch {}
    if (!allowed) {
      try {
        await dl.cancel();
      } catch {}
      session.downloads.push({
        filename: String(suggested).slice(0, 128),
        path: '',
        size_bytes: 0,
        status: 'blocked_policy'
      });
      return;
    }
    const filename = sanitizeDownloadName(session.id, suggested);
    const dest = path.join(session.downloadsDir, filename);
    try {
      await dl.saveAs(dest);
      let size = 0;
      try {
        size = fs.statSync(dest).size;
      } catch {}
      if (size > BROWSER_DEFAULTS.maxDownloadBytes) {
        try {
          fs.rmSync(dest, { force: true });
        } catch {}
        session.downloads.push({ filename, path: '', size_bytes: size, status: 'too_large' });
        return;
      }
      session.downloads.push({ filename, path: dest, size_bytes: size, status: 'completed' });
    } catch {
      session.downloads.push({ filename, path: '', size_bytes: 0, status: 'failed' });
    }
  }

  /**
   * @param {string} id
   * @param {string} [reason]
   */
  async closeSession(id, reason = 'close') {
    const session = this.sessions.get(id);
    if (!session) return { closed: false, existed: false };
    if (session.state === 'closed') return { closed: true, existed: true };
    session.state = 'closing';
    if (session.pendingDialog?.timer) {
      try {
        clearTimeout(session.pendingDialog.timer);
      } catch {}
      session.pendingDialog = null;
    }
    for (const cdp of session.cdpSessions.values()) {
      try {
        await cdp.detach();
      } catch {}
    }
    session.cdpSessions.clear();
    try {
      if (session.context) {
        if (session.mode === 'existing' || session.profileId) {
          // Existing: never close the operator's browser; close only pages
          // we created. Persistent profiles keep their browser alive.
          if (session.mode === 'existing') {
            for (const [, rec] of session.pages) {
              try {
                await rec.page.close();
              } catch {}
            }
            try {
              if (session.browser && session.browser.close) {
                // Detach-only: Playwright closes CDP sessions it owns.
              }
            } catch {}
          } else {
            await session.context.close();
          }
        } else {
          await session.context.close();
        }
      }
    } catch {}
    if (session.profileId) this.profileLocks.delete(session.profileId);
    if (session.ownsBrowser && session.browser) {
      try {
        await session.browser.close();
      } catch {}
    }
    session.pages.clear();
    session.refs.clear();
    session.state = 'closed';
    this.sessions.delete(id);
    // Downloads metadata dies with the session; files are TTL-swept.
    try {
      fs.rmSync(path.join(this.rt.downloadsDir, id), { recursive: true, force: true });
    } catch {}
    void reason;
    return { closed: true, existed: true };
  }

  async closeAll() {
    this.shuttingDown = true;
    if (this.sweeper) {
      clearInterval(this.sweeper);
      this.sweeper = null;
    }
    for (const id of [...this.sessions.keys()]) {
      await this.closeSession(id, 'shutdown').catch(() => {});
    }
    for (const [, browser] of this.managedBrowsers) {
      try {
        await browser.close();
      } catch {}
    }
    this.managedBrowsers.clear();
  }

  /**
   * @param {string} id
   */
  requireSession(id) {
    const session = this.sessions.get(id);
    if (!session) {
      const err = new Error('BROWSER_SESSION_NOT_FOUND');
      throw err;
    }
    if (session.state === 'lost' || session.state === 'error') {
      const err = new Error('BROWSER_SESSION_LOST');
      throw err;
    }
    if (session.state === 'closing' || session.state === 'closed') {
      throw new Error('BROWSER_SESSION_NOT_FOUND');
    }
    return session;
  }

  /**
   * @param {BrowserSession} session
   * @param {unknown} pageId
   */
  requirePage(session, pageId) {
    const wanted = typeof pageId === 'string' && pageId ? pageId : null;
    const id = wanted || session.currentPageId || session.currentPage()?.pageId || null;
    if (!id) throw new Error('BROWSER_PAGE_NOT_FOUND');
    const rec = session.pages.get(id);
    if (!rec) throw new Error('BROWSER_PAGE_NOT_FOUND');
    try {
      if (rec.page.isClosed && rec.page.isClosed()) {
        session.pages.delete(id);
        session.cdpSessions.delete(id);
        throw new Error('BROWSER_PAGE_NOT_FOUND');
      }
    } catch (e) {
      if (e && typeof e === 'object' && 'message' in e && String(e.message).startsWith('BROWSER_'))
        throw e;
    }
    return { pageId: /** @type {string} */ (id), ...rec };
  }

  /**
   * @param {BrowserSession} session
   * @param {unknown} pageId
   */
  async cdpForPage(session, pageId) {
    const ctx = session.context;
    if (!ctx) throw new Error('BROWSER_SESSION_LOST');
    const want = typeof pageId === 'string' && pageId ? pageId : session.currentPageId || '';
    const hit = session.cdpSessions.get(want);
    if (hit) return hit;
    const { page } = this.requirePage(session, want);
    const cdp = await ctx.newCDPSession(page);
    try {
      await cdp.send('Accessibility.enable');
    } catch {}
    session.cdpSessions.set(want, cdp);
    return cdp;
  }

  /**
   * @param {BrowserSession} session
   * @param {{pageId?: string|null, target?: string|null, depth?: number|null, maxChars?: number|null}} [options]
   */
  async snapshot(session, options = {}) {
    session.touch();
    const { page } = this.requirePage(session, options.pageId || '');
    const cdp = await this.cdpForPage(session, options.pageId || session.currentPageId || '');
    let rootId = null;
    if (options.target) {
      const resolved = await this.resolveTarget(session, options.target, {
        pageId: options.pageId || ''
      });
      rootId = resolved.backendNodeId || null;
      if (!rootId) throw new Error('BROWSER_TARGET_NOT_FOUND');
    }
    /** @type {{nodes?: Array<Record<string, unknown>>}} */
    let ax = { nodes: [] };
    try {
      ax = await cdp.send('Accessibility.getFullAXTree', {});
    } catch {
      throw new Error('BROWSER_SNAPSHOT_FAILED');
    }
    const nodes = Array.isArray(ax.nodes) ? ax.nodes : [];
    const rendered = this.renderAxTree(session, nodes, {
      rootId,
      depth: options.depth || null,
      maxChars: options.maxChars || BROWSER_DEFAULTS.maxSnapshotChars
    });
    let url = '';
    let title = '';
    try {
      url = page.url();
    } catch {}
    try {
      title = await page.title();
    } catch {}
    const rec = session.pages.get(options.pageId || session.currentPageId || '');
    if (rec) {
      rec.url = url;
      rec.title = title;
    }
    session.snapshotId = 'snap_' + crypto.randomBytes(8).toString('hex');
    return {
      snapshot_id: session.snapshotId,
      page_revision: session.pageRevision,
      url,
      title,
      tree: rendered.text,
      truncated: rendered.truncated,
      ref_count: rendered.refCount
    };
  }

  /**
   * @param {BrowserSession} session
   * @param {Array<Record<string, unknown>>} nodes
   * @param {{rootId?: string|number|null, depth?: number|null, maxChars?: number|null}} options
   */
  renderAxTree(session, nodes, options = {}) {
    const nodeMap = new Map();
    for (const n of nodes) nodeMap.set(n.nodeId, n);
    const childSet = new Set();
    for (const n of nodes) {
      if (Array.isArray(n.childIds)) for (const cid of n.childIds) childSet.add(cid);
    }
    // Subtree root: match CDP backendDOMNodeId when a target was given.
    let roots = nodes.filter((n) => !childSet.has(n.nodeId));
    if (options.rootId !== null && options.rootId !== undefined) {
      const match = nodes.find(
        (n) =>
          String(n.backendDOMNodeId || '') === String(options.rootId) ||
          String(n.nodeId || '') === String(options.rootId)
      );
      if (match) roots = [match];
    }
    /** @type {Array<{line: string, path: string, ref: string|null, depth: number}>} */
    const rows = [];
    session.refs.clear();
    let refSeq = 0;
    /** @type {Map<string, number>} */
    const roleCounts = new Map();
    /** @type {Map<string, number>} */
    const namedCounts = new Map();
    const maxDepth = options.depth || 0;
    /**
     * @param {Record<string, unknown>} node
     * @param {number} depth
     * @param {Array<string>} trail
     */
    const renderNode = (node, depth, trail) => {
      const role = String(/** @type {Record<string, any>} */ (node.role || {}).value || 'node');
      const name = String(/** @type {Record<string, any>} */ (node.name || {}).value || '').trim();
      const value = String(
        /** @type {Record<string, any>} */ (node.value || {}).value || ''
      ).trim();
      const description = String(
        /** @type {Record<string, any>} */ (node.description || {}).value || ''
      ).trim();
      const props = /** @type {Record<string, any>} */ (node.properties || {});
      const states = [];
      for (const [k, label] of [
        ['checked', 'checked'],
        ['disabled', 'disabled'],
        ['expanded', 'expanded'],
        ['selected', 'selected'],
        ['required', 'required'],
        ['invalid', 'invalid']
      ]) {
        if (props[k]?.value === true) states.push(label);
      }
      const ignored = node.ignored === true || SKIP_ROLES.has(role);
      const hasContent = Boolean(name || value || description);
      const refable = WIDGET_ROLES.has(role) || (!ignored && hasContent && name.length > 0);
      let ref = null;
      if (refable) {
        ref = 'e' + ++refSeq;
        const index = roleCounts.get(role) || 0;
        roleCounts.set(role, index + 1);
        const namedKey = role + '\u0000' + name;
        const nameIndex = namedCounts.get(namedKey) || 0;
        namedCounts.set(namedKey, nameIndex + 1);
        const cur = session.currentPage();
        session.refs.set(ref, {
          role,
          name,
          index,
          nameIndex,
          pageId: cur?.pageId || '',
          revision: session.pageRevision
        });
      }
      const crumb = name ? `${role} "${name.slice(0, 60)}"` : role;
      const nextTrail = [...trail, crumb];
      if (!ignored || hasContent) {
        const indent = '  '.repeat(depth);
        let line = `${indent}- ${role}`;
        if (name) line += ` "${name.slice(0, 200)}"`;
        if (value && value !== name) line += ` val="${value.slice(0, 120)}"`;
        if (description) line += ` (${description.slice(0, 120)})`;
        if (states.length) line += ` [${states.join(',')}]`;
        if (ref) line += ` [ref=${ref}]`;
        rows.push({ line, path: nextTrail.join(' > '), ref, depth });
      }
      if (maxDepth > 0 && depth >= maxDepth) return;
      if (Array.isArray(node.childIds)) {
        for (const cid of node.childIds) {
          const child = nodeMap.get(cid);
          if (child) renderNode(child, !ignored || hasContent ? depth + 1 : depth, nextTrail);
        }
      }
    };
    for (const r of roots) renderNode(r, 0, []);
    const budget = Math.max(
      1024,
      Math.min(100000, Number(options.maxChars) || BROWSER_DEFAULTS.maxSnapshotChars)
    );
    let text = rows.map((r) => r.line).join('\n') || '(empty accessibility tree)';
    let truncated = false;
    if (text.length > budget) {
      text = text.slice(0, budget);
      truncated = true;
    }
    return { text, truncated, refCount: session.refs.size, rows };
  }

  /**
   * @param {BrowserSession} session
   * @param {{text?: string|null, regex?: string|null, maxResults?: number|null}} options
   */
  async find(session, options = {}) {
    session.touch();
    const text = typeof options.text === 'string' ? options.text : '';
    const regex = typeof options.regex === 'string' ? options.regex : '';
    if ((text && regex) || (!text && !regex)) throw new Error('BROWSER_FIND_QUERY_REQUIRED');
    let matcher = null;
    if (text) {
      const needle = text.toLowerCase();
      matcher = (/** @type {string} */ line) => line.toLowerCase().includes(needle);
    } else {
      let pattern = regex;
      let flags = '';
      const m = /^\/(.+)\/([a-z]*)$/.exec(regex);
      if (m) {
        pattern = m[1] || '';
        flags = m[2] || '';
      }
      let re = null;
      try {
        re = new RegExp(pattern, flags);
      } catch {
        throw new Error('BROWSER_FIND_QUERY_REQUIRED');
      }
      matcher = (/** @type {string} */ line) => re.test(line);
    }
    const full = await this.snapshot(session, { maxChars: 100000 });
    const lines = String(full.tree).split('\n');
    const maxResults = Math.max(1, Math.min(50, Number(options.maxResults) || 10));
    const matches = [];
    for (let i = 0; i < lines.length && matches.length < maxResults + 1; i++) {
      if (matcher(lines[i] || '')) {
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        const ref = /\[ref=(e\d+)\]/.exec(lines[i] || '')?.[1] || null;
        matches.push({
          ref,
          line: i + 1,
          snippet: lines.slice(start, end).join('\n').slice(0, 1200)
        });
      }
    }
    const truncated = matches.length > maxResults;
    return {
      matches: matches.slice(0, maxResults),
      truncated,
      snapshot_id: full.snapshot_id,
      page_revision: full.page_revision,
      url: full.url,
      title: full.title
    };
  }

  /**
   * Resolve a target (ref like e17, or CSS selector) to a Playwright locator
   * plus CDP backend node id when cheap. Stale refs fail closed.
   * @param {BrowserSession} session
   * @param {string} target
   * @param {{pageId?: string|null}} [options]
   */
  async resolveTarget(session, target, options = {}) {
    const raw = String(target || '').trim();
    if (!raw) throw new Error('BROWSER_TARGET_NOT_FOUND');
    const { page } = this.requirePage(session, options.pageId || '');
    const refMatch = /^e(\d+)$/.exec(raw);
    if (refMatch) {
      const entry = session.refs.get(raw);
      if (!entry) throw new Error('BROWSER_STALE_TARGET');
      if (entry.revision !== session.pageRevision) throw new Error('BROWSER_STALE_TARGET');
      if (options.pageId && entry.pageId && entry.pageId !== options.pageId)
        throw new Error('BROWSER_STALE_TARGET');
      // Deterministic re-resolution: nth widget of its role, narrowed by
      // name when the snapshot had one. Unnamed widgets (bare inputs)
      // resolve by role order instead of failing. Text-only roles fall back
      // to visible-text matching.
      let locator = null;
      if (TEXT_FALLBACK_ROLES.has(entry.role)) {
        if (!entry.name) throw new Error('BROWSER_TARGET_NOT_FOUND');
        locator = page.getByText(entry.name).nth(entry.nameIndex);
      } else {
        locator = entry.name
          ? page.getByRole(entry.role, { name: entry.name }).nth(entry.nameIndex)
          : page.getByRole(entry.role).nth(entry.index);
      }
      try {
        await locator.waitFor({ state: 'attached', timeout: 2000 });
      } catch {
        throw new Error('BROWSER_STALE_TARGET');
      }
      return { locator, pageId: entry.pageId, backendNodeId: null };
    }
    // CSS selector path (backward compatibility).
    let locator = null;
    try {
      locator = page.locator(raw).first();
      const count = await page.locator(raw).count();
      if (count < 1) throw new Error('BROWSER_TARGET_NOT_FOUND');
    } catch (e) {
      if (e && typeof e === 'object' && 'message' in e && String(e.message).startsWith('BROWSER_'))
        throw e;
      throw Object.assign(new Error('BROWSER_TARGET_NOT_FOUND'), { cause: e });
    }
    let backendNodeId = null;
    try {
      const cdp = await this.cdpForPage(session, options.pageId || session.currentPageId || '');
      const doc = await cdp.send('DOM.getDocument', { depth: 1 });
      const found = await cdp.send('DOM.querySelector', {
        nodeId: doc.root.nodeId,
        selector: raw
      });
      backendNodeId = found?.nodeId || null;
    } catch {}
    return { locator, pageId: options.pageId || session.currentPageId, backendNodeId };
  }
}

/** @type {BrowserManager|null} */
let sharedManager = null;

/**
 * @param {{dataDir?: string|null, root?: string|null, env?: NodeJS.ProcessEnv}} [options]
 */
export function getBrowserManager(options = {}) {
  if (sharedManager) return sharedManager;
  sharedManager = new BrowserManager(options);
  return sharedManager;
}

/** For tests: drop the shared instance. */
export function resetBrowserManager() {
  const m = sharedManager;
  sharedManager = null;
  return m;
}

/**
 * @param {unknown} err
 * @param {'navigate'|'action'} kind
 */
export function mapBrowserError(err, kind = 'action') {
  const msg = err && typeof err === 'object' && 'message' in err ? String(err.message) : '';
  if (/^BROWSER_[A-Z_]+/.test(msg)) return msg;
  if (/Timeout/i.test(msg))
    return kind === 'navigate' ? 'BROWSER_NAVIGATION_TIMEOUT' : 'BROWSER_ACTION_TIMEOUT';
  if (/closed|destroyed|disconnected|crash|crashed/i.test(msg)) return 'BROWSER_SESSION_LOST';
  if (/net::|ERR_/i.test(msg)) return 'BROWSER_NAVIGATION_FAILED';
  return 'BROWSER_INTERNAL_ERROR';
}

/**
 * Standard job envelope helpers.
 * @param {number} started
 * @param {Record<string, unknown>} payload
 * @param {string|null} [stdout]
 */
export function okJob(started, payload, stdout = '') {
  return {
    status: 'completed',
    exit_code: 0,
    stdout: stdout || '',
    stderr: '',
    error: null,
    duration_ms: Date.now() - started,
    result_payload: payload
  };
}

/**
 * @param {number} started
 * @param {string} error
 * @param {Record<string, unknown>} [payload]
 */
export function failJob(started, error, payload = {}) {
  return {
    status: 'failed',
    exit_code: null,
    stdout: '',
    stderr: '',
    error,
    duration_ms: Date.now() - started,
    result_payload: payload
  };
}

/**
 * Client-audit summary for browser ops. Values, cookies, tokens and bodies
 * are NEVER included: action + target identity + sanitized URL only.
 * @param {string} op
 * @param {Record<string, unknown>} payload
 * @param {Record<string, unknown>} result
 */
export function browserAuditSummary(op, payload = {}, result = {}) {
  const rp =
    result?.result_payload && typeof result.result_payload === 'object'
      ? /** @type {Record<string, unknown>} */ (result.result_payload)
      : {};
  const redactTarget = (/** @type {unknown} */ t) => {
    const s = String(t || '');
    if (/^e\d+$/.test(s)) return s;
    return s ? '[selector]' : null;
  };
  return {
    browser_id:
      typeof rp.browser_id === 'string'
        ? rp.browser_id
        : typeof payload.browser_id === 'string'
          ? payload.browser_id
          : null,
    action:
      typeof rp.action === 'string'
        ? rp.action
        : typeof payload.action === 'string'
          ? payload.action
          : op,
    target: redactTarget(rp.target_ref || payload.target || payload.selector),
    url: typeof rp.url === 'string' ? auditProjectionUrl(rp.url) : null,
    page_id: typeof rp.page_id === 'string' ? rp.page_id : null,
    value: '[REDACTED]',
    duration_ms: typeof result.duration_ms === 'number' ? result.duration_ms : null,
    error: typeof result.error === 'string' ? result.error : null
  };
}

export { BROWSER_DEFAULTS };
