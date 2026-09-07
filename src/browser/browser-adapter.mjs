import { spawn } from 'node:child_process';
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import dns from 'node:dns/promises';
import { validateEgressUrl, auditProjectionUrl } from '../policy/egress-policy.mjs';

/**
 * @param {string} hostname
 * @returns {Promise<Array<string>>}
 */
export async function resolveAgentAddresses(hostname) {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

// --- System Browser Discovery ---
/**
 * @param {string} [preferred]
 */
export function findSystemBrowser(preferred = 'auto') {
  const plat = os.platform();
  /** @type {Array<{path: string, type: string}>} */
  const candidates = [];

  if (plat === 'win32') {
    const progFiles86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
    const progFiles = process.env.ProgramFiles || 'C:\\Program Files';
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');

    const edgePaths = [
      path.join(progFiles86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(progFiles, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(localAppData, 'Microsoft', 'Edge', 'Application', 'msedge.exe')
    ];
    const chromePaths = [
      path.join(progFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(progFiles86, 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(localAppData, 'Google', 'Chrome', 'Application', 'chrome.exe')
    ];

    if (preferred === 'edge') {
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
    } else if (preferred === 'chrome') {
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
    } else {
      // Default on Windows: Prefer Edge then Chrome
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
    }
  } else if (plat === 'darwin') {
    const edgePaths = ['/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'];
    const chromePaths = [
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
      '/Applications/Chromium.app/Contents/MacOS/Chromium'
    ];

    if (preferred === 'edge') {
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
    } else if (preferred === 'chrome') {
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
    } else {
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
    }
  } else {
    // Linux
    const chromePaths = [
      '/usr/bin/google-chrome',
      '/usr/bin/google-chrome-stable',
      '/usr/bin/chromium',
      '/usr/bin/chromium-browser'
    ];
    const edgePaths = ['/usr/bin/microsoft-edge', '/usr/bin/microsoft-edge-stable'];

    if (preferred === 'edge') {
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
    } else {
      candidates.push(...chromePaths.map((p) => ({ path: p, type: 'chrome' })));
      candidates.push(...edgePaths.map((p) => ({ path: p, type: 'edge' })));
    }
  }

  for (const c of candidates) {
    try {
      if (fs.existsSync(c.path)) {
        return c;
      }
    } catch {}
  }
  return null;
}

// --- Active Session Management ---
/** @type {CdpSession | null} */
let activeBrowser = null;
/** @type {NodeJS.Timeout | null} */
let sessionIdleTimer = null;

function resetIdleTimeout() {
  if (sessionIdleTimer) clearTimeout(sessionIdleTimer);
  // Auto-terminate browser after 5 minutes of inactivity to preserve memory
  sessionIdleTimer = setTimeout(
    () => {
      closeActiveBrowser().catch(() => {});
    },
    5 * 60 * 1000
  );
  if (sessionIdleTimer.unref) sessionIdleTimer.unref();
}

export async function closeActiveBrowser() {
  if (sessionIdleTimer) {
    clearTimeout(sessionIdleTimer);
    sessionIdleTimer = null;
  }
  if (!activeBrowser) return;

  const current = activeBrowser;
  activeBrowser = null;

  try {
    if (current.ws && current.ws.readyState === 1) {
      current.ws.close();
    }
  } catch {}

  try {
    if (current.process) {
      current.process.kill('SIGTERM');
      setTimeout(() => {
        try {
          current.process.kill('SIGKILL');
        } catch {}
      }, 1000).unref?.();
    }
  } catch {}

  try {
    if (current.profileDir) {
      await fsPromises.rm(current.profileDir, { recursive: true, force: true });
    }
  } catch {}
}

// --- CDP Connection Class ---
class CdpSession {
  /**
   * @param {import('node:child_process').ChildProcess} proc
   * @param {string} wsUrl
   * @param {string} profileDir
   * @param {string} browserType
   */
  constructor(proc, wsUrl, profileDir, browserType) {
    this.process = proc;
    this.wsUrl = wsUrl;
    this.profileDir = profileDir;
    this.browserType = browserType;
    /** @type {WebSocket | null} */
    this.ws = null;
    this.msgId = 1;
    this.callbacks = new Map();
    /** @type {string | null} */
    this.sessionId = null;
    /** @type {string | null} */
    this.targetId = null;
    this.currentUrl = 'about:blank';
    this.currentTitle = '';
  }

  async connect() {
    this.ws = new WebSocket(this.wsUrl);
    const ws = /** @type {WebSocket} */ (this.ws);
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('CDP_WS_TIMEOUT')), 5000);
      ws.onopen = () => {
        clearTimeout(t);
        resolve(true);
      };
      ws.onerror = (err) => {
        clearTimeout(t);
        reject(err);
      };
    });

    ws.onmessage = (e) => {
      let data;
      try {
        data = JSON.parse(e.data);
      } catch {
        return;
      }
      if (data.id && this.callbacks.has(data.id)) {
        const cb = this.callbacks.get(data.id);
        this.callbacks.delete(data.id);
        if (data.error) cb.reject(new Error(data.error.message || JSON.stringify(data.error)));
        else cb.resolve(data.result);
        return;
      }
      if (data.method === 'Fetch.requestPaused' && typeof this.handleFetchPaused === 'function') {
        this.handleFetchPaused(data.params).catch(() => {});
      }
    };

    // Create target page
    const target = await this.sendBrowser('Target.createTarget', { url: 'about:blank' });
    this.targetId = target.targetId;

    // Attach to target
    const attach = await this.sendBrowser('Target.attachToTarget', {
      targetId: this.targetId,
      flatten: true
    });
    this.sessionId = attach.sessionId;

    // Enable domains
    await this.sendPage('Page.enable');
    await this.sendPage('Runtime.enable');
    await this.sendPage('DOM.enable');
    await this.sendPage('Accessibility.enable');
  }

  /**
   * @param {string} method
   * @param {Record<string, unknown>} [params]
   */
  sendBrowser(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = this.msgId++;
      this.callbacks.set(id, { resolve, reject });
      const ws = /** @type {WebSocket} */ (this.ws);
      ws.send(JSON.stringify({ id, method, params }));
    });
  }

  /**
   * @param {string} method
   * @param {Record<string, unknown>} [params]
   */
  sendPage(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = this.msgId++;
      this.callbacks.set(id, { resolve, reject });
      const ws = /** @type {WebSocket} */ (this.ws);
      ws.send(JSON.stringify({ id, sessionId: this.sessionId, method, params }));
    });
  }

  /**
   * @param {string} expression
   */
  async evaluate(expression) {
    const res = await this.sendPage('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise: true
    });
    return res?.result?.value;
  }

  /**
   * @param {{allowPrivateNetwork?: boolean}} [context]
   */
  async enableFetchInterception(context = {}) {
    this.egressContext = {
      allowPrivateNetwork: context?.allowPrivateNetwork === true
    };
    if (this.fetchInterception) return;
    const session = this;
    /**
     * @param {{requestId: string, request?: {url?: string}}} params
     */
    this.handleFetchPaused = async (params) => {
      const url = params?.request?.url || '';
      let verdict;
      try {
        verdict = await validateEgressUrl(url, {
          allowPrivateNetwork: Boolean(session.egressContext?.allowPrivateNetwork),
          resolve: resolveAgentAddresses
        });
      } catch {
        verdict = { ok: false, error: 'URL_VALIDATION_FAILED' };
      }
      try {
        if (verdict.ok) {
          await session.sendPage('Fetch.continueRequest', { requestId: params.requestId });
        } else {
          await session.sendPage('Fetch.failRequest', {
            requestId: params.requestId,
            errorReason: 'BlockedByClient'
          });
        }
      } catch {}
    };
    await this.sendPage('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
    this.fetchInterception = true;
  }
}

// --- Browser Launcher ---
/**
 * @param {object} [options]
 * @param {string} [options.browser]
 * @param {boolean} [options.headless]
 */
async function getOrCreateBrowser({ browser = 'auto', headless = true } = {}) {
  resetIdleTimeout();

  if (activeBrowser && activeBrowser.ws && activeBrowser.ws.readyState === 1) {
    return activeBrowser;
  }

  const sys = findSystemBrowser(browser);
  if (!sys) {
    throw new Error(
      'NO_SUPPORTED_BROWSER_FOUND: Microsoft Edge or Google Chrome is required on this host.'
    );
  }

  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hhc_browser_'));
  const flags = [
    '--remote-debugging-port=0',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-background-networking',
    '--disable-background-timer-throttling',
    '--disable-client-side-phishing-detection',
    '--disable-default-apps',
    '--disable-dev-shm-usage',
    '--disable-extensions',
    '--disable-sync',
    '--disable-translate',
    '--metrics-recording-only',
    '--safebrowsing-disable-auto-update',
    `--user-data-dir=${profileDir}`
  ];

  if (headless) {
    flags.push('--headless=new');
  }

  flags.push('about:blank');

  const proc = spawn(sys.path, flags, {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false
  });

  let wsUrl = null;
  proc.stderr.on('data', (chunk) => {
    const text = chunk.toString();
    const match = text.match(/DevTools listening on (ws:\/\/[^\s]+)/);
    if (match) wsUrl = match[1];
  });

  for (let i = 0; i < 60; i++) {
    if (wsUrl) break;
    await new Promise((r) => setTimeout(r, 100));
  }

  if (!wsUrl) {
    try {
      proc.kill('SIGKILL');
    } catch {}
    try {
      fs.rmSync(profileDir, { recursive: true, force: true });
    } catch {}
    throw new Error(
      'BROWSER_CDP_INIT_TIMEOUT: Failed to capture Chrome DevTools Protocol endpoint.'
    );
  }

  const session = new CdpSession(proc, wsUrl, profileDir, sys.type);
  await session.connect();
  activeBrowser = session;
  return session;
}

// --- Format Accessibility Tree for AI Models ---
/**
 * @param {Array<Record<string, any>>} nodes
 */
function formatAXTree(nodes) {
  if (!Array.isArray(nodes) || nodes.length === 0) return '(empty accessibility tree)';

  const nodeMap = new Map();
  for (const n of nodes) {
    nodeMap.set(n.nodeId, n);
  }

  /** @type {Array<string>} */
  const lines = [];
  /**
   * @param {Record<string, any>} node
   * @param {number} [depth]
   */
  function renderNode(node, depth = 0) {
    const role = node.role?.value || 'node';
    const name = node.name?.value?.trim() || '';
    const value = node.value?.value?.trim() || '';
    const description = node.description?.value?.trim() || '';

    // Filter out purely decorative or invisible wrapper nodes to keep tokens minimal
    const isIgnored = node.ignored || role === 'none' || role === 'generic';
    const hasContent = name || value || description;

    let nextDepth = depth;
    if (!isIgnored || hasContent) {
      const indent = '  '.repeat(depth);
      let desc = `[${role}]`;
      if (name) desc += ` "${name}"`;
      if (value && value !== name) desc += ` val="${value}"`;
      if (description) desc += ` (${description})`;
      lines.push(`${indent}- ${desc}`);
      nextDepth = depth + 1;
    }

    if (Array.isArray(node.childIds)) {
      for (const cid of node.childIds) {
        const child = nodeMap.get(cid);
        if (child) renderNode(child, nextDepth);
      }
    }
  }

  // Find roots (nodes not referenced as childIds)
  const childSet = new Set();
  for (const n of nodes) {
    if (Array.isArray(n.childIds)) {
      for (const cid of n.childIds) childSet.add(cid);
    }
  }

  for (const n of nodes) {
    if (!childSet.has(n.nodeId)) {
      renderNode(n, 0);
    }
  }

  return lines.slice(0, 150).join('\n');
}

// --- Structured MCP Handlers ---

/**
 * @param {unknown} job
 */
export async function browserNavigateJob(job) {
  const started = Date.now();
  const jobRecord =
    /** @type {{request_payload?: unknown, payload?: unknown, agent_policy_capabilities?: unknown}} */ (
      job || {}
    );
  const p = /** @type {Record<string, unknown>} */ (
    jobRecord.request_payload || jobRecord.payload || {}
  );
  const url = String(p.url || '').trim();
  if (!url) {
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      error: 'URL_REQUIRED',
      duration_ms: 0,
      result_payload: {}
    };
  }

  try {
    const policyCaps = /** @type {Record<string, unknown>} */ (
      jobRecord.agent_policy_capabilities || {}
    );
    const allowPrivateNetwork = policyCaps.browser_private_network === true;
    const preflight = await validateEgressUrl(url, {
      allowPrivateNetwork,
      resolve: resolveAgentAddresses
    }).catch(() => ({ ok: false, error: 'URL_VALIDATION_FAILED' }));
    if (!preflight.ok) {
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: preflight.error || 'URL_EGRESS_DENIED',
        duration_ms: Date.now() - started,
        result_payload: { url: auditProjectionUrl(url) }
      };
    }
    const session = await getOrCreateBrowser({
      browser: typeof p.browser === 'string' && p.browser ? p.browser : 'auto',
      headless: p.headless !== false
    });

    await session.enableFetchInterception({ allowPrivateNetwork });
    await session.sendPage('Page.navigate', { url });

    // Wait up to 5s for page to settle
    await new Promise((r) => setTimeout(r, 1500));

    const [title, currentUrl] = await Promise.all([
      session.evaluate('document.title || ""'),
      session.evaluate('window.location.href || ""')
    ]);

    const finalCheck = await validateEgressUrl(currentUrl || url, {
      allowPrivateNetwork,
      resolve: resolveAgentAddresses
    }).catch(() => ({ ok: false, error: 'URL_VALIDATION_FAILED' }));
    if (!finalCheck.ok) {
      try {
        await session.sendPage('Page.navigate', { url: 'about:blank' });
      } catch {}
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: 'BROWSER_REDIRECT_DENIED',
        duration_ms: Date.now() - started,
        result_payload: { url: auditProjectionUrl(currentUrl || url) }
      };
    }

    session.currentTitle = title;
    session.currentUrl = currentUrl;

    return {
      status: 'completed',
      exit_code: 0,
      stdout: `Navigated to ${currentUrl} ("${title}")`,
      stderr: '',
      error: null,
      duration_ms: Date.now() - started,
      result_payload: {
        browser: session.browserType,
        url: currentUrl,
        title,
        status: 200,
        headless: p.headless !== false
      }
    };
  } catch (err) {
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      error:
        err && typeof err === 'object' && 'message' in err && err.message
          ? err.message
          : 'BROWSER_NAVIGATION_FAILED',
      duration_ms: Date.now() - started,
      result_payload: {}
    };
  }
}

/**
 * @param {unknown} job
 */
export async function browserInteractJob(job) {
  const started = Date.now();
  const jobRecord =
    /** @type {{request_payload?: unknown, payload?: unknown, agent_policy_capabilities?: unknown}} */ (
      job || {}
    );
  const p = /** @type {Record<string, unknown>} */ (
    jobRecord.request_payload || jobRecord.payload || {}
  );
  const action = String(p.action || 'click').toLowerCase();
  const selector = String(p.selector || '').trim();
  const value = String(p.value || '');

  if (action === 'evaluate') {
    const policyCaps = /** @type {Record<string, unknown>} */ (
      jobRecord.agent_policy_capabilities || {}
    );
    if (policyCaps.browser_script_exec !== true) {
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        error: 'BROWSER_SCRIPT_EXEC_DENIED',
        duration_ms: Date.now() - started,
        result_payload: {}
      };
    }
  }

  if (!activeBrowser || !activeBrowser.ws || activeBrowser.ws.readyState !== 1) {
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      error: 'BROWSER_NOT_OPEN: Call browser_navigate first.',
      duration_ms: 0,
      result_payload: {}
    };
  }

  resetIdleTimeout();

  try {
    let result = null;
    if (action === 'click') {
      if (!selector) throw new Error('SELECTOR_REQUIRED_FOR_CLICK');
      result = await activeBrowser.evaluate(`(() => {
        const el = document.querySelector(${JSON.stringify(selector)});
        if (!el) return { success: false, error: 'ELEMENT_NOT_FOUND' };
        el.scrollIntoView({ behavior: 'instant', block: 'center' });
        el.focus();
        el.click();
        return { success: true, tag: el.tagName, id: el.id, className: el.className };
      })()`);
    } else if (action === 'type' || action === 'fill') {
      if (!selector) throw new Error('SELECTOR_REQUIRED_FOR_TYPE');
      result = await activeBrowser.evaluate(`(() => {
        const el = document.querySelector(${JSON.stringify(selector)});
        if (!el) return { success: false, error: 'ELEMENT_NOT_FOUND' };
        el.scrollIntoView({ behavior: 'instant', block: 'center' });
        el.focus();
        el.value = ${JSON.stringify(value)};
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        return { success: true, value: el.value };
      })()`);
    } else if (action === 'press') {
      const key = value || 'Enter';
      result = await activeBrowser.evaluate(`(() => {
        const active = document.activeElement || document.body;
        active.dispatchEvent(new KeyboardEvent('keydown', { key: ${JSON.stringify(key)}, bubbles: true }));
        active.dispatchEvent(new KeyboardEvent('keyup', { key: ${JSON.stringify(key)}, bubbles: true }));
        return { success: true, key: ${JSON.stringify(key)} };
      })()`);
    } else if (action === 'scroll') {
      const dir = (value || selector || 'down').toLowerCase();
      result = await activeBrowser.evaluate(`(() => {
        if (${JSON.stringify(dir)} === 'up') window.scrollBy(0, -window.innerHeight * 0.7);
        else window.scrollBy(0, window.innerHeight * 0.7);
        return { success: true, scrollY: window.scrollY };
      })()`);
    } else if (action === 'wait_for') {
      if (!selector) throw new Error('SELECTOR_REQUIRED_FOR_WAIT');
      const maxTries = 30;
      let found = false;
      for (let i = 0; i < maxTries; i++) {
        const res = await activeBrowser.evaluate(
          `Boolean(document.querySelector(${JSON.stringify(selector)}))`
        );
        if (res) {
          found = true;
          break;
        }
        await new Promise((r) => setTimeout(r, 200));
      }
      result = { success: found, selector };
    } else if (action === 'evaluate') {
      const expr = value || selector;
      if (!expr) throw new Error('EXPRESSION_REQUIRED_FOR_EVALUATE');
      const val = await activeBrowser.evaluate(expr);
      result = { success: true, value: val };
    } else {
      throw new Error(`UNSUPPORTED_INTERACT_ACTION: ${action}`);
    }

    if (result && result.success === false) {
      throw new Error(result.error || 'INTERACTION_FAILED');
    }

    return {
      status: 'completed',
      exit_code: 0,
      stdout: `Action '${action}' executed successfully on ${selector || 'page'}`,
      stderr: '',
      error: null,
      duration_ms: Date.now() - started,
      result_payload: { action, selector, result }
    };
  } catch (err) {
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      error:
        err && typeof err === 'object' && 'message' in err && err.message
          ? err.message
          : 'BROWSER_INTERACT_FAILED',
      duration_ms: Date.now() - started,
      result_payload: {}
    };
  }
}

/**
 * @param {unknown} job
 */
export async function browserSnapshotJob(job) {
  const started = Date.now();
  const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  const p = /** @type {Record<string, unknown>} */ (
    jobRecord.request_payload || jobRecord.payload || {}
  );
  const type = String(p.type || 'accessibility').toLowerCase();
  const maxBytes = Math.max(1024, Math.min(262144, Number(p.max_bytes || 65536)));

  if (!activeBrowser || !activeBrowser.ws || activeBrowser.ws.readyState !== 1) {
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      error: 'BROWSER_NOT_OPEN: Call browser_navigate first.',
      duration_ms: 0,
      result_payload: {}
    };
  }

  resetIdleTimeout();

  try {
    if (type === 'screenshot') {
      const shot = await activeBrowser.sendPage('Page.captureScreenshot', { format: 'png' });
      return {
        status: 'completed',
        exit_code: 0,
        stdout: `Captured screenshot (${shot.data.length} chars base64)`,
        stderr: '',
        error: null,
        duration_ms: Date.now() - started,
        result_payload: {
          type: 'screenshot',
          format: 'png',
          base64: shot.data
        }
      };
    }

    if (type === 'html') {
      const html = await activeBrowser.evaluate('document.documentElement.outerHTML || ""');
      const truncated = html.length > maxBytes;
      const content = html.slice(0, maxBytes);
      return {
        status: 'completed',
        exit_code: 0,
        stdout: content,
        stderr: '',
        error: null,
        duration_ms: Date.now() - started,
        result_payload: {
          type: 'html',
          bytes: content.length,
          truncated,
          content
        }
      };
    }

    if (type === 'text') {
      const text = await activeBrowser.evaluate('document.body.innerText || ""');
      const truncated = text.length > maxBytes;
      const content = text.slice(0, maxBytes);
      return {
        status: 'completed',
        exit_code: 0,
        stdout: content,
        stderr: '',
        error: null,
        duration_ms: Date.now() - started,
        result_payload: {
          type: 'text',
          bytes: content.length,
          truncated,
          content
        }
      };
    }

    // Default: 'accessibility' (AXTree)
    const ax = await activeBrowser.sendPage('Accessibility.getFullAXTree');
    const axTreeText = formatAXTree(ax?.nodes || []);
    const [title, url] = await Promise.all([
      activeBrowser.evaluate('document.title || ""'),
      activeBrowser.evaluate('window.location.href || ""')
    ]);

    return {
      status: 'completed',
      exit_code: 0,
      stdout: `Page: "${title}" (${url})\n\nAccessibility Tree:\n${axTreeText}`,
      stderr: '',
      error: null,
      duration_ms: Date.now() - started,
      result_payload: {
        type: 'accessibility',
        url,
        title,
        nodes_count: ax?.nodes?.length || 0,
        tree: axTreeText
      }
    };
  } catch (err) {
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      error:
        err && typeof err === 'object' && 'message' in err && err.message
          ? err.message
          : 'BROWSER_SNAPSHOT_FAILED',
      duration_ms: Date.now() - started,
      result_payload: {}
    };
  }
}
