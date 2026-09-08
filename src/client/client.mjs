import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { connectWebSocket } from './ws-client.mjs';
import { makeStructuredHandlers, extendStructuredHandlers } from '../structured-ops/structured-ops.mjs';
import { makeMutationHandlers } from '../filesystem/mutation-ops.mjs';
import { makeGuiLaunchHandler } from '../../gui-broker/gui-launch.mjs';
import {
  makeUpdateHandler,
  activatePreparedUpdate,
  markUpdateHealthy,
  updaterPolicy
} from '../updater/updater.mjs';
import { hhcLayout } from './hhc-paths.mjs';
import {
  HOST_POLICY_FEATURE,
  BROWSER_POLICY_FEATURE,
  BROWSER_POLICY_V2_FEATURE,
  WORKSPACE_ROOTS_FEATURE,
  authorizeBoundJob,
  policyBindingFromJob,
  policyBindingRecord,
  validatePolicy,
  verifyPolicySignature
} from '../policy/host-policy.mjs';
import { createDeviceProof, deviceAuthHeaders, loadDeviceKey } from './device-proof.mjs';
import {
  clearRetirementCandidate,
  normalizeRetirementCandidate,
  observeRetirementResponse
} from '../lifecycle/lifecycle.mjs';
import { makePrivilegedHelperClientHandler } from '../../privileged-helper/privileged-helper-client.mjs';
import { browserAuditSummary } from '../browser/browser-manager.mjs';
import { linuxPrivilegedHelperReadiness } from '../../privileged-helper/privileged-helper-linux-readiness.mjs';
import {
  browserNavigateJob,
  browserInteractJob,
  browserSnapshotJob,
  browserCreateJob,
  browserCloseJob,
  browserFindJob,
  browserTabsJob,
  browserScreenshotJob,
  browserConsoleJob,
  browserNetworkJob,
  browserUploadJob,
  browserHealth
} from '../browser/browser-adapter.mjs';
import { makeProcessHandlers, sweepOrphanedSessions } from '../process/process-sessions.mjs';
import { makeServiceHandlers } from '../services/service-ops.mjs';
import { makeLogFollowHandlers } from '../logs/log-ops.mjs';
import { executeShellJob, normalizedJobPayload } from '../shell/shell.mjs';

const VERSION = '0.4.56';
const layout = hhcLayout();
const cfg = {
  serverUrl: (process.env.HHC_SERVER_URL || 'https://mcp.hhc.zone').replace(/\/$/, ''),
  clientId: process.env.HHC_CLIENT_ID || os.hostname(),
  clientName: process.env.HHC_CLIENT_NAME || os.hostname(),
  clientToken: process.env.HHC_CLIENT_TOKEN || '',
  deviceKeyFile: process.env.HHC_DEVICE_KEY_FILE || layout.deviceKey,
  heartbeatSeconds: Math.max(5, Number(process.env.HHC_HEARTBEAT_SECONDS || 15)),
  retrySeconds: Math.max(2, Number(process.env.HHC_RETRY_SECONDS || 10)),
  jobPollSeconds: Math.max(1, Number(process.env.HHC_JOB_POLL_SECONDS || 2)),
  remoteExecEnabled:
    String(process.env.HHC_REMOTE_EXEC_ENABLED || 'false').toLowerCase() === 'true',
  auditFile: process.env.HHC_AUDIT_FILE || '',
  serverLogFile: process.env.HHC_SERVER_LOG_FILE || layout.serverLog,
  tunnelLogFile: process.env.HHC_TUNNEL_LOG_FILE || layout.tunnelLog,
  stateFile: process.env.HHC_STATE_FILE || layout.stateFile,
  clientLog: process.env.HHC_CLIENT_LOG || layout.clientLog,
  bootstrapBytes: Math.max(4096, Number(process.env.HHC_BOOTSTRAP_BYTES || 65536)),
  maxStdoutBytes: Math.max(4096, Number(process.env.HHC_MAX_STDOUT_BYTES || 1048576)),
  maxStderrBytes: Math.max(4096, Number(process.env.HHC_MAX_STDERR_BYTES || 1048576)),
  maxTimeoutSeconds: Math.max(1, Number(process.env.HHC_MAX_TIMEOUT_SECONDS || 3600)),
  sessionEnabled: String(process.env.HHC_SESSION_ENABLED || 'true').toLowerCase() !== 'false',
  protocolVersion: process.env.HHC_PROTOCOL_VERSION || '1.0.0',
  localAuditFile: process.env.HHC_LOCAL_AUDIT_FILE || layout.auditLog,
  readRoots: String(process.env.HHC_FILE_READ_ROOTS || layout.root)
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean),
  serviceStatusUnits: String(
    process.env.HHC_SERVICE_STATUS_UNITS || 'hhc-client.service,hhc-mcp.service'
  )
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
};
const LOG_SOURCES = /** @type {Record<string, string>} */ (
  Object.freeze({
    client: cfg.clientLog,
    'mcp-server': cfg.serverLogFile,
    'mcp-tunnel': cfg.tunnelLogFile
  })
);
const SESSION_BACKOFF = [0, 1, 5, 15, 30, 60];
// Pong window after each ping we send: a healthy hub answers in
// milliseconds, so 10s is generous. Any inbound frame also counts as
// liveness (superset of pong-only tracking).
export const PONG_TIMEOUT_MS = 10000;

/**
 * Liveness watchdog for one session (SYN-TRANS-001). Call `poke()` on every
 * inbound frame and `sentPing()` after each ping we emit. When `sentPing()`
 * is not followed by any inbound traffic within the window, `onTimeout`
 * fires once so the caller can destroy the (likely half-open) socket and
 * reconnect. All timing injectable for tests.
 * @param {{windowMs?: number, now?: () => number, setTimer?: typeof setTimeout, clearTimer?: typeof clearTimeout, onTimeout?: () => void}} [options]
 */
export function attachPongWatchdog({
  windowMs = PONG_TIMEOUT_MS,
  now = () => Date.now(),
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  onTimeout = () => {}
} = {}) {
  /** @type {ReturnType<typeof setTimeout> | null} */
  let timer = null;
  let fired = false;
  let lastActivityMs = now();
  const cancel = () => {
    if (timer) {
      clearTimer(timer);
      timer = null;
    }
  };
  return {
    poke() {
      if (fired) return;
      lastActivityMs = now();
      cancel();
    },
    sentPing() {
      if (fired) return;
      lastActivityMs = now();
      cancel();
      timer = setTimer(() => {
        timer = null;
        if (fired) return;
        fired = true;
        onTimeout();
      }, windowMs);
    },
    cancel,
    get armed() {
      return timer !== null;
    },
    get lastActivityMs() {
      return lastActivityMs;
    }
  };
}

/** @param {number} baseSeconds */
export function reconnectDelayMs(baseSeconds) {
  return (
    Math.max(0, Math.floor(Number(baseSeconds) || 0)) * 1000 + Math.floor(Math.random() * 1000)
  );
}
/**
 * @typedef {Object} AgentPolicy
 * @property {string} contract_version
 * @property {number} revision
 * @property {string} digest
 * @property {Record<string, boolean>} capabilities
 * @property {{allowed_read_roots?: Array<string>, allowed_write_roots?: Array<string>}} [roots]
 * @typedef {Object} AgentStateJob
 * @property {string} [status]
 * @property {string} [claimed_at]
 * @property {string} [tool]
 * @property {unknown} [policy_binding]
 * @property {string} [started_at]
 * @property {string} [finished_local_at]
 * @property {string} [result_sent_at]
 * @property {number} [duration_ms]
 * @typedef {Object} AgentState
 * @property {Record<string, number>} offsets
 * @property {boolean} registered
 * @property {string|null} registered_client_id
 * @property {Record<string, AgentStateJob>} jobs
 * @property {Record<string, unknown>} pendingResults
 * @property {unknown} [retirement]
 * @typedef {Object} AgentSessionSocket
 * Wire callbacks receive untyped JSON (same contract as Express req.body).
 * @property {(msg: unknown) => unknown} sendJson
 * @property {(code?: number, reason?: string) => unknown} close
 * @property {(reason?: string) => unknown} [destroy]
 * @property {(event: string, listener: (msg: any) => unknown) => unknown} on
 * @property {(event: string, listener: (msg: any) => unknown) => unknown} once
 * @property {(event: string, listener: (msg: any) => unknown) => unknown} removeListener
 * @typedef {Object} SessionMessage
 * @property {unknown} [id]
 * @property {unknown} [type]
 * @property {unknown} [op]
 * @property {unknown} [kind]
 * @property {unknown} [data]
 * @property {unknown} [fatal]
 * @property {unknown} [code]
 * @property {unknown} [message]
 * @property {unknown} [payload]
 * @property {unknown} [policy_contract_version]
 * @property {unknown} [policy_revision]
 * @property {unknown} [policy_digest]
 * @property {unknown} [required_capabilities]
 * @property {unknown} [admission_origin]
 */
/** @type {object|null} */
let liveSession = null;
/**
 * @type {Record<string, (job: Record<string, unknown>, options?: Record<string, unknown>) => Promise<Record<string, unknown>>>|null} */
let handlerRegistry = null;
let auditWrites = 0;
/** @type {AgentPolicy|null} */
let currentPolicy = null;
let retired = false;
function configuredTransportScheme() {
  try {
    return new URL(cfg.serverUrl).protocol === 'https:' ? 'https' : 'http';
  } catch {
    return 'http';
  }
}
const transportProtected = () => configuredTransportScheme() === 'https';

/**
 * @param {number} ms
 */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * @param {object} [options]
 * @param {string} [options.platform]
 * @param {(file: string) => boolean} [options.exists]
 * @param {(file: string) => string} [options.read]
 */
export function detectLegacyArtifacts({
  platform = process.platform,
  exists = fsSync.existsSync,
  read = /** @type {(file: string) => string} */ ((file) => fsSync.readFileSync(file, 'utf8'))
} = {}) {
  const found = [];
  if (platform === 'linux' || platform === 'darwin') {
    const retiredRoot = '/' + ['work', 'space'].join('');
    for (const [code, target] of [
      ['legacy_client_tree', retiredRoot + '/hhc-client'],
      ['legacy_mcp_tree', retiredRoot + '/hhc-mcp'],
      ['legacy_update_cache', retiredRoot + '/.hhc-client-updates'],
      ['legacy_usr_local', '/usr/local/hhc'],
      ['legacy_etc_config', '/etc/hhc']
    ]) {
      try {
        if (exists(target)) found.push(code);
      } catch {}
    }
    if (platform === 'linux') {
      const unit = '/etc/systemd/system/hhc-mcp.service',
        clientUnit = '/etc/systemd/system/hhc-client.service';
      try {
        if (exists(unit) && String(read(unit)).includes(retiredRoot + '/hhc-mcp'))
          found.push('obsolete_systemd_unit');
      } catch {}
      try {
        if (exists(clientUnit) && /^Environment=HHC_ROOT=/m.test(String(read(clientUnit))))
          found.push('obsolete_root_env');
      } catch {}
    } else if (platform === 'darwin') {
      const plist = '/Library/LaunchDaemons/com.hhc.client.plist';
      try {
        if (exists(plist) && /<key>HHC_ROOT<\/key>/.test(String(read(plist))))
          found.push('obsolete_root_env');
      } catch {}
    }
  } else if (platform === 'win32') {
    const pf = String(process.env.ProgramFiles || 'C:\\Program Files'),
      pd = String(process.env.ProgramData || 'C:\\ProgramData');
    for (const [code, target] of [
      ['legacy_program_files', pf + '\\HHC'],
      ['legacy_program_data', pd + '\\HHC']
    ]) {
      try {
        if (exists(target)) found.push(code);
      } catch {}
    }
  }
  return [...new Set(found)].sort();
}
function filesystemLayoutMetadata() {
  return {
    root: layout.root,
    app: layout.app,
    config: layout.config,
    data: layout.data,
    logs: layout.logs,
    legacy_artifacts: detectLegacyArtifacts()
  };
}

/**
 * @param {string} level @param {string} message @param {Record<string, unknown>} [extra]
 */
async function log(level, message, extra = {}) {
  const safeExtra = { ...extra };
  delete safeExtra.authorization;
  delete safeExtra.token;
  const record = { ts: new Date().toISOString(), level, message, ...safeExtra };
  const line = `${JSON.stringify(record)}\n`;
  try {
    await fs.mkdir(path.dirname(cfg.clientLog), { recursive: true });
    await fs.appendFile(cfg.clientLog, line, { mode: 0o640 });
  } catch {}
  if (level === 'error') console.error(line.trim());
  else console.log(line.trim());
}

/**
 * @param {string} op @param {Record<string, unknown>} [payload] @param {Record<string, unknown>} [result] @returns {Record<string, unknown>}
 */
export function localAuditPayload(op, payload = {}, result = {}) {
  if (op === 'file_write') {
    const rp =
      result?.result_payload && typeof result.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (result.result_payload)
        : {};
    return {
      path:
        typeof rp.path === 'string'
          ? rp.path
          : typeof payload.path === 'string'
            ? payload.path
            : null,
      mode: typeof payload.mode === 'string' ? payload.mode : null,
      encoding: typeof payload.encoding === 'string' ? payload.encoding : 'utf8',
      create_parents: payload.create_parents === true,
      content_bytes:
        typeof payload.content === 'string' ? Buffer.byteLength(payload.content, 'utf8') : null,
      expected_sha256: typeof payload.expected_sha256 === 'string' ? payload.expected_sha256 : null,
      previous_sha256: typeof rp.previous_sha256 === 'string' ? rp.previous_sha256 : null,
      result_sha256: typeof rp.sha256 === 'string' ? rp.sha256 : null
    };
  }
  if (op === 'directory_create') {
    const rp =
      result?.result_payload && typeof result.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (result.result_payload)
        : {};
    return {
      path:
        typeof rp.path === 'string'
          ? rp.path
          : typeof payload.path === 'string'
            ? payload.path
            : null,
      parents: payload.parents === true
    };
  }
  if (op === 'file_move') {
    const rp =
      result?.result_payload && typeof result.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (result.result_payload)
        : {};
    return {
      source:
        typeof rp.source === 'string'
          ? rp.source
          : typeof payload.source === 'string'
            ? payload.source
            : null,
      destination:
        typeof rp.destination === 'string'
          ? rp.destination
          : typeof payload.destination === 'string'
            ? payload.destination
            : null,
      overwrite: payload.overwrite === true
    };
  }
  if (op === 'file_delete') {
    const rp =
      result?.result_payload && typeof result.result_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (result.result_payload)
        : {};
    return {
      path:
        typeof rp.path === 'string'
          ? rp.path
          : typeof payload.path === 'string'
            ? payload.path
            : null,
      recursive: payload.recursive === true
    };
  }
  if (typeof op === 'string' && op.startsWith('browser_')) {
    return browserAuditSummary(op, payload, result);
  }
  return payload;
}

/**
 * @param {string} op @param {unknown} [payload] @param {unknown} [result]
 */
async function localAudit(op, payload, result) {
  const resultRec =
    result && typeof result === 'object' ? /** @type {Record<string, unknown>} */ (result) : null;
  try {
    const entry = {
      ts: new Date().toISOString(),
      op,
      payload,
      ok: resultRec?.status === 'completed',
      status: resultRec?.status || null,
      duration_ms: resultRec?.duration_ms ?? null,
      exit_code: resultRec?.exit_code ?? null,
      error: resultRec?.error || null
    };
    await fs.mkdir(path.dirname(cfg.localAuditFile), { recursive: true });
    await fs.appendFile(cfg.localAuditFile, JSON.stringify(entry) + '\n', { mode: 0o640 });
    auditWrites++;
    if (auditWrites % 100 === 0) {
      const text = await fs.readFile(cfg.localAuditFile, 'utf8'),
        rows = text.split('\n').filter(Boolean);
      if (rows.length > 5500) {
        const tmp = cfg.localAuditFile + '.tmp';
        await fs.writeFile(tmp, rows.slice(-5000).join('\n') + '\n', { mode: 0o640 });
        await fs.rename(tmp, cfg.localAuditFile);
      }
    }
  } catch {}
}

/**
 * @param {unknown} result @returns {Record<string, unknown>}
 */
export function boundSessionResult(result) {
  const resultRec = /** @type {Record<string, unknown>} */ (result);
  const out = /** @type {Record<string, unknown>} */ (structuredClone(result)),
    original = Buffer.byteLength(JSON.stringify(out));
  if (original <= 128 * 1024) return out;
  let budget = 108 * 1024;
  for (const key of ['stdout', 'stderr', 'content']) {
    if (typeof out[key] !== 'string') continue;
    const raw = Buffer.from(out[key]);
    if (raw.length <= 8192) continue;
    const keep = Math.min(raw.length, Math.max(4096, Math.floor(budget / 2))),
      head = Math.floor(keep * 0.6),
      tail = keep - head;
    out[key] =
      raw.subarray(0, head).toString('utf8') +
      '\n…[hhc: wire response truncated]…\n' +
      raw.subarray(raw.length - tail).toString('utf8');
    out[key + '_truncated'] = true;
    budget = Math.max(8192, budget - Buffer.byteLength(String(out[key] ?? '')));
  }
  out.result_payload = {
    .../** @type {Record<string, unknown>} */ (out.result_payload || {}),
    _truncation: {
      response_truncated: true,
      original_bytes: original,
      delivered_bytes: Buffer.byteLength(JSON.stringify(out)),
      continuation_available: false,
      execution_status: resultRec.status
    }
  };
  return out;
}

/**
 * @returns {AgentState}
 */
function freshState() {
  return {
    offsets: /** @type {Record<string, number>} */ ({}),
    registered: false,
    registered_client_id: null,
    jobs: /** @type {Record<string, AgentStateJob>} */ ({}),
    pendingResults: /** @type {Record<string, unknown>} */ ({}),
    retirement: normalizeRetirementCandidate()
  };
}

/**
 * @param {AgentState|null|undefined} state @param {string} clientId
 */
export function registrationStateForClient(state, clientId) {
  const registeredClientId =
    typeof state?.registered_client_id === 'string' ? state.registered_client_id : null;
  const registered = Boolean(state?.registered) && registeredClientId === clientId;
  return { registered, registered_client_id: registered ? registeredClientId : null };
}

/**
 * @returns {Promise<AgentState>}
 */
async function readState() {
  try {
    const state = JSON.parse(await fs.readFile(cfg.stateFile, 'utf8'));
    state.offsets ||= {};
    state.jobs ||= {};
    state.pendingResults ||= {};
    state.retirement = normalizeRetirementCandidate(state.retirement);
    Object.assign(state, registrationStateForClient(state, cfg.clientId));
    return state;
  } catch {
    return freshState();
  }
}

let stateWriteChain = Promise.resolve();
/**
 * @param {AgentState} state
 */
async function writeState(state) {
  const persist = async () => {
    await fs.mkdir(path.dirname(cfg.stateFile), { recursive: true });
    const tmp = `${cfg.stateFile}.tmp`;
    await fs.writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o640 });
    await fs.rename(tmp, cfg.stateFile);
  };
  stateWriteChain = stateWriteChain.then(persist, persist);
  return stateWriteChain;
}

/**
 * @param {AgentState} state
 */
async function resetRetirementEvidence(state) {
  const next = clearRetirementCandidate(state.retirement);
  if (!next.changed) return;
  state.retirement = next.state;
  await writeState(state);
}

/**
 * @param {AgentState} state @param {unknown} error
 */
async function observeRetirementFailure(state, error) {
  const next = observeRetirementResponse(state.retirement, error, { serverUrl: cfg.serverUrl });
  if (next.changed) {
    state.retirement = next.state;
    await writeState(state);
  }
  if (!next.retire) return false;
  const marker = {
    client_id: cfg.clientId,
    reason: 'CLIENT_NOT_FOUND',
    confirmed_at: new Date().toISOString(),
    confirmations: next.state.consecutive_not_found,
    server: cfg.serverUrl
  };
  await fs.writeFile(layout.retiredMarker, `${JSON.stringify(marker, null, 2)}\n`, { mode: 0o640 });
  retired = true;
  await log('error', 'client_retired', {
    client_id: cfg.clientId,
    reason: marker.reason,
    confirmations: marker.confirmations
  });
  return true;
}

/** @type {Promise<import('node:crypto').KeyObject>|null} */
let deviceKeyPromise = null;
/** @returns {Promise<import('node:crypto').KeyObject>} */
const getDeviceKey = () =>
  deviceKeyPromise || (deviceKeyPromise = loadDeviceKey(cfg.deviceKeyFile));
/**
 * @param {string} method @param {string} absoluteUrl @param {{json?: boolean}} [options]
 */
async function authenticatedHeaders(method, absoluteUrl, { json = true } = {}) {
  if (!cfg.clientToken) throw new Error('CLIENT_TOKEN_REQUIRED');
  const privateKey = await getDeviceKey();
  /** @type {Record<string, string>} */
  const baseHeaders = {
    ...(json ? { 'content-type': 'application/json' } : {}),
    ...deviceAuthHeaders({
      privateKey,
      clientId: cfg.clientId,
      method,
      url: absoluteUrl,
      token: cfg.clientToken
    })
  };
  return baseHeaders;
}

/**
 * @param {string} method @param {string} urlPath @param {unknown} body @param {number} [timeoutMs]
 */
async function requestJson(method, urlPath, body, timeoutMs = 7000) {
  const absoluteUrl = `${cfg.serverUrl}${urlPath}`;
  /** @type {{method: string, headers: Record<string, string>, signal: AbortSignal, body?: string}} */
  const options = {
    method,
    headers: await authenticatedHeaders(method, absoluteUrl),
    signal: AbortSignal.timeout(timeoutMs)
  };
  if (body !== undefined) options.body = JSON.stringify(body);
  const response = await fetch(absoluteUrl, options);
  const text = await response.text();
  if (!response.ok) {
    const error = /** @type {Error & {status?: number, body?: string}} */ (
      new Error(`HTTP ${response.status}: ${text.slice(0, 500)}`)
    );
    error.status = response.status;
    error.body = text;
    throw error;
  }
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/**
 * @param {string} urlPath @param {unknown} body @param {number} [timeoutMs]
 */
const postJson = (urlPath, body, timeoutMs) => requestJson('POST', urlPath, body, timeoutMs);

/**
 * @param {unknown} policy @param {unknown} [sig] policy_sig sibling envelope
 * @returns {AgentPolicy}
 */
function applyCurrentPolicy(policy, sig = null) {
  if (!transportProtected()) {
    const error = /** @type {Error & {code?: string}} */ (
      new Error('HOST_POLICY_TRANSPORT_UNPROTECTED')
    );
    error.code = 'HOST_POLICY_TRANSPORT_UNPROTECTED';
    throw error;
  }
  // SYN-POL-001: authenticity is cryptographic, not transport-implied. The
  // HHC_ALLOW_INSECURE_POLICY escape is gone; a valid signature is required
  // on every ingest (welcome, re-hello, fetch). Legacy unsigned policies are
  // rejected — central sends policy_sig alongside policy since 0.7.2.
  const verified = verifyPolicySignature(policy, sig, cfg.clientId);
  if (!verified.ok) {
    const error = /** @type {Error & {code?: string}} */ (
      new Error(/** @type {string} */ (verified.error))
    );
    error.code = /** @type {string} */ (verified.error);
    throw error;
  }
  const checked = validatePolicy(policy, cfg.clientId);
  if (!checked.ok) {
    const error = /** @type {Error & {code?: string}} */ (new Error(checked.error));
    error.code = checked.error;
    throw error;
  }
  currentPolicy = /** @type {AgentPolicy} */ (checked.policy);
  return currentPolicy;
}

async function fetchCurrentPolicy() {
  try {
    const body = await requestJson(
      'GET',
      `/api/clients/${encodeURIComponent(cfg.clientId)}/policy`,
      undefined,
      7000
    );
    return applyCurrentPolicy(body?.policy, body?.policy_sig);
  } catch (error) {
    const errRec = error && typeof error === 'object' ? error : null;
    if (errRec && 'code' in errRec && errRec.code) throw error;
    let code = 'HOST_POLICY_NOT_READY';
    try {
      const errBody = errRec && 'body' in errRec ? errRec.body : undefined;
      const body = JSON.parse(typeof errBody === 'string' && errBody ? errBody : '{}');
      const bodyRec = body && typeof body === 'object' ? body : null;
      if (bodyRec && 'error' in bodyRec && bodyRec.error) code = String(bodyRec.error);
    } catch {}
    const wrapped = /** @type {Error & {code?: string}} */ (new Error(code));
    wrapped.code = code;
    throw wrapped;
  }
}

/**
 * @param {{error?: unknown, denied_capabilities?: unknown}|null|undefined} check @returns {Record<string, unknown>}
 */
function policyFailureResult(check) {
  return {
    status: 'failed',
    exit_code: null,
    stdout: '',
    stderr: '',
    duration_ms: 0,
    error: check?.error || 'HOST_POLICY_NOT_READY',
    result_payload: {
      policy_error: check?.error || 'HOST_POLICY_NOT_READY',
      ...(Array.isArray(check?.denied_capabilities)
        ? { denied_capabilities: [...check.denied_capabilities] }
        : {})
    }
  };
}

/**
 * @param {Record<string, unknown>} job
 */
async function ensureJobPolicy(job) {
  const binding = policyBindingFromJob(job);
  if (!binding.ok) return binding;
  if (!binding.bound) return { ok: true, bound: false };
  try {
    const policy = await fetchCurrentPolicy();
    return authorizeBoundJob(job, policy, { transportProtected: transportProtected() });
  } catch (error) {
    const policyErr = /** @type {Record<string, unknown>} */ (error);
    return { ok: false, error: policyErr?.code || 'HOST_POLICY_NOT_READY' };
  }
}

/**
 * @param {Record<string, unknown>} job @param {Record<string, unknown>} result
 */
async function auditPolicyFailure(job, result) {
  await localAudit(String(job?.tool || 'unknown'), { policy_enforced: true }, result);
}

function systemPayload() {
  return {
    id: cfg.clientId,
    client_id: cfg.clientId,
    name: cfg.clientName,
    hostname: os.hostname(),
    agent_version: VERSION,
    version: VERSION,
    os: `${os.type()} ${os.release()}`,
    platform: os.platform(),
    arch: os.arch(),
    status: 'online',
    metadata: {
      cpus: os.cpus()?.length || null,
      total_memory_bytes: os.totalmem(),
      remote_exec_enabled: cfg.remoteExecEnabled,
      log_sources: Object.keys(LOG_SOURCES),
      log_delivery: 'on_demand',
      update_policy: updaterPolicy(layout),
      filesystem_layout: filesystemLayoutMetadata(),
      transport: liveSession ? 'websocket' : 'http-poll',
      protocol_version: cfg.protocolVersion,
      capabilities: advertisedCapabilities(),
      // Browser-runtime telemetry for OTA pin decisions and bug reports.
      browser_runtime: { ...browserHealthCache }
    }
  };
}

async function register() {
  const result = await postJson('/api/clients/register', systemPayload());
  await log('info', 'registered', {
    server: cfg.serverUrl,
    client_id: cfg.clientId,
    version: VERSION
  });
  return result;
}

async function heartbeat() {
  const uptime_seconds = Math.floor(os.uptime()),
    loadavg = os.loadavg(),
    free_memory_bytes = os.freemem(),
    total_memory_bytes = os.totalmem();
  return postJson(`/api/clients/${encodeURIComponent(cfg.clientId)}/heartbeat`, {
    status: 'online',
    timestamp: new Date().toISOString(),
    hostname: os.hostname(),
    uptime_seconds,
    loadavg,
    free_memory_bytes,
    total_memory_bytes,
    agent_version: VERSION,
    platform: os.platform(),
    arch: os.arch(),
    metadata: {
      cpus: os.cpus()?.length || null,
      total_memory_bytes,
      uptime_seconds,
      loadavg,
      free_memory_bytes,
      remote_exec_enabled: cfg.remoteExecEnabled,
      log_sources: Object.keys(LOG_SOURCES),
      log_delivery: 'on_demand',
      transport: liveSession ? 'websocket' : 'http-poll',
      protocol_version: cfg.protocolVersion,
      capabilities: advertisedCapabilities(),
      filesystem_layout: filesystemLayoutMetadata()
    }
  });
}

/**
 * @param {string} file
 */
/**
 * @param {string} file
 * @returns {Promise<import('node:fs').Stats|null>}
 */
/**
 * @param {string} file
 */
async function statOrNull(file) {
  try {
    return await fs.stat(file);
  } catch {
    return null;
  }
}

/**
 * @param {string} file @param {unknown} offset @param {number} bootstrapBytes
 */
async function readNewCompleteLines(file, offset, bootstrapBytes) {
  const stat = await statOrNull(file);
  if (!stat) return { lines: [], nextOffset: typeof offset === 'number' ? offset : 0 };
  let start = typeof offset === 'number' && Number.isFinite(offset) ? offset : null;
  if (start === null) start = Math.max(0, stat.size - bootstrapBytes);
  if (stat.size < start) start = 0;
  if (stat.size === start) return { lines: [], nextOffset: start };
  const length = stat.size - start;
  const handle = await fs.open(file, 'r');
  try {
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, start);
    const text = buffer.subarray(0, bytesRead).toString('utf8');
    const lastNl = text.lastIndexOf('\n');
    if (lastNl < 0) return { lines: [], nextOffset: start };
    const complete = text.slice(0, lastNl);
    const lines = complete ? complete.split('\n').filter(Boolean) : [];
    return { lines, nextOffset: start + Buffer.byteLength(text.slice(0, lastNl + 1)) };
  } finally {
    await handle.close();
  }
}

/**
 * @param {string} line
 */
async function sendAuditLine(line) {
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    parsed = { raw: line };
  }
  const eventName = String(parsed.tool || parsed.event || parsed.action || 'audit');
  return postJson(`/api/clients/${encodeURIComponent(cfg.clientId)}/audit`, {
    event: eventName,
    payload: { source: 'hhc-mcp', ingested_at: new Date().toISOString(), ...parsed }
  });
}

/**
 * @param {AgentState} state @param {string} key @param {string} file @param {(line: string) => unknown} sender
 */
async function forwardFile(state, key, file, sender) {
  const currentOffset = Object.prototype.hasOwnProperty.call(state.offsets, key)
    ? state.offsets[key]
    : null;
  const { lines, nextOffset } = await readNewCompleteLines(file, currentOffset, cfg.bootstrapBytes);
  let deliveredOffset = currentOffset;
  if (currentOffset === null && lines.length === 0) deliveredOffset = nextOffset;
  if (lines.length > 0) {
    const stat = await fs.stat(file);
    const base =
      currentOffset === null
        ? Math.max(0, stat.size - cfg.bootstrapBytes)
        : stat.size < currentOffset
          ? 0
          : currentOffset;
    let cursor = base;
    for (const line of lines) {
      await sender(line);
      cursor += Buffer.byteLength(`${line}\n`);
      deliveredOffset = cursor;
      state.offsets[key] = deliveredOffset;
      await writeState(state);
    }
  } else {
    state.offsets[key] = deliveredOffset ?? nextOffset;
  }
  if (lines.length > 0 && deliveredOffset !== nextOffset) state.offsets[key] = nextOffset;
  await writeState(state);
  return lines.length;
}

/**
 * @param {AgentState} state
 */
async function forwardTelemetry(state) {
  const counts = { audit: 0 };
  if (cfg.auditFile) counts.audit = await forwardFile(state, 'audit', cfg.auditFile, sendAuditLine);
  return counts;
}

/**
 * @param {unknown} claimResponse @returns {Record<string, unknown>|null}
 */
function extractJob(claimResponse) {
  if (!claimResponse || typeof claimResponse !== 'object') return null;
  const rec = /** @type {Record<string, unknown>} */ (claimResponse);
  if (rec.job && typeof rec.job === 'object')
    return /** @type {Record<string, unknown>} */ (rec.job);
  if (Array.isArray(rec.jobs)) return /** @type {Record<string, unknown>} */ (rec.jobs[0]) || null;
  if (rec.id || rec.job_id) return rec;
  return null;
}

/**
 * @param {{id?: unknown, job_id?: unknown}|null|undefined} [job]
 */
function normalizedJobId(job) {
  return String(job?.id || job?.job_id || '');
}

/**


/**
 * @param {string} jobId
 */
async function postJobStart(jobId) {
  return postJson(
    `/api/clients/${encodeURIComponent(cfg.clientId)}/jobs/${encodeURIComponent(jobId)}/start`,
    {}
  );
}

/**
 * @param {string} jobId @param {unknown} result
 */
async function postJobResult(jobId, result) {
  return postJson(
    `/api/clients/${encodeURIComponent(cfg.clientId)}/jobs/${encodeURIComponent(jobId)}/result`,
    result,
    15000
  );
}

/**


/**
 * @param {string} file @param {number} requestedLines @param {string} [contains]
 */
/**
 * @param {string} file @param {number} requestedLines @param {string} [contains]
 */
async function readTailLines(file, requestedLines, contains = '') {
  const started = Date.now();
  const stat = await fs.stat(file);
  const maxReadBytes = 2 * 1024 * 1024;
  const start = Math.max(0, stat.size - maxReadBytes);
  const handle = await fs.open(file, 'r');
  let text = '';
  try {
    const buffer = Buffer.alloc(stat.size - start);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, start);
    text = buffer.subarray(0, bytesRead).toString('utf8');
  } finally {
    await handle.close();
  }
  let rows = text.split(/\r?\n/);
  if (start > 0) rows = rows.slice(1);
  if (rows.at(-1) === '') rows.pop();
  if (contains) rows = rows.filter((line) => line.includes(contains));
  const more = rows.length > requestedLines || start > 0;
  rows = rows.slice(-requestedLines);
  return {
    content: rows.join('\n'),
    lines_returned: rows.length,
    truncated: more,
    duration_ms: Date.now() - started
  };
}

/**
 * @param {Record<string, unknown>} job
 */
export async function executeLogReadJob(job) {
  const payload = normalizedJobPayload(job);
  const source = String(payload.source || '');
  const file = LOG_SOURCES[source];
  if (!file)
    return {
      status: 'failed',
      source,
      content: '',
      lines_returned: 0,
      truncated: false,
      duration_ms: 0,
      error: 'LOG_SOURCE_NOT_ALLOWED'
    };
  const lines = Math.max(1, Math.min(1000, Number(payload.lines || 200)));
  const contains = typeof payload.contains === 'string' ? payload.contains.slice(0, 200) : '';
  try {
    const r = await readTailLines(file, lines, contains);
    return { status: 'completed', source, ...r, error: null };
  } catch (error) {
    const readErr = /** @type {Record<string, unknown>} */ (error);
    return {
      status: 'failed',
      source,
      content: '',
      lines_returned: 0,
      truncated: false,
      duration_ms: 0,
      error: readErr?.code === 'ENOENT' ? 'LOG_SOURCE_NOT_FOUND' : String(readErr?.message || error)
    };
  }
}

/**
 * @param {object} [options]
 * @param {unknown} [options.capabilities]
 * @param {unknown} [options.policy_identity]
 */
function mutationPolicyGate({ capabilities, policy_identity } = {}) {
  const policy = currentPolicy;
  if (!policy)
    throw Object.assign(new Error('HOST_POLICY_NOT_READY'), { code: 'HOST_POLICY_NOT_READY' });
  const identity =
    policy_identity && typeof policy_identity === 'object'
      ? /** @type {Record<string, unknown>} */ (policy_identity)
      : null;
  if (
    identity?.policy_contract_version !== policy.contract_version ||
    identity?.policy_revision !== policy.revision ||
    identity?.policy_digest !== policy.digest
  )
    throw Object.assign(new Error('HOST_POLICY_REVISION_STALE'), {
      code: 'HOST_POLICY_REVISION_STALE'
    });
  return (
    Array.isArray(capabilities) &&
    capabilities.length > 0 &&
    capabilities.every((cap) => typeof cap === 'string' && policy.capabilities?.[cap] === true)
  );
}

/**
 * Browser capability is advertised only when the startup health gate passed
 * (playwright-core import + pin + managed Chromium present). A missing or
 * mismatched runtime hides every browser_* tool instead of failing at call
 * time. Full launch validation runs on first browser_create and is cached.
 * @returns {Array<string>}
 */
export function advertisedCapabilities() {
  const all = Object.keys(getHandlers()).sort();
  if (browserHealthCache.available) return all;
  return all.filter((c) => !c.startsWith('browser_'));
}
/** @type {{checked: boolean, available: boolean, error: string|null, playwright: string|null, revision: string|null}} */
export const browserHealthCache = {
  checked: false,
  available: false,
  error: 'BROWSER_HEALTH_NOT_CHECKED',
  playwright: null,
  revision: null
};

/** Re-announces capabilities on the live session, if any (cheap, idempotent). */
export function announceCapabilities() {
  try {
    const peer = /** @type {{sendJson?: unknown}} */ (liveSession);
    if (peer && typeof peer.sendJson === 'function')
      /** @type {(m: unknown) => void} */ (peer.sendJson).call(peer, sessionHello());
  } catch {}
}
/** Runs the lightweight startup browser health gate (no browser launch). */
export async function refreshBrowserHealth() {
  try {
    const h = await browserHealth();
    browserHealthCache.checked = true;
    browserHealthCache.available = h.available === true;
    browserHealthCache.error = h.available ? null : String(h.error || 'BROWSER_NOT_AVAILABLE');
    browserHealthCache.playwright = h.playwright || null;
    browserHealthCache.revision = h.revision || null;
  } catch {
    browserHealthCache.checked = true;
    browserHealthCache.available = false;
    browserHealthCache.error = 'BROWSER_NOT_AVAILABLE';
    browserHealthCache.playwright = null;
    browserHealthCache.revision = null;
  }
  return { ...browserHealthCache };
}
/**
 * @returns {Record<string, (job: Record<string, unknown>, options?: Record<string, unknown>) => Promise<Record<string, unknown>>>}
 */
export function getHandlers() {
  if (handlerRegistry) return handlerRegistry;
  const options = { readRoots: cfg.readRoots, serviceUnits: cfg.serviceStatusUnits },
    base = makeStructuredHandlers(options),
    mutations = makeMutationHandlers({ writeRoots: [layout.root], policyGate: mutationPolicyGate }),
    processes = makeProcessHandlers({ stateDir: layout.data }),
    services = makeServiceHandlers(),
    logFollow = makeLogFollowHandlers({
      logSources: Object.fromEntries(
        Object.entries(LOG_SOURCES).filter(([, v]) => typeof v === 'string' && v)
      )
    });
  const privilegedHelperAvailable = () => {
    if (process.platform !== 'linux') return false;
    try {
      return linuxPrivilegedHelperReadiness({
        clientId: cfg.clientId,
        serviceUid: typeof process.getuid === 'function' ? process.getuid() : 0,
        serviceGid: typeof process.getgid === 'function' ? process.getgid() : 0,
        expectedKeyId: null
      }).ok;
    } catch {
      return false;
    }
  };
  handlerRegistry = extendStructuredHandlers(
    {
      ...base,
      ...mutations,
      shell_exec: (job, options) =>
        executeShellJob(job, options, {
          root: layout.root,
          maxTimeoutSeconds: cfg.maxTimeoutSeconds,
          maxStdoutBytes: cfg.maxStdoutBytes,
          maxStderrBytes: cfg.maxStderrBytes
        }),
      log_read: executeLogReadJob,
      browser_navigate: browserNavigateJob,
      browser_interact: browserInteractJob,
      browser_snapshot: browserSnapshotJob,
      browser_create: browserCreateJob,
      browser_close: browserCloseJob,
      browser_find: browserFindJob,
      browser_tabs: browserTabsJob,
      browser_take_screenshot: browserScreenshotJob,
      browser_console_messages: browserConsoleJob,
      browser_network_requests: browserNetworkJob,
      browser_file_upload: browserUploadJob,
      ...processes,
      ...services,
      ...logFollow,
      ...(process.platform === 'linux'
        ? {
            privileged_shell_exec: makePrivilegedHelperClientHandler({
              isAvailable: privilegedHelperAvailable
            })
          }
        : {}),
      ...(process.platform === 'linux'
        ? {
            client_uninstall: makePrivilegedHelperClientHandler({
              isAvailable: privilegedHelperAvailable
            })
          }
        : {}),
      ...(process.platform === 'win32' ? { gui_launch: makeGuiLaunchHandler({ layout }) } : {}),
      client_update: makeUpdateHandler({
        serverUrl: cfg.serverUrl,
        clientId: cfg.clientId,
        currentVersion: VERSION,
        authHeaders: authenticatedHeaders,
        layout
      })
    },
    options
  );
  if (!handlerRegistry) throw new Error('HANDLER_REGISTRY_FAILED');
  return handlerRegistry;
}
/**
 * @param {Record<string, unknown>} job
 */
async function executeByTool(job) {
  const h = getHandlers()[String(job.tool || '')];
  if (!h)
    return {
      status: 'failed',
      exit_code: null,
      stdout: '',
      stderr: '',
      duration_ms: 0,
      error: 'UNSUPPORTED_TOOL:' + String(job.tool || ''),
      result_payload: {}
    };
  const started = Date.now(),
    r = await h({
      ...job,
      agent_policy_capabilities: currentPolicy?.capabilities || null,
      agent_policy_roots: currentPolicy?.roots || null
    });
  if (r.duration_ms == null) r.duration_ms = Date.now() - started;
  const op = String(job.tool || ''),
    payload = normalizedJobPayload(job);
  await localAudit(op, localAuditPayload(op, payload, r), r);
  return r;
}

/**
 * @param {Record<string, unknown>} [record]
 */
/**
 * @param {unknown} [record]
 */
async function authorizePreparedUpdate(record) {
  const rawBinding =
    record && typeof record === 'object'
      ? /** @type {Record<string, unknown>} */ (record).policy_binding
      : undefined;
  const binding = rawBinding && typeof rawBinding === 'object' ? rawBinding : null;
  if (!binding) return { ok: true, bound: false };
  return ensureJobPolicy({ ...binding, tool: 'client_update', request_payload: {} });
}

/**
 * @param {AgentState} state
 */
async function flushPendingResults(state) {
  for (const [jobId, rawResult] of Object.entries(state.pendingResults)) {
    const result = /** @type {Record<string, unknown>} */ (rawResult);
    try {
      await postJobResult(jobId, result);
      delete state.pendingResults[jobId];
      state.jobs[jobId] = {
        ...(state.jobs[jobId] || {}),
        status: /** @type {string} */ (result.status),
        result_sent_at: new Date().toISOString()
      };
      await writeState(state);
      await log('info', 'job_result_sent', { job_id: jobId, status: result.status });
      if (
        state.jobs[jobId]?.tool === 'client_update' &&
        result?.status === 'completed' &&
        resultPayloadOf(result)?.activation_pending
      ) {
        const policyCheck = await authorizePreparedUpdate(state.jobs[jobId]);
        if (!policyCheck.ok) {
          await log('error', 'client_update_activation_blocked', {
            job_id: jobId,
            version: resultPayloadOf(result)?.version,
            error: policyCheck.error
          });
          await auditPolicyFailure({ tool: 'client_update' }, policyFailureResult(policyCheck));
          continue;
        }
        await log('info', 'client_update_activating', {
          job_id: jobId,
          version: resultPayloadOf(result)?.version,
          transport: 'http-poll'
        });
        await activatePreparedUpdate(result, { layout });
      }
    } catch (error) {
      await log('error', 'job_result_retry_failed', {
        job_id: jobId,
        error: /** @type {Record<string, unknown>} */ (error).message
      });
      return false;
    }
  }
  return true;
}

/**
 * @param {AgentState} state
 */
function markInterruptedJobs(state) {
  let changed = false;
  for (const [jobId, record] of Object.entries(state.jobs)) {
    if (record?.status === 'running' && !state.pendingResults[jobId]) {
      state.pendingResults[jobId] = {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        duration_ms: record.duration_ms || 0,
        error: 'CLIENT_RESTART_DURING_EXECUTION',
        stdout_truncated: false,
        stderr_truncated: false
      };
      record.status = 'result_pending';
      changed = true;
    }
  }
  return changed;
}

/**
 * @param {AgentState} state
 */
export async function processOneJob(state) {
  if (!cfg.remoteExecEnabled) return { claimed: false, disabled: true };
  if (!cfg.clientToken) throw new Error('REMOTE_EXEC_REQUIRES_CLIENT_TOKEN');
  if (!(await flushPendingResults(state))) return { claimed: false, pending_result: true };

  const claimResponse = await postJson(
    `/api/clients/${encodeURIComponent(cfg.clientId)}/jobs/claim`,
    {}
  );
  const job = extractJob(claimResponse);
  if (!job) return { claimed: false };
  const jobId = normalizedJobId(job);
  if (!jobId) throw new Error('CLAIMED_JOB_WITHOUT_ID');

  if (state.jobs[jobId]) {
    await log('error', 'duplicate_job_claim_blocked', {
      job_id: jobId,
      local_status: state.jobs[jobId].status
    });
    return { claimed: true, duplicate: true, job_id: jobId };
  }

  state.jobs[jobId] = {
    status: 'claimed',
    claimed_at: new Date().toISOString(),
    tool: String(job.tool || ''),
    policy_binding: policyBindingRecord(job)
  };
  await writeState(state); // persist BEFORE any execution

  const policyCheck = await ensureJobPolicy(job);
  await postJobStart(jobId);
  state.jobs[jobId].status = 'running';
  state.jobs[jobId].started_at = new Date().toISOString();
  await writeState(state); // persist BEFORE spawn

  let result;
  if (!policyCheck.ok) {
    result = policyFailureResult(policyCheck);
    await auditPolicyFailure(job, result);
  } else {
    result = await executeByTool(job);
  }

  state.pendingResults[jobId] = result; // persist result BEFORE network send
  state.jobs[jobId].status = 'result_pending';
  state.jobs[jobId].finished_local_at = new Date().toISOString();
  await writeState(state);
  await flushPendingResults(state);
  return { claimed: true, job_id: jobId, result };
}

function sessionHello() {
  const p = systemPayload();
  return {
    type: 'hello',
    protocol_version: cfg.protocolVersion,
    client_id: cfg.clientId,
    client_version: VERSION,
    host: {
      hostname: p.hostname,
      platform: p.platform,
      arch: p.arch,
      os: p.os,
      cpus: p.metadata.cpus,
      total_memory_bytes: p.metadata.total_memory_bytes
    },
    capabilities: advertisedCapabilities(),
    features: [
      HOST_POLICY_FEATURE,
      BROWSER_POLICY_FEATURE,
      BROWSER_POLICY_V2_FEATURE,
      WORKSPACE_ROOTS_FEATURE,
      ...(Object.hasOwn(getHandlers(), 'privileged_shell_exec') ? ['privileged_helper_v1'] : [])
    ],
    transport: { scheme: configuredTransportScheme() },
    metadata: p.metadata
  };
}
/**
 * @param {AgentSessionSocket} ws @param {string} jobId @param {unknown} result
 */
/**
 * Reads a job-result payload without throwing on unexpected shapes.
 * Pending-results entries are always result objects in practice; anything
 * else yields undefined exactly where the old optional chains did.
 *
 * @param {unknown} result
 * @returns {Record<string, unknown>|undefined}
 */
function resultPayloadOf(result) {
  if (!result || typeof result !== 'object') return undefined;
  const payload = /** @type {Record<string, unknown>} */ (result).result_payload;
  return payload && typeof payload === 'object'
    ? /** @type {Record<string, unknown>} */ (payload)
    : undefined;
}
/**
 * @param {AgentSessionSocket} ws @param {string} jobId @param {unknown} result
 */
function sessionResponse(ws, jobId, result) {
  const bounded = boundSessionResult(result);
  ws.sendJson({
    type: 'response',
    id: jobId,
    ok: bounded.status === 'completed',
    result: bounded,
    ...(bounded.status === 'completed'
      ? {}
      : {
          error: {
            code: bounded.error || 'REMOTE_OPERATION_FAILED',
            message: bounded.error || bounded.status
          }
        })
  });
}
/**
 * @param {AgentState} state @param {AgentSessionSocket} ws
 */
async function flushSessionPending(state, ws) {
  for (const [jobId, result] of Object.entries(state.pendingResults)) {
    try {
      sessionResponse(ws, jobId, result);
    } catch {
      return false;
    }
  }
  return true;
}
/**
 * @param {AgentState} state @param {string} jobId @param {unknown} status
 */
async function ackSessionResult(state, jobId, status) {
  if (!state.pendingResults[jobId]) return;
  const result = /** @type {Record<string, unknown>} */ (state.pendingResults[jobId]),
    record = state.jobs[jobId] || {};
  delete state.pendingResults[jobId];
  state.jobs[jobId] = {
    ...record,
    status: /** @type {string} */ (status || 'completed'),
    result_sent_at: new Date().toISOString()
  };
  await writeState(state);
  await log('info', 'session_result_ack', { job_id: jobId, status });
  if (
    record.tool === 'client_update' &&
    status === 'completed' &&
    resultPayloadOf(result)?.activation_pending
  ) {
    const policyCheck = await authorizePreparedUpdate(record);
    if (!policyCheck.ok) {
      await log('error', 'client_update_activation_blocked', {
        job_id: jobId,
        version: resultPayloadOf(result)?.version,
        error: policyCheck.error
      });
      await auditPolicyFailure({ tool: 'client_update' }, policyFailureResult(policyCheck));
      return;
    }
    await log('info', 'client_update_activating', {
      job_id: jobId,
      version: resultPayloadOf(result)?.version
    });
    await activatePreparedUpdate(result, { layout });
  }
}
/**
 * @param {AgentState} state @param {AgentSessionSocket} ws @param {SessionMessage} msg
 */
async function handleSessionJob(state, ws, msg) {
  const jobId = String(msg.id || ''),
    tool = String(msg.op || '');
  if (!jobId) return;
  if (state.pendingResults[jobId]) {
    sessionResponse(ws, jobId, state.pendingResults[jobId]);
    return;
  }
  if (state.jobs[jobId] && state.jobs[jobId].status !== 'result_pending') {
    await log('error', 'duplicate_session_job_blocked', {
      job_id: jobId,
      local_status: state.jobs[jobId].status
    });
    return;
  }
  const job = {
    id: jobId,
    tool,
    request_payload: msg.payload || {},
    policy_contract_version: msg.policy_contract_version ?? null,
    policy_revision: msg.policy_revision ?? null,
    policy_digest: msg.policy_digest ?? null,
    required_capabilities: msg.required_capabilities ?? null,
    admission_origin: msg.admission_origin ?? null
  };
  state.jobs[jobId] = {
    status: 'claimed',
    claimed_at: new Date().toISOString(),
    tool,
    policy_binding: policyBindingRecord(job)
  };
  await writeState(state);
  const policyCheck = await ensureJobPolicy(job);
  let result;
  if (!policyCheck.ok) {
    result = policyFailureResult(policyCheck);
    await auditPolicyFailure(job, result);
  } else {
    ws.sendJson({ type: 'event', kind: 'job_started', data: { job_id: jobId } });
    state.jobs[jobId].status = 'running';
    state.jobs[jobId].started_at = new Date().toISOString();
    await writeState(state);
    result = await executeByTool(job);
  }
  state.pendingResults[jobId] = result;
  state.jobs[jobId].status = 'result_pending';
  state.jobs[jobId].finished_local_at = new Date().toISOString();
  await writeState(state);
  try {
    sessionResponse(ws, jobId, result);
  } catch {}
}
/**
 * @param {AgentState} state
 */
async function runSessionOnce(state) {
  const privateKey = await getDeviceKey(),
    sessionUrl = cfg.serverUrl + '/agent/connect',
    proof = createDeviceProof({
      privateKey,
      clientId: cfg.clientId,
      method: 'GET',
      url: sessionUrl,
      credential: cfg.clientToken
    }),
    ws = /** @type {AgentSessionSocket} */ (
      await connectWebSocket(cfg.serverUrl, { token: cfg.clientToken, deviceProof: proof })
    );
  let welcomed = false;
  /** @type {(value?: unknown) => void} */
  let resolveWelcome;
  /** @type {(reason?: unknown) => void} */
  let rejectWelcome;
  const welcome = new Promise((r, j) => {
      resolveWelcome = r;
      rejectWelcome = j;
    }),
    timer = setTimeout(() => rejectWelcome(new Error('WELCOME_TIMEOUT')), 10000);
  // Dead-peer detection (SYN-TRANS-001): every ping we send arms a 10s
  // window; ANY inbound frame disarms it. A half-open socket that swallows
  // pings trips the window → destroy → existing close/error path →
  // backoff reconnect. No behavior change on healthy links.
  // NOTE: created BEFORE the 'json' handler below registers — the handler
  // calls watchdog.poke() on every inbound frame including the welcome,
  // which arrives while runSessionOnce is suspended at `await welcome`,
  // i.e. before any later declaration would initialize (TDZ ReferenceError
  // would otherwise surface as INVALID_JSON on every connect).
  const watchdog = attachPongWatchdog({
    onTimeout: () => {
      log('error', 'session_pong_timeout', { after_ms: PONG_TIMEOUT_MS }).catch(() => {});
      try {
        if (typeof ws.destroy === 'function') ws.destroy('pong timeout');
        else ws.close(4001, 'pong timeout');
      } catch {}
    }
  });
  ws.on('json', (m) => {
    watchdog.poke();
    if (m.type === 'welcome') {
      welcomed = true;
      clearTimeout(timer);
      try {
        // Re-hellos (capability re-announce) also refresh a stale policy
        // when the hub sends a newer revision.
        const p = m?.policy ? applyCurrentPolicy(m.policy, m.policy_sig) : null;
        if (p && (!currentPolicy || Number(p.revision) >= Number(currentPolicy.revision || 0)))
          currentPolicy = p;
      } catch {}
      resolveWelcome(m);
      return;
    }
    if (m.type === 'request') {
      void handleSessionJob(state, ws, m);
      return;
    }
    if (m.type === 'event' && m.kind === 'result_ack') {
      void ackSessionResult(state, String(m.data?.job_id || ''), m.data?.status);
      return;
    }
    if (m.type === 'ping')
      try {
        ws.sendJson({ type: 'pong', timestamp: new Date().toISOString() });
      } catch {}
    if (m.type === 'error' && m.fatal)
      rejectWelcome(new Error(m.code || m.message || 'SESSION_FATAL'));
  });
  ws.on('protocolError', (e) => rejectWelcome(e));
  // SYN-TRANS-002: a socket-level 'error' during the welcome window has no
  // session yet; EventEmitter throws on unhandled 'error', which would crash
  // the agent process. Route it into the welcome race instead (post-welcome
  // the dedicated once('error') below owns it; double-reject is a no-op).
  const preWelcomeError = (/** @type {unknown} */ e) => rejectWelcome(e);
  ws.once('error', preWelcomeError);
  // Hello reflects current disk state on every (re)connect: a runtime that
  // arrived after boot (OTA, background convergence) advertises without
  // waiting for a process restart. Lightweight (no browser launch).
  try {
    await refreshBrowserHealth();
  } catch {}
  ws.sendJson(sessionHello());
  const w = await welcome
    .catch((/** @type {unknown} */ e) => {
      // SYN-TRANS-002: never leave a dead-but-open socket behind on welcome
      // failure (FD leak per retry; phantom-live on central). The throw below
      // preserves the original sessionLoop/backoff behavior.
      try {
        ws.close(4000, 'welcome failed');
      } catch {}
      throw e;
    })
    .finally(() => {
      ws.removeListener('error', preWelcomeError);
    });
  currentPolicy = w?.policy ? applyCurrentPolicy(w.policy, w.policy_sig) : null;
  liveSession = ws;
  await resetRetirementEvidence(state);
  await log('info', 'session_connected', {
    protocol_version: w.protocol_version,
    session_id: w.session_id,
    policy_revision: currentPolicy?.revision ?? null,
    transport_scheme: configuredTransportScheme()
  });
  await markUpdateHealthy(layout, VERSION);
  await flushSessionPending(state, ws);
  const hb = Math.max(5, Number(w.heartbeat_interval_seconds || 30)) * 1000,
    h = setInterval(() => {
      try {
        ws.sendJson({ type: 'ping', timestamp: new Date().toISOString() });
        watchdog.sentPing();
      } catch {}
    }, hb);
  try {
    await new Promise((resolve, reject) => {
      ws.once('close', resolve);
      ws.once('error', reject);
    });
  } catch (error) {
    /** @type {Record<string, unknown>} */ (error).sessionEstablished = welcomed;
    throw error;
  } finally {
    clearInterval(h);
    watchdog.cancel();
    if (liveSession === ws) liveSession = null;
  }
  if (welcomed) {
    const error = /** @type {Error & {sessionEstablished?: boolean}} */ (
      new Error('SESSION_DISCONNECTED')
    );
    error.sessionEstablished = true;
    throw error;
  }
}
/**
 * @param {number} attempt @param {{sessionEstablished?: unknown}|null|undefined} [error]
 */
export function nextSessionAttempt(attempt, error) {
  const base = error?.sessionEstablished ? 0 : attempt;
  return Math.min(base + 1, SESSION_BACKOFF.length - 1);
}
/**
 * @param {AgentState} state
 */
async function sessionLoop(state) {
  if (!cfg.sessionEnabled || !cfg.remoteExecEnabled || !cfg.clientToken) return;
  let attempt = 0;
  while (!retired) {
    const wait = SESSION_BACKOFF[Math.min(attempt, SESSION_BACKOFF.length - 1)];
    if (wait) await sleep(reconnectDelayMs(wait));
    if (retired) return;
    try {
      await runSessionOnce(state);
      attempt = 0;
    } catch (error) {
      liveSession = null;
      const sessionErr = /** @type {Record<string, unknown>} */ (error);
      const loggedAttempt = sessionErr?.sessionEstablished ? 0 : attempt;
      await log('error', 'session_failed', {
        error: sessionErr?.message || String(error),
        attempt: loggedAttempt,
        session_established: Boolean(sessionErr?.sessionEstablished)
      });
      attempt = nextSessionAttempt(
        attempt,
        error && typeof error === 'object'
          ? /** @type {{sessionEstablished?: unknown}} */ (error)
          : null
      );
    }
  }
}

/**
 * @param {AgentState} [state]
 */
export async function runTelemetryOnce(state) {
  if (!state) state = await readState();
  if (!state.registered) {
    await register();
    state.registered = true;
    state.registered_client_id = cfg.clientId;
    await writeState(state);
    await resetRetirementEvidence(state);
  }
  if (!liveSession) await heartbeat();
  await resetRetirementEvidence(state);
  const counts = await forwardTelemetry(state);
  await log('info', 'telemetry_cycle_ok', { counts });
  return { state, counts };
}

/**
 * @param {AgentState} state
 */
async function telemetryLoop(state) {
  while (!retired) {
    try {
      await runTelemetryOnce(state);
      if (!retired) await sleep(cfg.heartbeatSeconds * 1000);
    } catch (error) {
      if (/** @type {Record<string, unknown>} */ (error)?.status === 404) {
        state.registered = false;
        state.registered_client_id = null;
      }
      if (await observeRetirementFailure(state, error)) return;
      await log('error', 'telemetry_cycle_failed', {
        error: /** @type {Record<string, unknown>} */ (error)?.message || String(error)
      });
      if (!retired) await sleep(cfg.retrySeconds * 1000);
    }
  }
}

/**
 * @param {AgentState} state
 */
async function jobLoop(state) {
  while (!retired) {
    try {
      if (!liveSession) await processOneJob(state);
      if (!retired) await sleep(cfg.jobPollSeconds * 1000);
    } catch (error) {
      await log('error', 'job_cycle_failed', {
        error: /** @type {Record<string, unknown>} */ (error)?.message || String(error)
      });
      if (!retired) await sleep(cfg.retrySeconds * 1000);
    }
  }
}

export async function main() {
  await fs.mkdir(layout.data, { recursive: true });
  await fs.mkdir(layout.logs, { recursive: true });
  await fs.mkdir(layout.releases, { recursive: true });
  await fs.mkdir(layout.backups, { recursive: true });
  await fs.mkdir(layout.tmp, { recursive: true });
  try {
    await fs.access(layout.retiredMarker);
    retired = true;
    await log('info', 'client_retired_marker_present', { client_id: cfg.clientId });
    return 'retired';
  } catch (error) {
    if (/** @type {Record<string, unknown>} */ (error)?.code !== 'ENOENT') throw error;
  }
  await fs.writeFile(layout.pidFile, String(process.pid) + '\n', { mode: 0o640 });
  try {
    // SYN-PROC-004: adopt-or-kill processes recorded by a previous agent
    // incarnation (detached children survive agent death). Verified kills
    // only; unverifiable records are left for the next boot, never killed.
    const swept = await sweepOrphanedSessions({ stateDir: layout.data });
    if (swept.length)
      await log('info', 'process_orphan_sweep', { swept: swept.length, actions: swept });
  } catch {}
  const state = await readState();
  if (markInterruptedJobs(state)) await writeState(state);
  try {
    const { activateStagedBrowserRuntime, activateBundledBrowserRuntime, resolveBrowserRuntime } =
      await import('../browser/browser-runtime.mjs');
    const rtBase = resolveBrowserRuntime({ root: layout.root }).base;
    const bundled = await activateBundledBrowserRuntime({
      appDir: path.dirname(process.argv[1] || ''),
      base: rtBase
    });
    const promoted = await activateStagedBrowserRuntime(rtBase);
    await log('info', 'browser_runtime_promotion', { bundled, staged: promoted });
    // Converge the Chromium binary in the background (see
    // ensureManagedBrowsers): boot and hello never wait for the download.
    // When convergence newly completes, re-announce so the hub learns the
    // browser tools without waiting for a reconnect. A failed first attempt
    // schedules bounded backoff retries in-process (SYN-BRW-003) instead of
    // waiting for the next restart.
    import('../browser/browser-runtime.mjs')
      .then(async (m) => {
        const r = /** @type {{installed?: unknown}} */ (await m.ensureManagedBrowsers(rtBase));
        await log('info', 'browser_binary_convergence', { ...r });
        if (r.installed && !browserHealthCache.available) {
          try {
            await refreshBrowserHealth();
          } catch {}
          if (browserHealthCache.available) announceCapabilities();
        }
        if (!r.installed) {
          try {
            m.scheduleConvergenceRetry({
              base: rtBase,
              onResult: async (rr) => {
                const rec = /** @type {{installed?: unknown}} */ (
                  typeof rr === 'object' && rr !== null ? rr : {}
                );
                await log('info', 'browser_binary_convergence_retry', { ...rec });
                if (rec.installed && !browserHealthCache.available) {
                  try {
                    await refreshBrowserHealth();
                  } catch {}
                  if (browserHealthCache.available) announceCapabilities();
                }
              }
            });
          } catch {}
        }
      })
      .catch(() => {});
  } catch {}
  try {
    await refreshBrowserHealth();
  } catch {}
  await log('info', 'browser_health', { ...browserHealthCache });
  await log('info', 'hhc-client starting', {
    server: cfg.serverUrl,
    client_id: cfg.clientId,
    version: VERSION,
    remote_exec_enabled: cfg.remoteExecEnabled,
    token_configured: Boolean(cfg.clientToken),
    session_enabled: cfg.sessionEnabled,
    protocol_version: cfg.protocolVersion,
    capabilities: advertisedCapabilities(),
    filesystem_root: layout.root,
    runtime_app_dir: path.dirname(process.argv[1] || '')
  });
  await Promise.all([telemetryLoop(state), jobLoop(state), sessionLoop(state)]);
  return retired ? 'retired' : undefined;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(async (error) => {
    await log('error', 'fatal', { error: error?.stack || String(error) });
    process.exitCode = 1;
  });
}
