import path from 'node:path';

/**
 * @param {string} platform
 */
function pathApi(platform) {
  return platform === 'win32' ? path.win32 : path.posix;
}

/**
 * @param {string} [platform]
 */
export function defaultHhcRoot(platform = process.platform) {
  if (platform === 'win32') return 'C:\\HHC';
  return '/opt/hhc';
}

/**
 * @param {string} [root]
 * @param {string} [platform]
 */
export function hhcLayout(root = defaultHhcRoot(), platform = process.platform) {
  const api = pathApi(platform),
    r = api.resolve(root);
  /** @param {Array<string>} parts */
  const join = (...parts) => api.join(...parts);
  return Object.freeze({
    root: r,
    app: join(r, 'app'),
    config: join(r, 'config'),
    data: join(r, 'data'),
    logs: join(r, 'logs'),
    releases: join(r, 'releases'),
    backups: join(r, 'backups'),
    tmp: join(r, 'tmp'),
    envFile: join(r, 'config', 'hhc-client.env'),
    deviceKey: join(r, 'config', 'hhc-device-key.pem'),
    stateFile: join(r, 'data', 'client-state.json'),
    pidFile: join(r, 'data', 'client.pid'),
    lockFile: join(r, 'data', 'client.lock'),
    // Canonical writable workspace for file mutation tools. The policy root
    // (layout root) is OS-owned on Unix; this service-owned subtree is the
    // guaranteed-writable area for directory_create/file_write/file_edit.
    workspace: join(r, 'data', 'workspace'),
    retiredMarker: join(r, 'data', 'retired.json'),
    updateState: join(r, 'data', 'update-activation.json'),
    clientLog: join(r, 'logs', 'client.log'),
    auditLog: join(r, 'logs', 'audit.jsonl'),
    serverLog: join(r, 'logs', 'mcp-server.log'),
    tunnelLog: join(r, 'logs', 'mcp-tunnel.log'),
    clientReleases: join(r, 'releases', 'client'),
    clientBackups: join(r, 'backups', 'client')
  });
}

export function canonicalLayoutContract() {
  return Object.freeze({
    unixRoot: '/opt/hhc',
    windowsRoot: 'C:\\HHC',
    subdirs: ['app', 'config', 'data', 'logs', 'releases', 'backups', 'tmp']
  });
}
