import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { defaultHhcRoot } from '../client/hhc-paths.mjs';
import { policyExtraRoots } from '../policy/host-policy.mjs';
import { spawn } from 'node:child_process';

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
 * @param {string} target
 * @param {Array<string>} roots
 */
async function realAllowed(target, roots) {
  const real = await fs.realpath(target);
  for (const root of roots) {
    let rr;
    try {
      rr = await fs.realpath(root);
    } catch {
      continue;
    }
    if (real === rr || real.startsWith(rr + path.sep)) return real;
  }
  throw new Error('PATH_NOT_ALLOWED');
}
/**
 * @param {string} cmd
 * @param {Array<string>} args
 * @param {number} [timeoutMs]
 */
async function capture(cmd, args, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const p = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '',
      err = '';
    const t = setTimeout(() => {
      try {
        p.kill('SIGKILL');
      } catch {}
    }, timeoutMs);
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('error', (e) => {
      clearTimeout(t);
      resolve({ code: null, out, err, error: e.message });
    });
    p.on('close', (code) => {
      clearTimeout(t);
      resolve({ code, out: out.trim(), err: err.trim() });
    });
  });
}

/**
 * @param {object} [options]
 * @param {Array<string>} [options.readRoots]
 * @param {Array<string>} [options.serviceUnits]
 */
export function makeStructuredHandlers({
  readRoots = [defaultHhcRoot()],
  serviceUnits = ['hhc-client.service']
} = {}) {
  return {
    system_snapshot: async () =>
      ok({
        hostname: os.hostname(),
        platform: os.platform(),
        release: os.release(),
        arch: os.arch(),
        cpus: os.cpus()?.length || null,
        total_memory_bytes: os.totalmem(),
        free_memory_bytes: os.freemem(),
        uptime_seconds: Math.floor(os.uptime()),
        loadavg: os.loadavg()
      }),
    file_read: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const roots = [...readRoots, ...policyExtraRoots(job).read];
        const file = await realAllowed(String(p.path || ''), roots),
          max = Math.max(1, Math.min(65536, Number(p.max_bytes || 65536))),
          b = await fs.readFile(file);
        return ok({
          path: file,
          content: b.subarray(0, max).toString('utf8'),
          bytes: b.length,
          truncated: b.length > max
        });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    file_read_many: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const rawPaths = Array.isArray(p.paths) ? p.paths : [];
        if (rawPaths.length < 1 || rawPaths.length > 10) throw new Error('PATH_COUNT_INVALID');
        const max = Math.max(1, Math.min(65536, Number(p.max_bytes || 65536)));
        const roots = [...readRoots, ...policyExtraRoots(job).read];
        const results = [];
        for (const raw of rawPaths.slice(0, 10)) {
          try {
            const file = await realAllowed(String(raw || ''), roots),
              b = await fs.readFile(file);
            results.push({
              path: file,
              content: b.subarray(0, max).toString('utf8'),
              bytes: b.length,
              truncated: b.length > max,
              error: null
            });
          } catch (e) {
            const errorRecord = /** @type {{message?: unknown}} */ (e);
            results.push({
              path: String(raw || ''),
              content: '',
              bytes: 0,
              truncated: false,
              error: String(errorRecord?.message || e)
            });
          }
        }
        return ok({ results });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    file_stat: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const roots = [...readRoots, ...policyExtraRoots(job).read];
        const file = await realAllowed(String(p.path || ''), roots),
          st = await fs.stat(file);
        return ok({
          path: file,
          size_bytes: st.size,
          mtime: st.mtime?.toISOString?.() || null,
          mode: (st.mode & 0o777).toString(8),
          is_directory: st.isDirectory()
        });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    directory_tree: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const roots = [...readRoots, ...policyExtraRoots(job).read];
        const root = await realAllowed(String(p.path || ''), roots),
          maxDepth = Math.max(1, Math.min(10, Number(p.max_depth ?? 5))),
          maxEntries = Math.max(1, Math.min(2000, Number(p.max_entries ?? 500)));
        /** @type {Array<{path: string, name: string, type: string, depth: number}>} */
        const entries = [];
        let truncated = false;
        /** @param {string} dir @param {number} depth */
        const walk = async (dir, depth) => {
          if (depth > maxDepth || entries.length >= maxEntries) {
            truncated = true;
            return;
          }
          let rows;
          try {
            rows = await fs.readdir(dir, { withFileTypes: true });
          } catch {
            return;
          }
          for (const d of rows) {
            if (entries.length >= maxEntries) {
              truncated = true;
              return;
            }
            const full = path.join(dir, d.name);
            entries.push({
              path: full,
              name: d.name,
              type: d.isDirectory() ? 'directory' : d.isFile() ? 'file' : 'other',
              depth
            });
            if (d.isDirectory()) await walk(full, depth + 1);
          }
        };
        await walk(root, 0);
        return ok({ path: root, entries, truncated });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    },
    file_list: async (/** @type {unknown} */ job) => {
      const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
      const p = /** @type {Record<string, unknown>} */ (
        jobRecord.request_payload || jobRecord.payload || {}
      );
      try {
        const roots = [...readRoots, ...policyExtraRoots(job).read];
        const dir = await realAllowed(String(p.path || ''), roots),
          limit = Math.max(1, Math.min(500, Number(p.limit || 200))),
          rows = await fs.readdir(dir, { withFileTypes: true }),
          entries = [];
        for (const d of rows.slice(0, limit)) {
          let st = null;
          try {
            st = await fs.stat(path.join(dir, d.name));
          } catch {}
          entries.push({
            name: d.name,
            type: d.isDirectory()
              ? 'directory'
              : d.isFile()
                ? 'file'
                : d.isSymbolicLink()
                  ? 'symlink'
                  : 'other',
            size: st?.size ?? null,
            mtime: st?.mtime?.toISOString?.() || null
          });
        }
        return ok({ path: dir, entries, truncated: rows.length > limit });
      } catch (e) {
        const errorRecord = /** @type {{message?: unknown}} */ (e);
        return fail(errorRecord?.message);
      }
    }
  };
}
/**
 * @param {unknown} job
 * @param {object} [options]
 * @param {Array<string>} [options.readRoots]
 */
export async function fileSearchJob(job, { readRoots = [defaultHhcRoot()] } = {}) {
  const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  const p = /** @type {Record<string, unknown>} */ (
    jobRecord.request_payload || jobRecord.payload || {}
  );
  const query = String(p.query || '').slice(0, 200);
  if (!query) return fail('QUERY_REQUIRED');
  try {
    const roots = [...readRoots, ...policyExtraRoots(job).read];
    const root = await realAllowed(String(p.path || ''), roots),
      maxResults = Math.max(1, Math.min(200, Number(p.max_results || 100))),
      stack = [root],
      results = [];
    let files = 0;
    while (stack.length && files < 2000 && results.length < maxResults) {
      const dir = /** @type {string} */ (stack.pop());
      let rows = [];
      try {
        rows = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const d of rows) {
        const full = path.join(dir, d.name);
        if (d.isDirectory() && !d.isSymbolicLink()) {
          stack.push(full);
          continue;
        }
        if (!d.isFile()) {
          continue;
        }
        files++;
        if (files > 2000) break;
        let st;
        try {
          st = await fs.stat(full);
        } catch {
          continue;
        }
        if (st.size > 512 * 1024) continue;
        let text;
        try {
          text = await fs.readFile(full, 'utf8');
        } catch {
          continue;
        }
        const idx = text.indexOf(query);
        if (idx >= 0) {
          const before = text.slice(0, idx),
            line = before.split('\n').length,
            preview = text
              .slice(Math.max(0, idx - 80), Math.min(text.length, idx + query.length + 120))
              .replace(/\s+/g, ' ');
          results.push({ path: full, line, preview });
          if (results.length >= maxResults) break;
        }
      }
    }
    return ok({
      path: root,
      query,
      results,
      files_searched: files,
      truncated: stack.length > 0 || files >= 2000 || results.length >= maxResults
    });
  } catch (e) {
    const errorRecord = /** @type {{message?: unknown}} */ (e);
    return fail(errorRecord?.message);
  }
}

const KNOWN_SERVICE_ALIASES = [
  'hhc-client.service',
  'hhc-client',
  'hhc-mcp.service',
  'hhc-mcp',
  'com.hhc.client',
  'HHC Client',
  'HHCClient'
];

/**
 * @param {unknown} job
 * @param {object} [options]
 * @param {Array<string>} [options.serviceUnits]
 */
export async function serviceStatusJob(
  job,
  { serviceUnits = ['hhc-client.service', 'com.hhc.client', 'HHC Client'] } = {}
) {
  const jobRecord = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job || {});
  const p = /** @type {Record<string, unknown>} */ (
    jobRecord.request_payload || jobRecord.payload || {}
  );
  const unit = String(p.unit || '').trim();
  const allowed = new Set([...serviceUnits, ...KNOWN_SERVICE_ALIASES]);
  if (!unit || !allowed.has(unit)) return fail('SERVICE_NOT_ALLOWED');

  const platform = os.platform();

  if (platform === 'linux') {
    const linuxUnit = unit.endsWith('.service')
      ? unit
      : unit === 'HHC Client' || unit === 'com.hhc.client'
        ? 'hhc-client.service'
        : `${unit}.service`;
    const [active, enabled] = await Promise.all([
      capture('systemctl', ['is-active', linuxUnit]),
      capture('systemctl', ['is-enabled', linuxUnit])
    ]);
    return ok({
      unit,
      resolved_unit: linuxUnit,
      platform: 'linux',
      active: active.out || 'unknown',
      enabled: enabled.out || 'unknown',
      active_exit_code: active.code,
      enabled_exit_code: enabled.code
    });
  }

  if (platform === 'darwin') {
    const macUnit = unit.includes('com.hhc') ? unit : 'com.hhc.client';
    const res = await capture('launchctl', ['list', macUnit]);
    let isActive = 'unknown';
    let isEnabled = 'enabled';
    if (res.code === 0 && res.out) {
      isActive = 'active';
    } else if (res.code === 113 || (res.err && res.err.includes('Could not find'))) {
      isActive = 'inactive';
      isEnabled = 'disabled';
    } else {
      try {
        await fs.access(`/Library/LaunchDaemons/${macUnit}.plist`);
        isEnabled = 'enabled';
        isActive = res.code === 0 ? 'active' : 'inactive';
      } catch {
        isEnabled = 'unknown';
      }
    }
    return ok({
      unit,
      resolved_unit: macUnit,
      platform: 'darwin',
      active: isActive,
      enabled: isEnabled,
      active_exit_code: res.code,
      raw_output: res.out || res.err || ''
    });
  }

  if (platform === 'win32') {
    const taskName =
      unit === 'hhc-client.service' ||
      unit === 'com.hhc.client' ||
      unit === 'HHC Client' ||
      unit === 'hhc-client'
        ? 'HHC Client'
        : unit;
    const res = await capture('powershell.exe', [
      '-NoProfile',
      '-Command',
      `$t = Get-ScheduledTask -TaskName '${taskName}' -ErrorAction SilentlyContinue; if ($t) { Write-Output ('TASK_STATE:' + $t.State) } else { $s = Get-Service -Name '${unit}' -ErrorAction SilentlyContinue; if ($s) { Write-Output ('SVC_STATUS:' + $s.Status) } else { Write-Output 'NOT_FOUND' } }`
    ]);
    let isActive = 'unknown';
    let isEnabled = 'enabled';
    const out = (res.out || '').trim();
    if (out.includes('TASK_STATE:Running')) {
      isActive = 'active';
      isEnabled = 'enabled';
    } else if (out.includes('TASK_STATE:Ready')) {
      isActive = 'active';
      isEnabled = 'enabled';
    } else if (out.includes('TASK_STATE:Disabled')) {
      isActive = 'inactive';
      isEnabled = 'disabled';
    } else if (out.includes('SVC_STATUS:Running')) {
      isActive = 'active';
      isEnabled = 'enabled';
    } else if (out.includes('SVC_STATUS:Stopped')) {
      isActive = 'inactive';
      isEnabled = 'enabled';
    } else if (out.includes('NOT_FOUND')) {
      isActive = 'inactive';
      isEnabled = 'unknown';
    }
    return ok({
      unit,
      resolved_unit: taskName,
      platform: 'win32',
      active: isActive,
      enabled: isEnabled,
      active_exit_code: res.code,
      raw_output: out
    });
  }

  return fail('PLATFORM_NOT_SUPPORTED');
}

/**
 * @param {Record<string, (job: any, ...args: Array<any>) => unknown>} base
 * @param {object} [options]
 * @param {Array<string>} [options.readRoots]
 * @param {Array<string>} [options.serviceUnits]
 */
export function extendStructuredHandlers(base, options) {
  return {
    ...base,
    file_search: (/** @type {unknown} */ job) => fileSearchJob(job, options),
    service_status: (/** @type {unknown} */ job) => serviceStatusJob(job, options)
  };
}
