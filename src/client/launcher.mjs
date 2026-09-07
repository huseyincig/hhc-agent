import fs from 'node:fs/promises';
import { defaultHhcRoot, hhcLayout } from './hhc-paths.mjs';
import { acquireClientLock } from './singleton.mjs';

/**
 * @param {unknown} text
 */
export function parseEnvFile(text) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i < 1) throw new Error('INVALID_ENV_LINE');
    const key = line.slice(0, i).trim();
    let value = line.slice(i + 1).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new Error('INVALID_ENV_KEY');
    if (key === 'HHC_ROOT') throw new Error('HHC_ROOT_NOT_CONFIGURABLE');
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    )
      value = value.slice(1, -1);
    out[key] = value;
  }
  return out;
}

/**
 * @param {object} [options]
 * @param {Record<string, string | undefined>} [options.env]
 * @param {string} [options.platform]
 * @param {string} [options.root]
 */
export async function loadCanonicalEnv({
  env = process.env,
  platform = process.platform,
  root = defaultHhcRoot(platform)
} = {}) {
  const layout = hhcLayout(root, platform);
  /** @type {Record<string, string>} */
  let parsed = {};
  try {
    parsed = parseEnvFile(await fs.readFile(layout.envFile, 'utf8'));
  } catch (error) {
    const errorCode =
      error && typeof error === 'object' && 'code' in error ? error.code : undefined;
    if (errorCode !== 'ENOENT') throw error;
  }
  for (const [key, value] of Object.entries(parsed)) if (env[key] == null) env[key] = value;
  return { root, layout, loaded: Object.keys(parsed).length > 0 };
}

export const LINUX_RETIRED_EXIT_CODE = 75;
/**
 * @param {unknown} platform
 * @param {unknown} outcome
 */
export function launcherExitCode(platform, outcome) {
  return platform === 'linux' && outcome === 'retired' ? LINUX_RETIRED_EXIT_CODE : null;
}

/**
 * @param {object} [options]
 * @param {Record<string, string | undefined>} [options.env]
 * @param {string} [options.platform]
 * @param {string} [options.root]
 * @param {() => Promise<any>} [options.loadClient]
 */
export async function runLauncher({
  env = process.env,
  platform = process.platform,
  root = defaultHhcRoot(platform),
  loadClient = () => import('./client.mjs')
} = {}) {
  const { layout } = await loadCanonicalEnv({ env, platform, root });
  const release = await acquireClientLock({ lockFile: layout.lockFile });
  let outcome;
  try {
    const { main } = await loadClient();
    if (typeof main !== 'function') throw new Error('CLIENT_MAIN_NOT_EXPORTED');
    outcome = await main();
  } finally {
    await release();
  }
  const exitCode = launcherExitCode(platform, outcome);
  if (exitCode != null) process.exitCode = exitCode;
  return outcome;
}

const invoked =
  process.argv[1] &&
  (process.argv[1].endsWith('/launcher.mjs') || process.argv[1].endsWith('\\launcher.mjs'));
if (invoked) await runLauncher();
