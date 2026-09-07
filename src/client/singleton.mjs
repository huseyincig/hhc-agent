import fs from 'node:fs/promises';
import path from 'node:path';

/**
 * @param {unknown} pid
 */
export function defaultPidAlive(pid) {
  if (typeof pid !== 'number' || !Number.isInteger(pid) || pid < 2) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const errorCode =
      error && typeof error === 'object' && 'code' in error ? error.code : undefined;
    return errorCode === 'EPERM';
  }
}

/**
 * @param {object} [options]
 * @param {string} [options.lockFile]
 * @param {number} [options.pid]
 * @param {(pid: number) => boolean} [options.pidAlive]
 */
export async function acquireClientLock({
  lockFile,
  pid = process.pid,
  pidAlive = defaultPidAlive
} = {}) {
  if (!lockFile) throw new Error('CLIENT_LOCK_PATH_REQUIRED');
  await fs.mkdir(path.dirname(lockFile), { recursive: true });
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const handle = await fs.open(lockFile, 'wx', 0o640);
      await handle.writeFile(JSON.stringify({ pid, started_at: new Date().toISOString() }) + '\n');
      await handle.close();
      let released = false;
      return async () => {
        if (released) return;
        released = true;
        try {
          const row = JSON.parse(await fs.readFile(lockFile, 'utf8'));
          if (Number(row.pid) === pid) await fs.rm(lockFile, { force: true });
        } catch {}
      };
    } catch (error) {
      const errorCode =
        error && typeof error === 'object' && 'code' in error ? error.code : undefined;
      if (errorCode !== 'EEXIST') throw error;
      let owner = 0;
      try {
        owner = Number(JSON.parse(await fs.readFile(lockFile, 'utf8')).pid || 0);
      } catch {}
      if (owner && pidAlive(owner)) {
        const e = /** @type {Error & {code?: string, owner_pid?: number}} */ (
          new Error('HHC_CLIENT_ALREADY_RUNNING')
        );
        e.code = 'HHC_CLIENT_ALREADY_RUNNING';
        e.owner_pid = owner;
        throw e;
      }
      await fs.rm(lockFile, { force: true });
    }
  }
  throw new Error('CLIENT_LOCK_ACQUIRE_FAILED');
}
