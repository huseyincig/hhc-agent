import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { policyExtraRoots } from '../policy/host-policy.mjs';

export const MAX_WRITE_BYTES = 1024 * 1024;

export class MutationError extends Error {
  /**
   * @param {string} code
   */
  constructor(code) {
    super(code);
    /** @type {string} */
    this.code = code;
  }
}
/** @type {(code: string) => never} */
const err = (code) => {
  throw new MutationError(code);
};
/**
 * @param {unknown} e
 */
const isNoEnt = (e) => !!e && typeof e === 'object' && 'code' in e && e.code === 'ENOENT';
/**
 * @param {unknown} o @param {string} k
 */
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o || {}, k);
/**
 * @param {unknown} o @param {string} key @param {string} errorCode
 */
function optionalBoolean(o, key, errorCode) {
  const rec = o && typeof o === 'object' ? /** @type {Record<string, unknown>} */ (o) : null;
  if (!rec || !hasOwn(rec, key)) return false;
  if (typeof rec[key] !== 'boolean') err(errorCode);
  return rec[key] === true;
}

/**
 * @param {string} v @param {typeof import('node:path')} pathApi
 */
function normCase(v, pathApi) {
  const n = pathApi.normalize(v);
  return pathApi.sep === '\\' ? n.toLowerCase() : n;
}
/**
 * @param {string} candidate @param {string} root @param {typeof import('node:path')} pathApi
 */
function within(candidate, root, pathApi) {
  const c = normCase(candidate, pathApi),
    r = normCase(root, pathApi);
  return c === r || c.startsWith(r.endsWith(pathApi.sep) ? r : r + pathApi.sep);
}
/**
 * @param {string} target @param {typeof import('node:fs/promises')} fsApi
 */
async function lstatOrNull(target, fsApi) {
  try {
    return await fsApi.lstat(target);
  } catch (e) {
    if (isNoEnt(e)) return null;
    throw e;
  }
}
/**
 * @param {Array<string>|undefined} roots @param {typeof import('node:fs/promises')} fsApi @returns {Promise<Array<string>>}
 */
async function realAllowedRoots(roots, fsApi) {
  const out = [];
  for (const root of roots || []) {
    try {
      out.push(await fsApi.realpath(root));
    } catch {}
  }
  if (!out.length) err('PATH_NOT_ALLOWED');
  return out;
}
/**
 * @param {string} raw
 */
function validateWindowsLexicalPath(raw) {
  const value = raw.replace(/\//g, '\\');
  if (/^\\\\[?.]\\/.test(value)) err('PATH_NAMESPACE_NOT_ALLOWED');
  const afterDrive = /^[A-Za-z]:/.test(value) ? value.slice(2) : value;
  if (afterDrive.includes(':')) err('PATH_ALTERNATE_STREAM_NOT_ALLOWED');
  const reserved = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i;
  for (const segment of value.split('\\')) {
    if (!segment || segment === '.' || segment === '..' || /^[A-Za-z]:$/.test(segment)) continue;
    if (/[<>"|?*]/.test(segment) || /[\x00-\x1f]/.test(segment)) err('PATH_WINDOWS_INVALID_CHAR');
    if (/[ .]$/.test(segment)) err('PATH_WINDOWS_AMBIGUOUS_SEGMENT');
    if (reserved.test(segment)) err('PATH_RESERVED_NAME_NOT_ALLOWED');
  }
}
/**
 * @param {string} target @param {object} [options] @param {typeof import('node:path')} [options.pathApi]
 */
export function normalizeMutationPath(target, { pathApi = path } = {}) {
  const raw = String(target || '');
  if (raw.includes('\0')) err('PATH_INVALID');
  if (!pathApi.isAbsolute(raw)) err('PATH_NOT_ABSOLUTE');
  if (pathApi.sep === '\\') validateWindowsLexicalPath(raw);
  return pathApi.normalize(raw);
}
/**
 * @param {string} target @param {object} options @param {typeof import('node:fs/promises')} options.fsApi @param {typeof import('node:path')} options.pathApi
 */
async function nearestExistingAncestor(target, { fsApi, pathApi }) {
  let cur = target;
  while (true) {
    const st = await lstatOrNull(cur, fsApi);
    if (st) return cur;
    const parent = pathApi.dirname(cur);
    if (parent === cur) err('PATH_NOT_ALLOWED');
    cur = parent;
  }
}
/**
 * @param {string} target @param {object} [options] @param {Array<string>} [options.roots] @param {typeof import('node:fs/promises')} [options.fsApi] @param {typeof import('node:path')} [options.pathApi]
 */
export async function authorizeMutationPath(target, { roots, fsApi = fs, pathApi = path } = {}) {
  const normalized = normalizeMutationPath(target, { pathApi });
  const [ancestor, realRoots] = await Promise.all([
    nearestExistingAncestor(normalized, { fsApi, pathApi }),
    realAllowedRoots(roots, fsApi)
  ]);
  const realAncestor = await fsApi.realpath(ancestor);
  if (!realRoots.some((root) => within(realAncestor, root, pathApi))) err('PATH_NOT_ALLOWED');
  return { path: normalized, ancestor, real_ancestor: realAncestor, real_roots: realRoots };
}
/**
 * @param {string} target @param {{roots?: Array<string>, fsApi: typeof import('node:fs/promises'), pathApi: typeof import('node:path')}} options
 */
async function authorizeLeafParent(target, options) {
  const { fsApi = fs, pathApi = path } = options;
  const normalized = normalizeMutationPath(target, { pathApi });
  const parent = pathApi.dirname(normalized);
  const auth = await authorizeMutationPath(parent, options);
  return { ...auth, path: normalized, parent };
}
/**
 * @param {unknown} value @param {boolean} [present]
 */
function validateSha(value, present = value !== undefined) {
  if (!present) return null;
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) err('INVALID_SHA256');
  return value.toLowerCase();
}
/**
 * @param {string} file @param {typeof import('node:fs/promises')} fsApi
 */
async function shaFile(file, fsApi) {
  const h = crypto.createHash('sha256');
  const handle = await fsApi.open(file, 'r');
  try {
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (!bytesRead) break;
      h.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    return h.digest('hex');
  } finally {
    await handle.close();
  }
}
/**
 * @param {unknown} content
 */
function contentBytes(content) {
  if (typeof content !== 'string') err('CONTENT_REQUIRED');
  const bytes = Buffer.byteLength(content, 'utf8');
  if (bytes > MAX_WRITE_BYTES) err('CONTENT_TOO_LARGE');
  return bytes;
}
/**
 * @param {unknown} encoding @param {boolean} [present]
 */
function ensureEncoding(encoding, present = encoding !== undefined) {
  if (!present) return;
  if (encoding !== 'utf8') err('ENCODING_NOT_SUPPORTED');
}
/**
 * @param {string} target @param {Array<string>} realRoots @param {typeof import('node:path')} pathApi
 */
function rootTargetForbidden(target, realRoots, pathApi) {
  const t = normCase(target, pathApi);
  if (realRoots.some((root) => t === normCase(root, pathApi))) err('ROOT_MUTATION_FORBIDDEN');
}
/**
 * @param {string} target @param {object} [options] @param {Array<string>} [options.roots] @param {typeof import('node:fs/promises')} [options.fsApi] @param {typeof import('node:path')} [options.pathApi]
 */
async function forbidConfiguredRootTarget(target, { roots, fsApi = fs, pathApi = path } = {}) {
  const normalized = normalizeMutationPath(target, { pathApi });
  const realRoots = await realAllowedRoots(roots, fsApi);
  const configured = (roots || []).map((root) =>
    normCase(pathApi.normalize(String(root)), pathApi)
  );
  const t = normCase(normalized, pathApi);
  if (configured.includes(t) || realRoots.some((root) => t === normCase(root, pathApi)))
    err('ROOT_MUTATION_FORBIDDEN');
  return realRoots;
}
const queues = new Map();

/**
 * @param {Record<string, unknown>} [job]
 * @returns {{policy_contract_version: string|null, policy_revision: number|null, policy_digest: string|null}}
 */
export function policyIdentityFromJob(job = {}) {
  const contract =
    typeof job?.policy_contract_version === 'string' ? job.policy_contract_version : null;
  const revision =
    typeof job?.policy_revision === 'number' &&
    Number.isInteger(job.policy_revision) &&
    job.policy_revision > 0
      ? job.policy_revision
      : null;
  const digest =
    typeof job?.policy_digest === 'string' && /^[0-9a-f]{64}$/.test(job.policy_digest)
      ? job.policy_digest
      : null;
  return { policy_contract_version: contract, policy_revision: revision, policy_digest: digest };
}
/**
 * @param {string} key @param {() => unknown} fn
 */
async function serialized(key, fn) {
  const prior = queues.get(key) || Promise.resolve();
  /** @type {(value?: unknown) => void} */
  let release = () => {};
  const gate = new Promise((r) => (release = r));
  const tail = prior.then(() => gate);
  queues.set(key, tail);
  await prior;
  try {
    return await fn();
  } finally {
    release();
    if (queues.get(key) === tail) queues.delete(key);
  }
}
/**
 * @param {Array<string>} keys @param {(index?: number) => unknown} fn
 */
async function serializedMany(keys, fn) {
  const ordered = [...new Set(keys)].sort();
  /**
   * @param {number} index
   * @returns {unknown}
   */
  const take = (index) =>
    index >= ordered.length ? fn() : serialized(ordered[index], () => take(index + 1));
  return take(0);
}

/**
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {typeof import('node:path')} [options.pathApi]
 * @param {string} [options.platform]
 */
export async function fileWriteMutation(
  payload,
  { roots, fsApi = fs, pathApi = path, platform = process.platform } = {}
) {
  ensureEncoding(payload?.encoding, hasOwn(payload, 'encoding'));
  const mode = String(payload?.mode || '');
  if (!['create', 'replace', 'append'].includes(mode)) err('WRITE_MODE_INVALID');
  const bytes = contentBytes(payload?.content);
  const expected = validateSha(payload?.expected_sha256, hasOwn(payload, 'expected_sha256'));
  if (mode === 'create' && hasOwn(payload, 'expected_sha256'))
    err('EXPECTED_SHA_NOT_ALLOWED_FOR_CREATE');
  const createParents = optionalBoolean(payload, 'create_parents', 'INVALID_CREATE_PARENTS');
  const normalized = normalizeMutationPath(/** @type {string} */ (payload?.path), { pathApi });
  return serialized(normCase(normalized, pathApi), async () => {
    const options = { roots, fsApi, pathApi };
    await forbidConfiguredRootTarget(normalized, options);
    let st;
    let previousSha = null;
    if (mode === 'create') {
      const parent = pathApi.dirname(normalized);
      let parentAuth = await authorizeMutationPath(parent, options);
      rootTargetForbidden(normalized, parentAuth.real_roots, pathApi);
      st = await lstatOrNull(normalized, fsApi);
      if (st) err('FILE_EXISTS');
      if (createParents) {
        await fsApi.mkdir(parent, { recursive: true });
        parentAuth = await authorizeMutationPath(parent, options);
      } else {
        const pst = await lstatOrNull(parent, fsApi);
        if (!pst || !pst.isDirectory()) err('PARENT_NOT_FOUND');
      }
      rootTargetForbidden(normalized, parentAuth.real_roots, pathApi);
      if (await lstatOrNull(normalized, fsApi)) err('FILE_EXISTS');
      await fsApi.writeFile(normalized, /** @type {string} */ (payload.content), {
        encoding: 'utf8',
        flag: 'wx'
      });
    } else {
      const leaf = await authorizeLeafParent(normalized, options);
      rootTargetForbidden(normalized, leaf.real_roots, pathApi);
      st = await lstatOrNull(normalized, fsApi);
      if (!st) err('FILE_NOT_FOUND');
      if (st.isSymbolicLink()) err('PATH_SYMLINK_NOT_ALLOWED_FOR_WRITE');
      if (!st.isFile()) err('PATH_TYPE_NOT_SUPPORTED');
      const before = await shaFile(normalized, fsApi);
      previousSha = before;
      if (expected && before !== expected) err('FILE_SHA256_MISMATCH');
      if (mode === 'append') {
        if (Number(st.nlink || 1) > 1) err('PATH_HARDLINK_NOT_ALLOWED_FOR_APPEND');
        const appendLeaf = await authorizeLeafParent(normalized, options);
        rootTargetForbidden(normalized, appendLeaf.real_roots, pathApi);
        const appendStat = await lstatOrNull(normalized, fsApi);
        if (!appendStat) err('FILE_NOT_FOUND');
        if (appendStat.isSymbolicLink()) err('PATH_SYMLINK_NOT_ALLOWED_FOR_WRITE');
        if (!appendStat.isFile()) err('PATH_TYPE_NOT_SUPPORTED');
        if (Number(appendStat.nlink || 1) > 1) err('PATH_HARDLINK_NOT_ALLOWED_FOR_APPEND');
        if (expected && (await shaFile(normalized, fsApi)) !== expected)
          err('FILE_SHA256_MISMATCH');
        await fsApi.appendFile(normalized, /** @type {string} */ (payload.content), {
          encoding: 'utf8'
        });
      } else {
        const tmp = pathApi.join(
          pathApi.dirname(normalized),
          '.hhc-' +
            pathApi.basename(normalized) +
            '.' +
            process.pid +
            '.' +
            crypto.randomBytes(6).toString('hex') +
            '.tmp'
        );
        try {
          await fsApi.writeFile(tmp, /** @type {string} */ (payload.content), {
            encoding: 'utf8',
            flag: 'wx'
          });
          if (platform !== 'win32') await fsApi.chmod(tmp, st.mode & 0o7777);
          if (expected && (await shaFile(normalized, fsApi)) !== expected)
            err('FILE_SHA256_MISMATCH');
          await fsApi.rename(tmp, normalized);
        } finally {
          try {
            await fsApi.unlink(tmp);
          } catch {}
        }
      }
    }
    const resultSha = await shaFile(normalized, fsApi);
    return {
      path: normalized,
      mode,
      bytes_written: bytes,
      previous_sha256: previousSha,
      expected_sha256: expected,
      sha256: resultSha
    };
  });
}

/**
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {typeof import('node:path')} [options.pathApi]
 * @param {string} [options.platform]
 */
export async function directoryCreateMutation(payload, { roots, fsApi = fs, pathApi = path } = {}) {
  const parents = optionalBoolean(payload, 'parents', 'INVALID_PARENTS');
  const normalized = normalizeMutationPath(/** @type {string} */ (payload?.path), { pathApi });
  const options = { roots, fsApi, pathApi };
  return serialized(normCase(normalized, pathApi), async () => {
    await forbidConfiguredRootTarget(normalized, options);
    const leaf = await authorizeLeafParent(normalized, options);
    rootTargetForbidden(normalized, leaf.real_roots, pathApi);
    const current = await lstatOrNull(normalized, fsApi);
    if (current) {
      if (!current.isDirectory() || current.isSymbolicLink()) err('PATH_TYPE_NOT_SUPPORTED');
      return { path: normalized, created: false };
    }
    const parent = pathApi.dirname(normalized);
    if (!parents) {
      const pst = await lstatOrNull(parent, fsApi);
      if (!pst || !pst.isDirectory() || pst.isSymbolicLink()) err('PARENT_NOT_FOUND');
    }
    await fsApi.mkdir(normalized, { recursive: parents });
    const created = await lstatOrNull(normalized, fsApi);
    if (!created || !created.isDirectory() || created.isSymbolicLink())
      err('PATH_TYPE_NOT_SUPPORTED');
    const auth = await authorizeMutationPath(normalized, options);
    rootTargetForbidden(normalized, auth.real_roots, pathApi);
    return { path: normalized, created: true };
  });
}

/**
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {typeof import('node:path')} [options.pathApi]
 * @param {string} [options.platform]
 */
export async function fileMoveMutation(payload, { roots, fsApi = fs, pathApi = path } = {}) {
  const overwrite = optionalBoolean(payload, 'overwrite', 'INVALID_OVERWRITE');
  const source = normalizeMutationPath(/** @type {string} */ (payload?.source), { pathApi });
  const destination = normalizeMutationPath(/** @type {string} */ (payload?.destination), {
    pathApi
  });
  if (normCase(source, pathApi) === normCase(destination, pathApi))
    err('SOURCE_EQUALS_DESTINATION');
  const sourceOptions = { roots, fsApi, pathApi };
  await forbidConfiguredRootTarget(source, sourceOptions);
  const srcAuth = await authorizeLeafParent(source, sourceOptions);
  rootTargetForbidden(source, srcAuth.real_roots, pathApi);
  const srcStat = await lstatOrNull(source, fsApi);
  if (!srcStat) err('FILE_NOT_FOUND');
  if (srcStat.isDirectory() || (!srcStat.isFile() && !srcStat.isSymbolicLink()))
    err('PATH_TYPE_NOT_SUPPORTED');

  await forbidConfiguredRootTarget(destination, sourceOptions);
  const dstAuth = await authorizeLeafParent(destination, sourceOptions);
  rootTargetForbidden(destination, dstAuth.real_roots, pathApi);
  const dstParent = pathApi.dirname(destination);
  const dstParentStat = await lstatOrNull(dstParent, fsApi);
  if (!dstParentStat || !dstParentStat.isDirectory() || dstParentStat.isSymbolicLink())
    err('PARENT_NOT_FOUND');
  await authorizeMutationPath(dstParent, sourceOptions);

  const dstStat = await lstatOrNull(destination, fsApi);
  if (dstStat && !overwrite) err('DESTINATION_EXISTS');
  if (dstStat && (dstStat.isDirectory() || (!dstStat.isFile() && !dstStat.isSymbolicLink())))
    err('PATH_TYPE_NOT_SUPPORTED');

  return serializedMany([normCase(source, pathApi), normCase(destination, pathApi)], async () => {
    await forbidConfiguredRootTarget(source, sourceOptions);
    const srcLeafNow = await authorizeLeafParent(source, sourceOptions);
    rootTargetForbidden(source, srcLeafNow.real_roots, pathApi);
    await forbidConfiguredRootTarget(destination, sourceOptions);
    const dstLeafNow = await authorizeLeafParent(destination, sourceOptions);
    rootTargetForbidden(destination, dstLeafNow.real_roots, pathApi);
    const srcNow = await lstatOrNull(source, fsApi);
    if (!srcNow) err('FILE_NOT_FOUND');
    if (srcNow.isDirectory() || (!srcNow.isFile() && !srcNow.isSymbolicLink()))
      err('PATH_TYPE_NOT_SUPPORTED');
    const dstNow = await lstatOrNull(destination, fsApi);
    if (dstNow && !overwrite) err('DESTINATION_EXISTS');
    if (dstNow && (dstNow.isDirectory() || (!dstNow.isFile() && !dstNow.isSymbolicLink())))
      err('PATH_TYPE_NOT_SUPPORTED');
    try {
      await fsApi.rename(source, destination);
    } catch (e) {
      const moveCode = e && typeof e === 'object' && 'code' in e ? e.code : undefined;
      if (moveCode === 'EXDEV') err('CROSS_DEVICE_MOVE_NOT_SUPPORTED');
      throw e;
    }
    return { source, destination, overwritten: Boolean(dstNow) };
  });
}

/**
 * @param {Record<string, unknown>} payload
 * @param {object} [options]
 * @param {Array<string>} [options.roots]
 * @param {typeof import('node:fs/promises')} [options.fsApi]
 * @param {typeof import('node:path')} [options.pathApi]
 * @param {string} [options.platform]
 */
export async function fileDeleteMutation(payload, { roots, fsApi = fs, pathApi = path } = {}) {
  const recursive = optionalBoolean(payload, 'recursive', 'INVALID_RECURSIVE');
  const target = normalizeMutationPath(/** @type {string} */ (payload?.path), { pathApi });
  const options = { roots, fsApi, pathApi };
  await forbidConfiguredRootTarget(target, options);
  const auth = await authorizeLeafParent(target, options);
  rootTargetForbidden(target, auth.real_roots, pathApi);
  return serialized(normCase(target, pathApi), async () => {
    await forbidConfiguredRootTarget(target, options);
    const leafNow = await authorizeLeafParent(target, options);
    rootTargetForbidden(target, leafNow.real_roots, pathApi);
    const st = await lstatOrNull(target, fsApi);
    if (!st) err('FILE_NOT_FOUND');
    if (st.isDirectory() && !st.isSymbolicLink()) {
      if (!recursive) err('DIRECTORY_RECURSIVE_REQUIRED');
      await fsApi.rm(target, { recursive: true, force: false });
      return { path: target, type: 'directory', recursive: true, deleted: true };
    }
    if (!st.isFile() && !st.isSymbolicLink()) err('PATH_TYPE_NOT_SUPPORTED');
    await fsApi.unlink(target);
    return {
      path: target,
      type: st.isSymbolicLink() ? 'symlink' : 'file',
      recursive: false,
      deleted: true
    };
  });
}

/**
 * @param {unknown} error
 */
export function normalizeMutationError(error) {
  if (error instanceof MutationError) return { error: error.code, os_error_code: null };
  const osCode =
    error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
      ? error.code
      : null;
  /** @type {Record<string, string>} */
  const mapped = {
    EACCES: 'ACCESS_DENIED',
    EPERM: 'ACCESS_DENIED',
    ENOENT: 'FILE_NOT_FOUND',
    EEXIST: 'FILE_EXISTS',
    ENOTDIR: 'PATH_TYPE_NOT_SUPPORTED',
    EISDIR: 'PATH_TYPE_NOT_SUPPORTED',
    ENOTEMPTY: 'DIRECTORY_NOT_EMPTY',
    EROFS: 'READ_ONLY_FILESYSTEM',
    ENOSPC: 'NO_SPACE_LEFT',
    EBUSY: 'PATH_BUSY',
    ENAMETOOLONG: 'PATH_TOO_LONG',
    ELOOP: 'PATH_SYMLINK_LOOP',
    EMFILE: 'RESOURCE_LIMIT',
    ENFILE: 'RESOURCE_LIMIT',
    EXDEV: 'CROSS_DEVICE_MOVE_NOT_SUPPORTED'
  };
  return { error: (osCode && mapped[osCode]) || 'MUTATION_IO_ERROR', os_error_code: osCode };
}
/**
 * @param {unknown} result_payload @param {number} duration_ms
 */
function handlerOk(result_payload, duration_ms) {
  return {
    status: 'completed',
    exit_code: 0,
    stdout: '',
    stderr: '',
    error: null,
    duration_ms,
    result_payload
  };
}
/**
 * @param {unknown} error @param {number} duration_ms
 */
function handlerFail(error, duration_ms) {
  const normalized = normalizeMutationError(error);
  return {
    status: 'failed',
    exit_code: null,
    stdout: '',
    stderr: '',
    error: normalized.error,
    duration_ms,
    result_payload: normalized.os_error_code ? { os_error_code: normalized.os_error_code } : {}
  };
}
/**
 * @param {unknown} job @returns {Record<string, unknown>}
 */
function jobPayload(job) {
  const holder = /** @type {{request_payload?: unknown, payload?: unknown}} */ (job);
  const p = holder?.request_payload ?? holder?.payload ?? {};
  if (!p || typeof p !== 'object' || Array.isArray(p)) err('INVALID_ARGUMENTS');
  return /** @type {Record<string, unknown>} */ (p);
}

/**
 * @param {string} tool @param {Record<string, unknown>} [payload] @returns {Array<string>}
 */
export function requiredMutationCapabilities(tool, payload = {}) {
  if (tool === 'file_write') {
    const v = optionalBoolean(payload, 'create_parents', 'INVALID_CREATE_PARENTS');
    return ['file_write', ...(v ? ['directory_manage'] : [])];
  }
  if (tool === 'directory_create') {
    optionalBoolean(payload, 'parents', 'INVALID_PARENTS');
    return ['directory_manage'];
  }
  if (tool === 'file_move') {
    const v = optionalBoolean(payload, 'overwrite', 'INVALID_OVERWRITE');
    return ['file_move', ...(v ? ['file_delete'] : [])];
  }
  if (tool === 'file_delete') {
    const v = optionalBoolean(payload, 'recursive', 'INVALID_RECURSIVE');
    return ['file_delete', ...(v ? ['directory_manage'] : [])];
  }
  return [];
}

/**
 * @param {(args: Record<string, unknown>) => unknown} policyGate
 * @param {string} tool
 * @param {Record<string, unknown>} payload
 * @param {Record<string, unknown>} job
 */
async function requirePolicy(policyGate, tool, payload, job) {
  if (typeof policyGate !== 'function') err('HOST_POLICY_NOT_READY');
  const identity = policyIdentityFromJob(job);
  if (!identity.policy_contract_version || !identity.policy_revision || !identity.policy_digest)
    err('HOST_POLICY_NOT_READY');
  const capabilities = requiredMutationCapabilities(tool, payload);
  let allowed;
  try {
    allowed = await policyGate({ tool, capabilities, policy_identity: identity });
  } catch {
    err('HOST_POLICY_NOT_READY');
  }
  if (allowed !== true) err('HOST_POLICY_DENIED');
}

/**
 * @param {object} [options]
 * @param {Array<string>} [options.writeRoots]
 * @param {(args: Record<string, unknown>) => unknown} [options.policyGate]
 * @param {unknown} [options.fsApi]
 * @param {unknown} [options.pathApi]
 * @param {string} [options.platform]
 */
export function makeMutationHandlers({
  writeRoots = [],
  policyGate,
  fsApi = fs,
  pathApi = path,
  platform = process.platform
} = {}) {
  const options = { roots: writeRoots, fsApi, pathApi, platform };
  /** @type {(tool: string, fn: (payload: Record<string, unknown>, options: object) => unknown) => (job: unknown) => Promise<unknown>} */
  const wrap = (tool, fn) => async (job) => {
    const started = Date.now();
    try {
      const payload = jobPayload(job);
      await requirePolicy(
        /** @type {(args: Record<string, unknown>) => unknown} */ (policyGate),
        tool,
        payload,
        /** @type {Record<string, unknown>} */ (job)
      );
      const extra = policyExtraRoots(job);
      const roots = [...writeRoots, ...extra.write];
      return handlerOk(await fn(payload, { ...options, roots }), Date.now() - started);
    } catch (e) {
      return handlerFail(e, Date.now() - started);
    }
  };
  return {
    file_write: wrap('file_write', fileWriteMutation),
    directory_create: wrap('directory_create', directoryCreateMutation),
    file_move: wrap('file_move', fileMoveMutation),
    file_delete: wrap('file_delete', fileDeleteMutation)
  };
}
