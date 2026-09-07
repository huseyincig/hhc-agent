import { invokePrivilegedHelper } from './privileged-helper-ipc.mjs';

/**
 * @param {object} [options]
 * @param {(request: unknown) => Promise<unknown>} [options.invoke]
 * @param {() => boolean} [options.isAvailable]
 */
export function makePrivilegedHelperClientHandler({
  invoke = invokePrivilegedHelper,
  isAvailable
} = {}) {
  /**
   * @param {string} error
   */
  const unavailable = (error) => ({
    status: 'failed',
    exit_code: null,
    stdout: '',
    stderr: '',
    duration_ms: 0,
    error,
    result_payload: {}
  });
  return async (/** @type {unknown} */ job) => {
    if (isAvailable && !isAvailable()) return unavailable('PRIVILEGED_HELPER_NOT_AVAILABLE');
    const jobRecord = /** @type {{request_payload?: unknown}} */ (job || {});
    const payloadRecord =
      jobRecord.request_payload && typeof jobRecord.request_payload === 'object'
        ? /** @type {Record<string, unknown>} */ (jobRecord.request_payload)
        : null;
    const request = payloadRecord?.privileged_authorization;
    if (!request || typeof request !== 'object' || Array.isArray(request))
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        duration_ms: 0,
        error: 'PRIVILEGED_HELPER_AUTH_REQUIRED',
        result_payload: {}
      };
    let reply;
    try {
      reply = /** @type {Record<string, any>} */ (await invoke(request));
    } catch (error) {
      const errorRecord = /** @type {{message?: unknown}} */ (error);
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        duration_ms: 0,
        error: errorRecord?.message || 'PRIVILEGED_HELPER_NOT_AVAILABLE',
        result_payload: {}
      };
    }
    if (!reply?.ok)
      return {
        status: 'failed',
        exit_code: null,
        stdout: '',
        stderr: '',
        duration_ms: 0,
        error: reply?.error || 'PRIVILEGED_HELPER_EXECUTION_FAILED',
        result_payload: {}
      };
    const r = reply.result && typeof reply.result === 'object' ? reply.result : {};
    return {
      status: ['completed', 'failed', 'timeout'].includes(r.status) ? r.status : 'completed',
      exit_code: r.exit_code ?? null,
      stdout: String(r.stdout || ''),
      stderr: String(r.stderr || ''),
      duration_ms: Number(r.duration_ms || 0),
      error: r.error ?? null,
      stdout_truncated: Boolean(r.stdout_truncated),
      stderr_truncated: Boolean(r.stderr_truncated),
      result_payload: { privileged: true }
    };
  };
}
