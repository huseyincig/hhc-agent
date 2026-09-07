import { verifyPrivilegedHelperRequest } from './privileged-helper-contract.mjs';
import { verifyPrivilegedHelperPeer } from './privileged-helper-ipc.mjs';

export const MAX_PRIVILEGED_REPLAY_ENTRIES = 10000;

export const PRIVILEGED_HELPER_RESULT_ERRORS = Object.freeze([
  'PRIVILEGED_HELPER_NOT_AVAILABLE',
  'PRIVILEGED_HELPER_EXECUTION_FAILED',
  'PRIVILEGED_HELPER_PEER_UNVERIFIED',
  'PRIVILEGED_HELPER_PEER_DENIED'
]);

/**
 * @param {object} [options]
 * @param {unknown} [options.clientId]
 * @param {unknown} [options.publicKey]
 * @param {Record<string, (payload: unknown, context: Record<string, unknown>) => unknown>} [options.handlers]
 * @param {() => number} [options.now]
 * @param {string} [options.platform]
 * @param {string} [options.peerIdentity]
 */
export function createPrivilegedHelperCore({
  clientId,
  publicKey,
  handlers = {},
  now = () => Date.now(),
  platform = process.platform,
  peerIdentity
} = {}) {
  const replay = new Set();
  const boundedReplay = /** @type {Set<string>} */ (
    /** @type {unknown} */ ({
      has: (/** @type {string} */ key) => replay.has(key),
      add: (/** @type {string} */ key) => {
        replay.add(key);
        if (replay.size > MAX_PRIVILEGED_REPLAY_ENTRIES) {
          const oldest = replay.values().next();
          if (!oldest.done) replay.delete(/** @type {string} */ (oldest.value));
        }
        return boundedReplay;
      }
    })
  );
  return Object.freeze({
    /**
     * @param {unknown} request
     * @param {object} [options]
     * @param {unknown} [options.peer]
     */
    async handle(request, { peer } = {}) {
      const peerCheck = verifyPrivilegedHelperPeer(peer, { platform, identity: peerIdentity });
      if (!peerCheck.ok) return peerCheck;
      const verified = verifyPrivilegedHelperRequest(request, {
        clientId,
        publicKey,
        nowMs: now(),
        replaySet: boundedReplay
      });
      if (!verified.ok) return verified;
      const handler = handlers[/** @type {string} */ (verified.request.operation)];
      if (typeof handler !== 'function')
        return { ok: false, error: 'PRIVILEGED_HELPER_NOT_AVAILABLE' };
      try {
        const result = await handler(structuredClone(verified.request.payload), {
          request_id: verified.request.request_id,
          job_id: verified.request.job_id,
          client_id: verified.request.client_id,
          operation: verified.request.operation,
          admission_origin: verified.request.admission_origin,
          policy_contract_version: verified.request.policy_contract_version,
          policy_revision: verified.request.policy_revision,
          policy_digest: verified.request.policy_digest,
          required_capabilities: [
            .../** @type {Array<string>} */ (verified.request.required_capabilities)
          ],
          peer: peerCheck.peer
        });
        return { ok: true, result: result ?? null };
      } catch {
        return { ok: false, error: 'PRIVILEGED_HELPER_EXECUTION_FAILED' };
      }
    }
  });
}
