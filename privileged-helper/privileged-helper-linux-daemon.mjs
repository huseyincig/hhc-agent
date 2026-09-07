import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import { pathToFileURL } from 'node:url';
import { createPrivilegedHelperCore } from './privileged-helper-core.mjs';
import {
  decodePrivilegedHelperFrame,
  encodePrivilegedHelperFrame,
  PRIVILEGED_HELPER_MAX_FRAME_BYTES
} from './privileged-helper-ipc.mjs';
import { verifyLinuxHelperPeer } from '../src/client/linux-peer-credentials.mjs';
import { linuxPrivilegedHelperHandlers } from './privileged-helper-linux-operations.mjs';

export const LINUX_HELPER_CONFIG = '/opt/hhc/config/privileged-helper.json';
export const LINUX_HELPER_PUBLIC_KEY = '/opt/hhc/config/privileged-helper-public.pem';
export const LINUX_PEERCRED_BINARY = '/opt/hhc/libexec/hhc-linux-peercred';
const CLIENT_ID_RE = /^hhc_[0-9a-f]{64}$/;
/**
 * @param {unknown} value
 * @param {Array<string>} keys
 */
const exactKeys = (value, keys) =>
  value &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());

/**
 * @param {string} [file]
 */
export function loadLinuxPrivilegedHelperConfig(file = LINUX_HELPER_CONFIG) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!exactKeys(value, ['client_id', 'service_gid', 'service_uid']))
    throw new Error('PRIVILEGED_HELPER_CONFIG_INVALID');
  if (
    !CLIENT_ID_RE.test(String(value.client_id || '')) ||
    !Number.isSafeInteger(value.service_uid) ||
    value.service_uid < 0 ||
    !Number.isSafeInteger(value.service_gid) ||
    value.service_gid < 0
  )
    throw new Error('PRIVILEGED_HELPER_CONFIG_INVALID');
  return Object.freeze({ ...value });
}

/**
 * @param {string} [file]
 */
export function loadLinuxPrivilegedHelperPublicKey(file = LINUX_HELPER_PUBLIC_KEY) {
  const key = crypto.createPublicKey(fs.readFileSync(file));
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('PRIVILEGED_HELPER_AUTH_INVALID');
  return key;
}
/**
 * @param {import('node:net').Socket} socket
 * @param {Buffer} buffer
 * @param {object} options
 * @param {ReturnType<typeof import('./privileged-helper-core.mjs').createPrivilegedHelperCore>} options.core
 * @param {any} options.config
 * @param {string} [options.peercredBinary]
 */
async function dispatchFrame(socket, buffer, { core, config, peercredBinary }) {
  const peer = await verifyLinuxHelperPeer(socket, {
    binary: peercredBinary,
    expectedUid: config.service_uid,
    expectedGid: config.service_gid
  });
  if (!peer.ok) {
    socket.end(encodePrivilegedHelperFrame(peer));
    return;
  }
  let request;
  try {
    request = decodePrivilegedHelperFrame(buffer);
  } catch {
    socket.end(
      encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_FRAME_INVALID' })
    );
    return;
  }
  const result = await core.handle(request, { peer: peer.peer });
  socket.end(encodePrivilegedHelperFrame(result));
}

/**
 * @param {import('node:net').Socket} socket
 * @param {object} context
 * @param {ReturnType<typeof import('./privileged-helper-core.mjs').createPrivilegedHelperCore>} context.core
 * @param {any} context.config
 * @param {string} [context.peercredBinary]
 */
function serveConnection(socket, context) {
  let buffer = Buffer.alloc(0),
    handled = false;
  socket.on('data', (chunk) => {
    if (handled) return;
    buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
    if (buffer.length > PRIVILEGED_HELPER_MAX_FRAME_BYTES) {
      handled = true;
      socket.end(
        encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_FRAME_TOO_LARGE' })
      );
      return;
    }
    const nl = buffer.indexOf(10);
    if (nl < 0) return;
    handled = true;
    socket.pause();
    if (nl !== buffer.length - 1) {
      socket.end(
        encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_FRAME_INVALID' })
      );
      return;
    }
    void dispatchFrame(socket, buffer, context).catch(() => {
      try {
        socket.end(
          encodePrivilegedHelperFrame({ ok: false, error: 'PRIVILEGED_HELPER_EXECUTION_FAILED' })
        );
      } catch {
        socket.destroy();
      }
    });
  });
}

/**
 * @param {object} [options]
 * @param {any} [options.config]
 * @param {unknown} [options.publicKey]
 * @param {string} [options.peercredBinary]
 * @param {Record<string, (payload: unknown, context: Record<string, unknown>) => unknown>} [options.handlers]
 */
export function createLinuxPrivilegedHelperServer({
  config,
  publicKey,
  peercredBinary = LINUX_PEERCRED_BINARY,
  handlers = {}
} = {}) {
  if (process.platform !== 'linux' || process.getuid?.() !== 0)
    throw new Error('PRIVILEGED_HELPER_ROOT_REQUIRED');
  const core = createPrivilegedHelperCore({
    clientId: config.client_id,
    publicKey,
    handlers,
    platform: 'linux',
    peerIdentity: '_hhc'
  });
  return net.createServer({ allowHalfOpen: false }, (socket) =>
    serveConnection(socket, { core, config, peercredBinary })
  );
}
export async function main() {
  const config = loadLinuxPrivilegedHelperConfig(),
    publicKey = loadLinuxPrivilegedHelperPublicKey();
  const server = createLinuxPrivilegedHelperServer({
    config,
    publicKey,
    handlers: linuxPrivilegedHelperHandlers()
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ fd: 3 }, () => resolve(server));
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error?.message || 'PRIVILEGED_HELPER_START_FAILED');
    process.exitCode = 1;
  });
}
