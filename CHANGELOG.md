# Changelog

## 0.4.44 — 2026-09-07

- Playwright browser subsystem (contract 5.4.0): vendored `playwright-core`
  1.63.0 + HHC-managed Chromium r1243 under the data dir; per-`browser_id`
  isolated contexts with TTL sweep; stable refs with `BROWSER_STALE_TARGET`;
  `browser_find`, tabs, screenshots, console/network diagnostics,
  policy-gated uploads/downloads/evaluate; secret redaction; startup health
  gate; OTA staged runtime with boot promotion and background binary
  convergence. New: `src/browser/browser-{runtime,manager,jobs}.mjs`.
- Process/service/log sessions: `src/process/process-sessions.mjs`,
  `src/services/service-ops.mjs`, `src/logs/log-ops.mjs`; `file_edit`,
  `file_read_many/stat`, `directory_tree` handlers.
- Policy: `browser_uploads/downloads/existing_attach/headed` (deny by
  default), `browser_policy_v2` feature tier.
- Packaging fix: `shell.mjs` is now in `RUNTIME_FILES`/`SOURCE_PATHS` and
  all installers (previously omitted — staged releases would fail to load).
- Installer/OTA: versioned browser-runtime payload, staged validated
  installs, `BROWSER_READY` reporting; USTAR prefix support in packager.

## Unreleased

- `executeShellJob` extracted from `src/client/client.mjs` to
  `src/shell/shell.mjs` with explicit `runtime` limits
  (`{root, maxTimeoutSeconds, maxStdoutBytes, maxStderrBytes}`).
  `shellChildDetached` now lives in `src/shell/shell.mjs`.
  New: `tests/shell.test.mjs` (7 cases).

## 0.4.41 — 2026-09-07

- Updater refuses non-newer versions (`UPDATE_VERSION_NOT_NEWER`).
- Privileged helper replay cache bounded (10k, FIFO).
- Privileged handlers always registered on Linux with per-job readiness probe.
- Host policy requires protected transport unless `HHC_ALLOW_INSECURE_POLICY=1`.
- Default hub URL `https://mcp.hhc.zone`.

## History note

Versions ≤ 0.4.41 were developed in the private monorepo
(`hhc-remote-control`). This repo starts at 0.4.41 with a clean root commit;
prior history is intentionally not carried over.
