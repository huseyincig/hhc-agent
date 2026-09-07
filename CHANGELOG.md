# Changelog

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
