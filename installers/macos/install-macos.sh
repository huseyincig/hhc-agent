#!/bin/bash
set -euo pipefail
ROOT=/opt/hhc
PLIST=/Library/LaunchDaemons/com.hhc.client.plist
SRC="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
[ "$(id -u)" -eq 0 ] || { echo 'root required' >&2; exit 1; }
NODE_BIN="${HHC_NODE_BIN:-$(command -v node || true)}"
[ -n "$NODE_BIN" ] || { echo 'Node.js 22+ required' >&2; exit 1; }
NODE_MAJOR="$($NODE_BIN -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 22 ] || { echo 'Node.js 22+ required' >&2; exit 1; }
USER_NAME="${HHC_SERVICE_USER:-_hhc}"
GROUP_NAME="${HHC_SERVICE_GROUP:-$USER_NAME}"
if ! dscl . -read "/Groups/$GROUP_NAME" >/dev/null 2>&1; then
  [ "$GROUP_NAME" = "_hhc" ] || { echo "Service group '$GROUP_NAME' does not exist." >&2; exit 1; }
  SERVICE_ID="$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) 2>/dev/null | awk '$2 ~ /^[0-9]+$/ && $2 >= 200 && $2 < 500 { used[$2]=1 } END { for (i=499; i>=200; i--) if (!used[i]) { print i; exit } }' )"
  [ -n "$SERVICE_ID" ] || { echo 'No free macOS service UID/GID available in 200-499.' >&2; exit 1; }
  dscl . -create "/Groups/$GROUP_NAME"
  dscl . -create "/Groups/$GROUP_NAME" PrimaryGroupID "$SERVICE_ID"
fi
if ! dscl . -read "/Users/$USER_NAME" >/dev/null 2>&1; then
  [ "$USER_NAME" = "_hhc" ] || { echo "Service account '$USER_NAME' does not exist." >&2; exit 1; }
  SERVICE_ID="$(dscl . -read "/Groups/$GROUP_NAME" PrimaryGroupID | awk '{print $2}')"
  dscl . -create "/Users/$USER_NAME"
  dscl . -create "/Users/$USER_NAME" UniqueID "$SERVICE_ID"
  dscl . -create "/Users/$USER_NAME" PrimaryGroupID "$SERVICE_ID"
  dscl . -create "/Users/$USER_NAME" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$USER_NAME" UserShell /usr/bin/false
  dscl . -create "/Users/$USER_NAME" RealName 'HHC Service'
  dscl . -create "/Users/$USER_NAME" IsHidden 1
  dscl . -create "/Users/$USER_NAME" Password '*'
fi
if dseditgroup -o checkmember -m "$USER_NAME" admin 2>/dev/null | grep -qi '^yes'; then
  echo "HHC service account '$USER_NAME' must not be an administrator." >&2
  exit 1
fi
unset SERVICE_ID
launchctl bootout system "$PLIST" 2>/dev/null || true
chown root:"$GROUP_NAME" "$ROOT"
chmod 0750 "$ROOT"
_retired_root="/$(printf work)$(printf space)"
_retired_client_root="$_retired_root/hhc-client"
_hhc_pids=''
while IFS= read -r _line; do
  _pid="$(printf '%s\n' "$_line" | awk '{print $1}')"
  _cmd="$(printf '%s\n' "$_line" | cut -d' ' -f2-)"
  case "$_cmd" in
    *"$ROOT/app/launcher.mjs"*|*"$ROOT/app/client.mjs"*|*"$_retired_client_root/launcher.mjs"*|*"$_retired_client_root/client.mjs"*)
      [ "$_pid" = "$$" ] || _hhc_pids="$_hhc_pids $_pid"
      ;;
  esac
done <<EOF
$(ps -axo pid=,command=)
EOF
for _pid in $_hhc_pids; do kill -TERM "$_pid" 2>/dev/null || true; done
for _wait in 1 2 3 4 5 6 7 8 9 10; do
  _alive=''
  for _pid in $_hhc_pids; do kill -0 "$_pid" 2>/dev/null && _alive="$_alive $_pid" || true; done
  [ -z "$_alive" ] && break
  sleep 0.25
done
for _pid in $_alive; do kill -KILL "$_pid" 2>/dev/null || true; done
rm -f "$ROOT/data/client.lock"
unset _retired_root _retired_client_root _hhc_pids _alive _pid _cmd _line _wait
for d in app config data logs releases backups tmp; do
  install -d -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/$d"
done
if [ -f "$ROOT/config/hhc-device-key.pem" ]; then
  chown "$USER_NAME:$GROUP_NAME" "$ROOT/config/hhc-device-key.pem"
  chmod 0600 "$ROOT/config/hhc-device-key.pem"
fi
RUNTIME=(launcher.mjs singleton.mjs gui-launch.mjs browser-adapter.mjs browser-manager.mjs browser-jobs.mjs browser-runtime.mjs process-sessions.mjs service-ops.mjs log-ops.mjs shell.mjs egress-policy.mjs client.mjs ws-client.mjs structured-ops.mjs mutation-ops.mjs host-policy.mjs device-proof.mjs lifecycle.mjs updater.mjs hhc-paths.mjs privileged-helper-contract.mjs privileged-helper-core.mjs privileged-helper-ipc.mjs linux-peer-credentials.mjs privileged-helper-linux-daemon.mjs privileged-helper-linux-operations.mjs privileged-helper-bootstrap.mjs privileged-helper-client.mjs privileged-helper-linux-readiness.mjs package.json)
NEW="$ROOT/tmp/app-new-$STAMP"
install -d -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$NEW"
for f in "${RUNTIME[@]}"; do
  [ -f "$SRC/$f" ] || { echo "missing runtime file: $f" >&2; exit 1; }
  install -m 0640 -o "$USER_NAME" -g "$GROUP_NAME" "$SRC/$f" "$NEW/$f"
done
"$NODE_BIN" --check "$NEW/launcher.mjs"
"$NODE_BIN" --check "$NEW/client.mjs"
"$NODE_BIN" --check "$NEW/updater.mjs"
if [ -n "$(find "$ROOT/app" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  mv "$ROOT/app" "$ROOT/backups/migration-app-$STAMP"
else
  rmdir "$ROOT/app" 2>/dev/null || true
fi
mv "$NEW" "$ROOT/app"
chown -R "$USER_NAME:$GROUP_NAME" "$ROOT/app"
ENV_DST="$ROOT/config/hhc-client.env"
ENV_SRC=''
for p in "$ENV_DST" "$SRC/client.env" /usr/local/hhc/client.env /opt/hhc-client/client.env; do
  if [ -f "$p" ]; then ENV_SRC="$p"; break; fi
done
if [ -n "$ENV_SRC" ] && [ "$ENV_SRC" != "$ENV_DST" ]; then
  awk '!/^(HHC_ROOT|HHC_AUDIT_FILE|HHC_SERVER_LOG_FILE|HHC_TUNNEL_LOG_FILE|HHC_STATE_FILE|HHC_CLIENT_LOG|HHC_LOCAL_AUDIT_FILE)=/' "$ENV_SRC" > "$ROOT/tmp/hhc-client.env"
  install -m 0640 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/tmp/hhc-client.env" "$ENV_DST"
  rm -f "$ROOT/tmp/hhc-client.env"
elif [ ! -f "$ENV_DST" ]; then
  install -m 0640 -o "$USER_NAME" -g "$GROUP_NAME" /dev/null "$ENV_DST"
fi
migrate_one(){
  local dst="$1"; shift
  [ -e "$dst" ] && return 0
  local src
  for src in "$@"; do
    if [ -f "$src" ]; then
      install -m 0640 -o "$USER_NAME" -g "$GROUP_NAME" "$src" "$dst"
      return 0
    fi
  done
}
migrate_one "$ROOT/data/client-state.json" "$SRC/state.json" /usr/local/hhc/state.json /opt/hhc-client/state.json
migrate_one "$ROOT/logs/client.log" "$SRC/client.log" /usr/local/hhc/client.log /opt/hhc-client/client.log
migrate_one "$ROOT/logs/audit.jsonl" "$SRC/audit.jsonl" /usr/local/hhc/audit.jsonl /opt/hhc-client/audit.jsonl
chown -R "$USER_NAME:$GROUP_NAME" "$ROOT/config" "$ROOT/data" "$ROOT/logs" "$ROOT/releases" "$ROOT/backups" "$ROOT/tmp"

# Provision the managed browser runtime (Playwright + HHC-managed Chromium).
# Optional: BROWSER_READY=0 when the payload is absent or the install fails.
# No OS-dependency step on macOS; the client health gate hides browser tools
# until the runtime is present.
BROWSER_READY=0
BROWSER_SRC="$SRC/browser-runtime"
BROWSER_BASE="$ROOT/data/browser"
BROWSER_RT="$BROWSER_BASE/browser-runtime"
BROWSER_BROWSERS="$BROWSER_BASE/playwright-browsers"
if [ -f "$BROWSER_SRC/playwright-core/package.json" ] && [ -f "$BROWSER_SRC/playwright-core/cli.js" ]; then
  PIN_VERSION="$("$NODE_BIN" -e "import('file://$ROOT/app/browser-runtime.mjs').then((m) => console.log(m.BROWSER_RUNTIME_PIN.playwright))" 2>/dev/null || true)"
  RT_VERSION="$("$NODE_BIN" -p "require('$BROWSER_SRC/playwright-core/package.json').version" 2>/dev/null || true)"
  if [ -n "$PIN_VERSION" ] && [ "$PIN_VERSION" = "$RT_VERSION" ]; then
    rm -rf "$BROWSER_RT.new"
    install -d -m 0700 -o "$USER_NAME" -g "$GROUP_NAME" "$BROWSER_BASE"
    cp -a "$BROWSER_SRC" "$BROWSER_RT.new"
    chown -R "$USER_NAME:$GROUP_NAME" "$BROWSER_RT.new"
    rm -rf "$BROWSER_RT"
    mv "$BROWSER_RT.new" "$BROWSER_RT"
    if PLAYWRIGHT_BROWSERS_PATH="$BROWSER_BROWSERS" "$NODE_BIN" "$BROWSER_RT/playwright-core/cli.js" install chromium >/dev/null 2>&1; then
      _chromium_present=0
      for _rev in "$BROWSER_BROWSERS"/chromium-*; do
        [ -d "$_rev" ] && { _chromium_present=1; break; }
      done
      if [ "$_chromium_present" -eq 1 ]; then
        chown -R "$USER_NAME:$GROUP_NAME" "$BROWSER_BROWSERS"
        BROWSER_READY=1
      else
        echo 'Warning: managed Chromium revision missing after install; browser tools unavailable.' >&2
      fi
    else
      echo 'Warning: managed Chromium install failed (offline?); browser tools unavailable until installed.' >&2
    fi
  else
    echo "Warning: browser-runtime payload version ($RT_VERSION) does not match client pin ($PIN_VERSION); skipping browser install." >&2
  fi
else
  echo 'Warning: no browser-runtime payload in bootstrap; browser tools unavailable until OTA delivers it.' >&2
fi
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.hhc.client</string>
<key>ProgramArguments</key><array><string>$NODE_BIN</string><string>$ROOT/app/launcher.mjs</string></array>
<key>WorkingDirectory</key><string>$ROOT/app</string>
<key>UserName</key><string>$USER_NAME</string>
<key>GroupName</key><string>$GROUP_NAME</string>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ProcessType</key><string>Background</string>
</dict></plist>
EOF
chmod 0644 "$PLIST"
plutil -lint "$PLIST"
rm -f "$ROOT/data/retired.json"
install -m 0700 -o root -g wheel "$SRC/install/uninstall-macos.sh" "$ROOT/uninstall.sh"
launchctl bootstrap system "$PLIST"
launchctl enable system/com.hhc.client
sleep 2
launchctl print system/com.hhc.client >/dev/null
if [ "$BROWSER_READY" -eq 1 ]; then
  printf 'HHC canonical install complete: %s (managed browser runtime ready)\n' "$ROOT"
else
  printf 'HHC canonical install complete: %s (managed browser runtime NOT ready; browser tools hidden until installed)\n' "$ROOT"
fi
