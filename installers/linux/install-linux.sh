#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/hhc
UNIT=/etc/systemd/system/hhc-client.service
SRC="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
[ "$(id -u)" -eq 0 ] || { echo 'root required' >&2; exit 1; }
NODE_BIN="$(command -v node || true)"
[ -n "$NODE_BIN" ] || { echo 'Node.js 22+ required' >&2; exit 1; }
NODE_MAJOR="$($NODE_BIN -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 22 ] || { echo 'Node.js 22+ required' >&2; exit 1; }
USER_NAME="${HHC_SERVICE_USER:-_hhc}"
GROUP_NAME="${HHC_SERVICE_GROUP:-$USER_NAME}"
if ! getent group "$GROUP_NAME" >/dev/null; then groupadd --system "$GROUP_NAME"; fi
if ! id "$USER_NAME" >/dev/null 2>&1; then
  useradd --system --gid "$GROUP_NAME" --home-dir "$ROOT" --shell /usr/sbin/nologin "$USER_NAME"
fi
PRIMARY_GID="$(id -g "$USER_NAME")"
EXPECTED_GID="$(getent group "$GROUP_NAME" | cut -d: -f3)"
[ "$PRIMARY_GID" = "$EXPECTED_GID" ] || { echo "HHC service account '$USER_NAME' primary group must be '$GROUP_NAME'." >&2; exit 1; }
USER_SHELL="$(getent passwd "$USER_NAME" | cut -d: -f7)"
case "$USER_SHELL" in
  /usr/sbin/nologin|/sbin/nologin|/bin/false|/usr/bin/false) ;;
  *) echo "HHC service account '$USER_NAME' must use a non-login shell." >&2; exit 1 ;;
esac
USER_GROUPS="$(id -nG "$USER_NAME" | xargs)"
[ "$USER_GROUPS" = "$GROUP_NAME" ] || { echo "HHC service account '$USER_NAME' must not belong to supplementary groups: $USER_GROUPS" >&2; exit 1; }
unset PRIMARY_GID EXPECTED_GID USER_SHELL USER_GROUPS
systemctl stop hhc-client.service 2>/dev/null || true
chown root:"$GROUP_NAME" "$ROOT"
chmod 0750 "$ROOT"
_retired_root="/$(printf work)$(printf space)"
_retired_client_root="$_retired_root/hhc-client"
_hhc_pids=''
for _proc in /proc/[0-9]*; do
  [ -r "$_proc/cmdline" ] || continue
  _cmd="$(tr '\000' ' ' < "$_proc/cmdline" 2>/dev/null || true)"
  case "$_cmd" in
    *"$ROOT/app/launcher.mjs"*|*"$ROOT/app/client.mjs"*|*"$_retired_client_root/launcher.mjs"*|*"$_retired_client_root/client.mjs"*)
      _pid="${_proc##*/}"
      [ "$_pid" = "$$" ] || _hhc_pids="$_hhc_pids $_pid"
      ;;
  esac
done
for _pid in $_hhc_pids; do kill -TERM "$_pid" 2>/dev/null || true; done
for _wait in 1 2 3 4 5 6 7 8 9 10; do
  _alive=''
  for _pid in $_hhc_pids; do kill -0 "$_pid" 2>/dev/null && _alive="$_alive $_pid" || true; done
  [ -z "$_alive" ] && break
  sleep 0.25
done
for _pid in $_alive; do kill -KILL "$_pid" 2>/dev/null || true; done
rm -f "$ROOT/data/client.lock"
unset _retired_root _retired_client_root _hhc_pids _alive _pid _proc _cmd _wait
for d in app config data logs releases backups tmp; do
  install -d -m 0750 -o "$USER_NAME" -g "$GROUP_NAME" "$ROOT/$d"
done
install -d -m 0755 -o root -g root "$ROOT/libexec"
if [ -f "$ROOT/config/hhc-device-key.pem" ]; then
  chown "$USER_NAME:$GROUP_NAME" "$ROOT/config/hhc-device-key.pem"
  chmod 0600 "$ROOT/config/hhc-device-key.pem"
fi
RUNTIME=(launcher.mjs singleton.mjs gui-launch.mjs browser-adapter.mjs egress-policy.mjs client.mjs ws-client.mjs structured-ops.mjs mutation-ops.mjs host-policy.mjs device-proof.mjs lifecycle.mjs updater.mjs hhc-paths.mjs privileged-helper-contract.mjs privileged-helper-core.mjs privileged-helper-ipc.mjs linux-peer-credentials.mjs privileged-helper-linux-daemon.mjs privileged-helper-linux-operations.mjs privileged-helper-bootstrap.mjs privileged-helper-client.mjs privileged-helper-linux-readiness.mjs package.json)
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

# Provision the optional Linux privileged-helper peer-credential broker.
# Base-agent installation must not depend on a compiler. If the helper cannot be
# built, it is disabled fail-closed and privileged_shell_exec is not advertised.
HELPER_READY=0
CC_BIN="$(command -v cc || command -v gcc || command -v clang || true)"
PEERCRED_SRC="$SRC/native/linux-peercred.c"
PEERCRED_TMP="$ROOT/tmp/hhc-linux-peercred-$STAMP"
if [ -n "$CC_BIN" ] && [ -f "$PEERCRED_SRC" ]; then
  if "$CC_BIN" -O2 -Wall -Wextra -Werror -o "$PEERCRED_TMP" "$PEERCRED_SRC"; then
    install -m 0755 -o root -g root "$PEERCRED_TMP" "$ROOT/libexec/hhc-linux-peercred"
    HELPER_READY=1
  else
    echo 'Warning: HHC privileged helper peer-credential broker build failed; helper disabled.' >&2
  fi
else
  echo 'Warning: no C compiler or peer-credential source; HHC privileged helper disabled.' >&2
fi
rm -f "$PEERCRED_TMP"

ENV_DST="$ROOT/config/hhc-client.env"
ENV_SRC=''
for p in "$ENV_DST" "$SRC/client.env" /etc/hhc/hhc-client.env; do
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
migrate_one "$ROOT/data/client-state.json" "$SRC/state.json"
migrate_one "$ROOT/logs/client.log" "$SRC/client.log"
migrate_one "$ROOT/logs/audit.jsonl" "$SRC/audit.jsonl"
chown -R "$USER_NAME:$GROUP_NAME" "$ROOT/config" "$ROOT/data" "$ROOT/logs" "$ROOT/releases" "$ROOT/backups" "$ROOT/tmp"
HELPER_SOCKET=/etc/systemd/system/hhc-privileged-helper.socket
HELPER_SERVICE=/etc/systemd/system/hhc-privileged-helper.service
HELPER_TMPFILES=/etc/tmpfiles.d/hhc-privileged-helper.conf
if [ "$HELPER_READY" -eq 1 ]; then
  PUBLIC_KEY="$ROOT/config/privileged-helper-public.pem"
  "$NODE_BIN" "$SRC/privileged-helper-bootstrap.mjs" "$ENV_DST" "$ROOT/config/hhc-device-key.pem" "$PUBLIC_KEY" >/dev/null
  chown root:root "$PUBLIC_KEY"
  chmod 0644 "$PUBLIC_KEY"
  SERVICE_UID="$(id -u "$USER_NAME")"
  SERVICE_GID="$(id -g "$USER_NAME")"
  CLIENT_ID_VALUE="$(awk -F= '$1=="HHC_CLIENT_ID"{print substr($0,index($0,"=")+1);exit}' "$ENV_DST")"
  printf '{"client_id":"%s","service_gid":%s,"service_uid":%s}\n' "$CLIENT_ID_VALUE" "$SERVICE_GID" "$SERVICE_UID" > "$ROOT/tmp/privileged-helper.json"
  install -m 0600 -o root -g root "$ROOT/tmp/privileged-helper.json" "$ROOT/config/privileged-helper.json"
  rm -f "$ROOT/tmp/privileged-helper.json"
  sed "s#@HHC_SERVICE_GROUP@#$GROUP_NAME#g" "$SRC/install/hhc-privileged-helper-linux.socket.in" > "$ROOT/tmp/hhc-privileged-helper.socket"
  install -m 0644 -o root -g root "$ROOT/tmp/hhc-privileged-helper.socket" "$HELPER_SOCKET"
  rm -f "$ROOT/tmp/hhc-privileged-helper.socket"
  sed "s#@NODE_BIN@#$NODE_BIN#g" "$SRC/install/hhc-privileged-helper-linux.service.in" > "$ROOT/tmp/hhc-privileged-helper.service"
  install -m 0644 -o root -g root "$ROOT/tmp/hhc-privileged-helper.service" "$HELPER_SERVICE"
  rm -f "$ROOT/tmp/hhc-privileged-helper.service"
  sed "s#@HHC_SERVICE_GROUP@#$GROUP_NAME#g" "$SRC/install/hhc-privileged-helper-tmpfiles.in" > "$ROOT/tmp/hhc-privileged-helper.conf"
  install -m 0644 -o root -g root "$ROOT/tmp/hhc-privileged-helper.conf" "$HELPER_TMPFILES"
  rm -f "$ROOT/tmp/hhc-privileged-helper.conf"
  systemd-tmpfiles --create "$HELPER_TMPFILES"
  # A running daemon holds the install-time identity in memory; stop it so the
  # next socket-activated spawn reloads the freshly written config. No-op on
  # fresh installs where the service is not running yet.
  systemctl stop hhc-privileged-helper.service >/dev/null 2>&1 || true
else
  systemctl disable --now hhc-privileged-helper.socket hhc-privileged-helper.service >/dev/null 2>&1 || true
  rm -f "$HELPER_SOCKET" "$HELPER_SERVICE" "$HELPER_TMPFILES" "$ROOT/libexec/hhc-linux-peercred"
fi
cat > "$UNIT" <<EOF
[Unit]
Description=HHC Client
After=network-online.target
Wants=network-online.target
ConditionPathExists=!$ROOT/data/retired.json

[Service]
Type=simple
User=$USER_NAME
Group=$GROUP_NAME
WorkingDirectory=$ROOT/app
ExecStart=$NODE_BIN $ROOT/app/launcher.mjs
Restart=always
RestartSec=5
SuccessExitStatus=75
RestartPreventExitStatus=75
TimeoutStopSec=10
UMask=0027
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"
systemctl daemon-reload
# Remove the obsolete pre-centralization local MCP unit only when it still points at the retired HHC source tree.
_retired_root="/$(printf work)$(printf space)"
_legacy_mcp_unit=/etc/systemd/system/hhc-mcp.service
if [ -f "$_legacy_mcp_unit" ] && grep -Fq "$_retired_root/hhc-mcp" "$_legacy_mcp_unit"; then
  systemctl disable --now hhc-mcp.service >/dev/null 2>&1 || true
  rm -f "$_legacy_mcp_unit"
  systemctl daemon-reload
fi
unset _retired_root _legacy_mcp_unit
rm -f "$ROOT/data/retired.json"
install -m 0700 -o root -g root "$SRC/install/uninstall-linux.sh" "$ROOT/uninstall.sh"
systemctl enable hhc-client.service
if [ "$HELPER_READY" -eq 1 ]; then
  systemctl enable --now hhc-privileged-helper.socket
fi
systemctl restart hhc-client.service
sleep 2
systemctl is-active --quiet hhc-client.service
printf 'HHC canonical install complete: %s\n' "$ROOT"
