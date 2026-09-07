#!/bin/bash
set -euo pipefail
ROOT=/opt/hhc
PLIST=/Library/LaunchDaemons/com.hhc.client.plist
[ "$(id -u)" -eq 0 ] || { echo 'root required' >&2; exit 1; }
[ "$ROOT" = "/opt/hhc" ] || { echo 'unexpected HHC root' >&2; exit 1; }

launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
launchctl disable system/com.hhc.client >/dev/null 2>&1 || true

_hhc_pids=''
while IFS= read -r _line; do
  _pid="$(printf '%s\\n' "$_line" | awk '{print $1}')"
  _cmd="$(printf '%s\\n' "$_line" | cut -d' ' -f2-)"
  case "$_cmd" in
    *"$ROOT/app/launcher.mjs"*|*"$ROOT/app/client.mjs"*)
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

rm -f "$PLIST"
rm -rf -- "$ROOT"

echo 'HHC client uninstalled from macOS. The dedicated _hhc service identity is intentionally retained.'
