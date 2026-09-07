#!/bin/bash
set -euo pipefail
ROOT=/opt/hhc
UNIT=/etc/systemd/system/hhc-client.service
[ "$(id -u)" -eq 0 ] || { echo 'root required' >&2; exit 1; }
[ "$ROOT" = "/opt/hhc" ] || { echo 'unexpected HHC root' >&2; exit 1; }

systemctl disable --now hhc-client.service >/dev/null 2>&1 || true
systemctl disable --now hhc-privileged-helper.socket >/dev/null 2>&1 || true
systemctl stop hhc-privileged-helper.service >/dev/null 2>&1 || true

_hhc_pids=''
for _proc in /proc/[0-9]*; do
  [ -r "$_proc/cmdline" ] || continue
  _cmd="$(tr '\0' ' ' < "$_proc/cmdline" 2>/dev/null || true)"
  case "$_cmd" in
    *"$ROOT/app/launcher.mjs"*|*"$ROOT/app/client.mjs"*)
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

rm -f "$UNIT" /etc/systemd/system/hhc-privileged-helper.socket /etc/systemd/system/hhc-privileged-helper.service /etc/tmpfiles.d/hhc-privileged-helper.conf
rm -f /run/hhc/privileged-helper-v1.sock 2>/dev/null || true
rmdir /run/hhc 2>/dev/null || true
systemctl daemon-reload
systemctl reset-failed hhc-client.service >/dev/null 2>&1 || true
rm -rf -- "$ROOT"

echo 'HHC client uninstalled from Linux. Dedicated service user/group are intentionally retained.'
