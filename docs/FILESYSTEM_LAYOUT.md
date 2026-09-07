# HHC Agent Filesystem Layout

Canonical host roots:

- Linux/macOS: `/opt/hhc`
- Windows: `C:\\HHC`

Runtime is installed under `app`; mutable identity/config/data/logs/releases/backups/tmp remain outside the replaceable app tree. `HHC_ROOT` is not a user-configurable compatibility override.
