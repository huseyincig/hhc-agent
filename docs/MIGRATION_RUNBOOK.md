# HHC Agent Migration Runbook

A client migration must preserve the centrally generated client identity, device key, token material and mutable data. Installers stage a complete candidate app tree, syntax-check it, stop only HHC runtime processes, atomically replace the app tree, and retain a rollback copy. Published package and installer runtime-file sets must be identical.
