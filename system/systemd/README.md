# systemd

These units provide an optional background WineWarden service.

## Hardening notes

The service unit applies explicit sandboxing (`NoNewPrivileges`, `ProtectSystem=strict`,
`PrivateTmp`, seccomp `SystemCallFilter=@system-service`, empty capability bounding set,
`MemoryDenyWriteExecute`, and `UMask=0077`).

`ProtectHome=read-only` is intentional: the daemon only needs to *read* executables under
`$HOME` to hash/scan them, while all writes (prefixes, stores, reports) go to the XDG
data/config directories. Prefix root locations under `$HOME` are only created by the CLI
running in the user session, not by the daemon. If you deploy prefixes under `$HOME`
and need the daemon to write there, relax this directive deliberately and document it.

The socket unit sets `SocketMode=0600` so only the owning user can connect to the
daemon IPC socket.
