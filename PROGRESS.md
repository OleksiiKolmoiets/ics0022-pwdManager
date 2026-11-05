# Checkpoint 2 Progress Note

The password manager is implemented in C using the original four modules: `main.c`, `auth.c`, `crypto.c` and `storage.c`, with shared declarations in `pwmgr.h`.

## Implemented

- `init` creates an encrypted empty vault and refuses to overwrite an existing one.
- `add`, `list`, `get` and `delete` verify the master password before accessing records. Duplicate service names are rejected, and deletion requires `yes` confirmation.
- Credentials use Argon2id-derived keys and libsodium secretbox encryption. Every save generates a fresh nonce.
- The private vault directory and file use `0700` and `0600` permissions. Storage checks ownership and file types, holds a lock during record operations, and saves through temporary files.
- Input is bounded, passwords are entered invisibly, and sensitive buffers are cleared after use.

## Current limitation and next work

`get` currently displays the username and a fixed password mask. It cannot yet return a usable password. Clipboard retrieval is planned for Checkpoint 3, with clipboard history, synchronization and secret lifetime considered in the security analysis.

Checkpoint 3 will also complete memory-handling checks, validation, structured logging, record-access checks, expanded tests and the draft report.
