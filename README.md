# Password Manager — Checkpoint 2

## Project idea

This is a small command-line password manager in C for Linux. It stores service names, usernames and passwords in one encrypted file. The user unlocks the file with a master password.
The program supports one local user and five commands: `init`, `add`, `list`, `get` and `delete`. It has no server, website or separate account registration.

## Manual

`init` - creates an empty encrypted vault. It asks the user for a master password and confirmation. It must refuse to overwrite an existing vault.

`add` - asks for the master password, service name, username and password. It rejects duplicate service names, then encrypts and saves the updated vault.

`list` - unlocks the vault and lists service names only.

`get` - unlocks the vault and asks for a service name. It currently displays the service, username and a fixed password mask (`********`). It does not reveal or copy the stored password. Clipboard retrieval is planned for Checkpoint 3 so that passwords can be used without printing them in cleartext.

`delete` - unlocks the vault and asks for a service name. It removes the entry only after the user types exactly `yes`, then encrypts and saves the updated vault. Other answers cancel deletion. Deleting the final entry leaves a valid empty vault.

## Current limits

- Up to 100 entries and a vault file up to 64 KiB.
- Service names up to 64 characters, usernames up to 128, and passwords up to 128.
- Each field must be nonempty and contain printable ASCII characters. Spaces are allowed. Tabs, newlines and other control characters are rejected within fields.
- Service names are case-sensitive. `Email` and `email` are distinct names.
- `get` is currently a masked lookup. Usable password retrieval through the clipboard is remaining work for Checkpoint 3.

## Architecture

### 1. User-management module `auth.c`

The password manager has only one local user; thus, registration, usernames, roles or an account database are not required.

It:
- Reads master and credential passwords without showing them in the terminal.
- Reads visible service names and usernames through bounded input.
- Rejects empty, overlong and non-printable-ASCII input.
- Collects the fields of a new credential entry.

The command code in `main.c` requests master-password confirmation during `init` and enforces a minimum master-password length of 12 characters.

### 2. Encryption module `crypto.c`

This module turns readable entries into encrypted data and converts them back when the correct master password is provided.

It has two main jobs:
- Key derivation: the module uses Argon2id to turn the master password and salt into an encryption key.
- Encryption and decryption: the module uses the libsodium library to encrypt the entries or verify and decrypt an existing vault.

The salt is saved alongside the encrypted data.

Every encryption operation generates a fresh random nonce. Unlocking derives the key again using the saved salt. Successful authenticated decryption verifies the entered master password.

### 3. Storage layer `storage.c`

This module handles the files on disk.

It:

- Creates the private directory and vault file.
- Reads the encrypted vault into memory.
- Saves updated encrypted data.
- Checks ownership, permissions, file type, hard-link count and file-operation errors.
- Holds an exclusive lock during each record operation so cooperating program instances cannot overwrite each other’s changes.

The vault location is `~/.pwmgr/vault.pmv`. The directory uses `0700` permissions and the vault uses `0600`. A separate `vault.lock` file coordinates access. Unsafe ownership, permissions or file types are rejected.

The storage layer only receives encrypted bytes and writes them or reads encrypted bytes and returns them.

To avoid overwriting the existing file, it writes the new encrypted data to a temporary file in the same directory, synchronizes it to disk, and then replaces the old vault.

### 4. Main module `main.c`

`main.c` connects the modules and implements the commands. It represents credentials using `Entry` and `Vault`, parses decrypted records, serializes updated records, and coordinates authentication, encryption and storage. Shared types and function declarations are in `pwmgr.h`.

### Data Flow

![Data Flow](Data%20Flow.png)


## Threat model

| # | Area | Risk | Intended mitigation |
|---|---|---|---|
| 1 | Master password | A weak master password can be guessed or brute-forced. | Require a long passphrase and use Argon2id with a random salt to make guessing more expensive. |
| 2 | Master password | The master password appears in shell history or logs. | Read it through a hidden prompt, never as a command-line argument. Never log passwords. |
| 3 | Vault at rest | Incorrect file permissions allow someone to read or modify the vault. | Use file permissions `0600` and verify ownership. Encrypt credentials and use authenticated encryption to detect tampering. |
| 4 | Vault at rest | Incorrect directory permissions allow someone to delete the vault. | Use directory permissions `0700` and verify ownership. Deletion is controlled by the containing directory’s permissions, not the file’s permissions alone. |
| 5 | Vault at rest | A symlink or a file changed between checking and opening redirects access. | Use a private directory, reject symlinks and check the opened file using `fstat()`. Avoid checking a pathname and then reopening it. |
| 6 | Vault in memory | Credentials remain in memory after use. | Minimize their lifetime and unnecessary copies. Clear sensitive buffers with `sodium_memzero()` before freeing them or exiting. |
| 7 | Vault in memory | A buffer overflow exposes or corrupts sensitive memory. | Use bounded input, check buffer sizes before copying data, reserve space for null terminators and validate array indexes. |
| 8 | Vault in memory | Incorrect memory handling causes invalid access or crashes. | Initialize pointers, check allocation results, free memory exactly once and never access freed memory. |
| 9 | Interface | Output accidentally exposes passwords. | Make `list` show service names only and `get` show the username with a fixed password mask. Add explicit clipboard retrieval in Checkpoint 3. |
| 10 | Interface | Special characters manipulate terminal output or break the file format. | Accept printable ASCII characters only. Reject tabs, newlines and control characters. Use fixed output formats such as `printf("%s", value)`. |
| 11 | Interface | An error message reveals sensitive data. | Use fixed error messages without passwords, keys or decrypted contents, such as “Wrong master password or damaged vault.” |

## Vault Format

Each entry contains three fields: service name, username and password.

Before encryption, each entry will be represented as fields separated with TABs: `<Service name><TAB><Username><TAB><Password><NEWLINE>`.

NEWLINE is used as an entry separator.

This readable text exists only temporarily in memory. It is encrypted before being written to disk.

### Cryptographic scheme

The application uses libsodium for key derivation, encryption and random-value generation.

| Component | Decision |
|---|---|
| Symmetric encryption | XSalsa20-Poly1305 through `crypto_secretbox_easy()` |
| Key derivation | Argon2id through `crypto_pwhash()` |
| Argon2id settings | `crypto_pwhash_ALG_ARGON2ID13`, operation limit 3, memory limit 64 MiB |
| Encryption key | 32 bytes, derived from the master password and salt |
| Salt | 16 random bytes, generated when creating the vault |
| Nonce | 24 fresh random bytes for every save; must never repeat with the same key |
| Authentication tag | 16 bytes, used to detect tampering or an incorrect key |

The master password and derived key will never be stored on disk. The salt and nonce are public and will be saved with the encrypted data.

### Vault file layout

| Part, in order | Size | Purpose |
|---|---|---|
| Format marker: `PMC1` | 4 bytes | Identifies the supported format and its fixed cryptographic settings |
| Salt | 16 bytes | Allows the key to be derived again |
| Nonce | 24 bytes | Required for decryption |
| Authentication tag | 16 bytes | Allows verification of the encrypted data |
| Ciphertext | Variable | Contains all encrypted entries |

Libsodium produces the authentication tag and ciphertext together. The program will reject an unknown format marker or an invalid file length.

## Build and run

Build and run the program from the repository directory. Use the five commands below through an interactive terminal.

### Requirements

The target platform is Linux, with GCC and the libsodium development library. On Ubuntu or Debian, install the dependencies with:

```bash
sudo apt update
sudo apt install build-essential libsodium-dev
```

On Windows, use a Linux environment such as Ubuntu in WSL for these commands.

### Build

From the repository directory containing `main.c`, `auth.c`, `crypto.c` and `storage.c`, run:

```bash
gcc -std=c11 -Wall -Wextra -Wpedantic -Werror=return-type \
    main.c auth.c crypto.c storage.c -lsodium -o pwmgr
```

This will create an executable named `pwmgr`.

### Run

Run the program as your normal user:

```bash
./pwmgr init
./pwmgr add
./pwmgr list
./pwmgr get
./pwmgr delete
```

Use `init` once to create `~/.pwmgr/vault.pmv`. Each later command will ask for the master password. Entry details will be entered through prompts.

## Use of AI

I used AI to learn more about cryptography concepts that I was less familiar with and to consult on the architecture and data flow of the program.
