# Password Manager — Checkpoint 1

## Project idea

I will build a small command-line password manager in C for Linux. It will store service names, usernames and passwords in one encrypted file. The user will unlock the file with a master password.
The program will support one local user and five commands: `init`, `add`, `list`, `get` and `delete`. There will be no server, website or separate account registration.

## Manual

`init` - creates an empty encrypted vault. It asks the user for a master password and confirmation. It must refuse to overwrite an existing vault.

`add` - adds a record with a service name, username and password. It then encrypts and saves the updated vault.

`list` - lists service names without showing any credentials.

`get` - displays the username and password for a selected service.

`delete` - removes a selected record of a service from the file after confirmation. It then saves the updated vault.

## Architecture

### 1. User-management module `auth.c`

The password manager has only one local user; thus, registration, usernames, roles or an account database are not required.

It will:
- During init, ask the user to choose a master password and enter it again for confirmation.
- During later commands, ask for the existing master password.
- Read the password without showing it in the terminal.
- Check input length and reject input that is too long.

### 2. Encryption module `crypto.c`

This module turns readable entries into encrypted data and converts them back when the correct master password is provided.

It has 2 main jobs:
- Key derivation: the module uses Argon2id to turn the master password and salt into an encryption key.
- Encryption and decryption: the module uses the libsodium library to encrypt the entries or verify and decrypt an existing vault.

The salt is saved alongside the encrypted data.

When adding a new record, this module also generates a random nonce needed by the encryption operation.

### 3. Storage layer `storage.c`

This module handles the files on disk.

It will:

- Create the private directory and vault file.
- Read the encrypted vault into memory.
- Save updated encrypted data.
- Check permissions, file type and file-operation errors.
- Coordinate access so two running copies do not overwrite each other’s changes.

The planned location will be `~/.pwmgr/vault.pmv`.

The directory will have `0700` permissions and the vault will have `0600`.

The storage layer only receives encrypted bytes and writes them or reads encrypted bytes and returns them.

To avoid overwriting the existing file, it writes the new encrypted data to a temporary file in the same directory, synchronizes it to disk, and then replaces the old vault.

### 4. Main module `main.c`

main.c connects the previously described modules and implements the commands. The individual modules provide the functions; main.c calls them in the correct order.

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
| 9 | Interface | Listing entries accidentally exposes credentials. | Make `list` show service names only. Require an explicit `get` operation and confirmation before displaying a password. |
| 10 | Interface | Special characters manipulate terminal output or break the file format. | Accept printable ASCII characters only. Reject tabs, newlines and control characters. Use fixed output formats such as `printf("%s", value)`. |
| 11 | Interface | An error message reveals sensitive data. | Use fixed error messages without passwords, keys or decrypted contents, such as “Wrong master password or damaged vault.” |

## Vault Format

Each entry contains three fields: service name, username and password.

Before encryption, each entry will be represented as fields separated with TABs: `<Service name><TAB><Username><TAB><Password><NEWLINE>`.

NEWLINE is used as an entry separator.

This readable text exists only temporarily in memory. It is encrypted before being written to disk.

### Cryptographic scheme

The application will use libsodium for key derivation, encryption and random-value generation.

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

The C source files have not been implemented yet. These commands describe how the program will be built and run after implementation.

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
gcc -std=c11 -Wall -Wextra -Wpedantic main.c auth.c crypto.c storage.c -lsodium -o pwmgr
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
