#ifndef PWMGR_H
#define PWMGR_H

#include <stddef.h>
#include <sodium.h>

#define MAX_PASSWORD_LENGTH 128
#define MIN_MASTER_PASSWORD_LENGTH 12

#define KDF_OPSLIMIT 3
#define KDF_MEMLIMIT (64U * 1024U * 1024U)

#define MAX_VAULT_SIZE (64U * 1024U)

#define VAULT_HEADER_SIZE (4 + crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES)

#define MAX_SERVICE_LENGTH 64
#define MAX_USERNAME_LENGTH 128
#define MAX_ENTRIES 100

typedef struct {
    char service[MAX_SERVICE_LENGTH + 1];
    char username[MAX_USERNAME_LENGTH + 1];
    char password[MAX_PASSWORD_LENGTH + 1];
} Entry;

typedef struct {
    Entry entries[MAX_ENTRIES];
    size_t count;
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];
} Vault;

int storage_open(const char *directory);
void storage_close(void);

int storage_read(unsigned char *data, size_t capacity, size_t *length);

int storage_save(const unsigned char *data, size_t length, int create_only);

int read_password(const char *prompt, char *password, size_t size);

int derive_key(const char *password, const unsigned char *salt,
               unsigned char *key);

int encrypt_data(const unsigned char *plaintext, size_t plaintext_len,
                 const unsigned char *key, unsigned char *nonce,
                 unsigned char *ciphertext, size_t ciphertext_size);

int decrypt_data(const unsigned char *ciphertext, size_t ciphertext_len,
                 const unsigned char *key, const unsigned char *nonce,
                 unsigned char *plaintext, size_t plaintext_size);

int read_text(const char *prompt, char *buffer, size_t size);
int read_entry(Entry *entry);                 

int open_vault_directory(void);

int vault_open(const char *password, Vault *vault);
int vault_save(const Vault *vault);
void vault_close(Vault *vault);

#endif