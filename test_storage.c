#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pwmgr.h"

int main(void)
{
    assert(sodium_init() >= 0);

    char directory[] = "/tmp/pwmgr-storage-XXXXXX";
    assert(mkdtemp(directory) != NULL);

    unsigned char saved[VAULT_HEADER_SIZE + crypto_secretbox_MACBYTES] = {
        'P', 'M', 'C', '1'
    };
    unsigned char loaded[sizeof(saved)];
    unsigned char key[crypto_secretbox_KEYBYTES];
    size_t length;

    unsigned char *salt = saved + 4;
    unsigned char *nonce = salt + crypto_pwhash_SALTBYTES;
    unsigned char *ciphertext = saved + VAULT_HEADER_SIZE;

    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
    assert(derive_key("student-test-123", salt, key) == 0);

    assert(encrypt_data((const unsigned char *)"", 0, key, nonce,
                        ciphertext, crypto_secretbox_MACBYTES) == 0);

    assert(storage_open(directory) == 0);
    assert(storage_read(loaded, sizeof(loaded), &length) == 1);

    assert(storage_save(saved, sizeof(saved), 1) == 0);
    assert(storage_save(saved, sizeof(saved), 1) == -1);
    puts("Vault created; duplicate creation rejected: OK");

    assert(storage_read(loaded, sizeof(loaded), &length) == 0);
    assert(length == sizeof(saved));
    assert(memcmp(saved, loaded, length) == 0);
    puts("Stored bytes read correctly: OK");

    assert(encrypt_data((const unsigned char *)"", 0, key, nonce,
                        ciphertext, crypto_secretbox_MACBYTES) == 0);
    assert(storage_save(saved, sizeof(saved), 0) == 0);
    storage_close();

    assert(storage_open(directory) == 0);
    assert(storage_read(loaded, sizeof(loaded), &length) == 0);
    assert(length == sizeof(saved));
    assert(memcmp(saved, loaded, length) == 0);
    storage_close();
    puts("Updated vault persists after reopening: OK");

    sodium_memzero(key, sizeof(key));

    char path[sizeof(directory) + 20];
    snprintf(path, sizeof(path), "%s/vault.pmv", directory);
    assert(unlink(path) == 0);
    snprintf(path, sizeof(path), "%s/vault.lock", directory);
    assert(unlink(path) == 0);
    assert(rmdir(directory) == 0);

    return 0;
}