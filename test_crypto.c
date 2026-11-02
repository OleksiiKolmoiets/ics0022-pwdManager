#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "pwmgr.h"

int main(void)
{
    assert(sodium_init() >= 0);

    const unsigned char original[] = "example-service\tstudent\ttest-password\n";
    const size_t length = sizeof(original) - 1;

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char wrong_key[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    unsigned char encrypted[sizeof(original) - 1 + crypto_secretbox_MACBYTES];
    unsigned char decrypted[sizeof(original) - 1];

    randombytes_buf(salt, sizeof(salt));

    assert(derive_key("student-test-123", salt, key) == 0);
    assert(derive_key("different-password", salt, wrong_key) == 0);

    assert(encrypt_data(original, length, key, nonce,
                        encrypted, sizeof(encrypted)) == 0);

    assert(decrypt_data(encrypted, sizeof(encrypted), key, nonce,
                        decrypted, sizeof(decrypted)) == 0);
    assert(memcmp(original, decrypted, length) == 0);
    puts("Encryption and decryption: OK");

    assert(decrypt_data(encrypted, sizeof(encrypted), wrong_key, nonce,
                        decrypted, sizeof(decrypted)) == -1);
    puts("Wrong password rejected: OK");

    encrypted[0] ^= 1;

    assert(decrypt_data(encrypted, sizeof(encrypted), key, nonce,
                        decrypted, sizeof(decrypted)) == -1);
    puts("Modified data rejected: OK");

    sodium_memzero(key, sizeof(key));
    sodium_memzero(wrong_key, sizeof(wrong_key));
    sodium_memzero(decrypted, sizeof(decrypted));

    return 0;
}