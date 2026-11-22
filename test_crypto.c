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
    assert(sodium_is_zero(decrypted, sizeof(decrypted)) == 1);
    puts("Wrong password rejected: OK");

    memset(decrypted, 0xAA, sizeof(decrypted));
    encrypted[0] ^= 1;

    assert(decrypt_data(encrypted, sizeof(encrypted), key, nonce,
                        decrypted, sizeof(decrypted)) == -1);
    assert(sodium_is_zero(decrypted, sizeof(decrypted)) == 1);
    puts("Modified data rejected: OK");

    encrypted[0] ^= 1; /* Restore the valid ciphertext. */

    memset(decrypted, 0xAA, sizeof(decrypted));
    assert(decrypt_data(encrypted, crypto_secretbox_MACBYTES - 1,
                        key, nonce, decrypted, sizeof(decrypted)) == -1);
    assert(sodium_is_zero(decrypted, sizeof(decrypted)) == 1);
    puts("Truncated ciphertext rejected and output cleared: OK");

    unsigned char small_output[sizeof(decrypted) - 1];
    memset(small_output, 0xAA, sizeof(small_output));

    assert(decrypt_data(encrypted, sizeof(encrypted), key, nonce,
                        small_output, sizeof(small_output)) == -1);
    assert(sodium_is_zero(small_output, sizeof(small_output)) == 1);

    assert(encrypt_data(original, length, key, nonce,
                        encrypted, sizeof(encrypted) - 1) == -1);
    puts("Small output buffers rejected: OK");

    unsigned char next_nonce[crypto_secretbox_NONCEBYTES];
    unsigned char next_encrypted[sizeof(encrypted)];

    assert(encrypt_data(original, length, key, next_nonce,
                        next_encrypted, sizeof(next_encrypted)) == 0);
    assert(memcmp(nonce, next_nonce, sizeof(nonce)) != 0);

    assert(decrypt_data(next_encrypted, sizeof(next_encrypted), key,
                        next_nonce, decrypted, sizeof(decrypted)) == 0);
    assert(memcmp(original, decrypted, length) == 0);
    puts("Fresh nonce and repeat decryption: OK");

    unsigned char empty_ciphertext[crypto_secretbox_MACBYTES];
    unsigned char empty_nonce[crypto_secretbox_NONCEBYTES];
    unsigned char empty_output[1] = {0};

    assert(encrypt_data((const unsigned char *)"", 0, key, empty_nonce,
                        empty_ciphertext, sizeof(empty_ciphertext)) == 0);
    assert(decrypt_data(empty_ciphertext, sizeof(empty_ciphertext), key,
                        empty_nonce, empty_output, sizeof(empty_output)) == 0);
    puts("Empty vault encryption and decryption: OK");

    sodium_memzero(key, sizeof(key));
    sodium_memzero(wrong_key, sizeof(wrong_key));
    sodium_memzero(decrypted, sizeof(decrypted));

    return 0;
}