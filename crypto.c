#include <string.h>

#include "pwmgr.h"

int derive_key(const char *password, const unsigned char *salt, unsigned char *key){
    return crypto_pwhash(key, crypto_secretbox_KEYBYTES, password, strlen(password), salt, KDF_OPSLIMIT, KDF_MEMLIMIT, crypto_pwhash_ALG_ARGON2ID13);
}

int encrypt_data(const unsigned char *plaintext, size_t plaintext_len, const unsigned char *key, unsigned char *nonce, unsigned char *ciphertext, size_t ciphertext_size){
    if (ciphertext_size < crypto_secretbox_MACBYTES || plaintext_len > ciphertext_size - crypto_secretbox_MACBYTES) {
        return -1;
    }

    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    return crypto_secretbox_easy(ciphertext, plaintext, plaintext_len, nonce, key);
}

int decrypt_data(const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key, const unsigned char *nonce, unsigned char *plaintext, size_t plaintext_size){
    if (ciphertext_len < crypto_secretbox_MACBYTES || ciphertext_len - crypto_secretbox_MACBYTES > plaintext_size) {
        return -1;
    }

    return crypto_secretbox_open_easy(plaintext, ciphertext, ciphertext_len, nonce, key);
}