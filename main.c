#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <stdlib.h>

#include "pwmgr.h"

static int create_vault(const char *password){
    const char *home = getenv("HOME");
    char directory[4096];

    if (home == NULL || home[0] != '/') {
        fprintf(stderr, "HOME must contain an absolute path.\n");
        return -1;
    }

    int written = snprintf(directory, sizeof(directory), "%s/.pwmgr", home);
    if (written < 0 || (size_t)written >= sizeof(directory)) {
        fprintf(stderr, "Vault directory path is too long.\n");
        return -1;
    }

    if (storage_open(directory) != 0) {
        fprintf(stderr, "Could not open or lock the vault directory.\n");
        return -1;
    }

    unsigned char vault[VAULT_HEADER_SIZE + crypto_secretbox_MACBYTES] = {
        'P', 'M', 'C', '1'
    };
    unsigned char key[crypto_secretbox_KEYBYTES];
    const unsigned char empty[] = "";

    unsigned char *salt = vault + 4;
    unsigned char *nonce = salt + crypto_pwhash_SALTBYTES;
    unsigned char *ciphertext = vault + VAULT_HEADER_SIZE;

    randombytes_buf(salt, crypto_pwhash_SALTBYTES);

    int result = -1;
    if (derive_key(password, salt, key) != 0) {
        fprintf(stderr, "Could not derive the vault key.\n");
    } else if (encrypt_data(empty, 0, key, nonce,
                            ciphertext, crypto_secretbox_MACBYTES) != 0) {
        fprintf(stderr, "Could not encrypt the empty vault.\n");
    } else if (storage_save(vault, sizeof(vault), 1) != 0) {
        fprintf(stderr, "Could not create the vault. It may already exist.\n");
    } else {
        result = 0;
    }

    sodium_memzero(key, sizeof(key));
    storage_close();
    return result;
}

int main(int argc, char *argv[]){
    if (argc != 2){
        fprintf(stderr, "Usage: %s <init|list>\n", argv[0]);
        return 1;
    }

    if (sodium_init() < 0){
        fprintf(stderr, "Could not initialise libsodium.\n");
        return 1;
    }

    char password[MAX_PASSWORD_LENGTH + 1] = {0};
    char confirmation[MAX_PASSWORD_LENGTH + 1] = {0};
    int result = 1;

    if (strcmp(argv[1], "init") == 0){
        if (read_password("Choose a master password: ", password, sizeof(password)) != 0){
            fprintf(stderr, "Could not read password or input was invalid.\n");
        } else if (strlen(password) < MIN_MASTER_PASSWORD_LENGTH){
            fprintf(stderr, "Use at least %d characters.\n", MIN_MASTER_PASSWORD_LENGTH);
        } else if (read_password("Confirm master password: ", confirmation, sizeof(confirmation)) != 0){
            fprintf(stderr, "Could not read confirmation or input was invalid.\n");
        } else if (strcmp(password, confirmation) != 0){
            fprintf(stderr, "Passwords do not match.\n");
        } else if (create_vault(password) == 0) {
            puts("Vault created.");
            result = 0;
        }
    } else if (strcmp(argv[1], "list") == 0){
        if (read_password("Master password: ", password, sizeof(password)) != 0) {
            fprintf(stderr, "Could not read password or input was invalid.\n");
        } else {
            printf("Password read.\n");
            result = 0;
        }
    } else {
        fprintf(stderr, "Unknown command. Available commands: init, list.\n");
    }

    sodium_memzero(password, sizeof(password));
    sodium_memzero(confirmation, sizeof(confirmation));

    return result;
}

