#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pwmgr.h"

int open_vault_directory(void)
{
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

    return 0;
}

static int valid_field(const char *text, size_t capacity)
{
    size_t length = 0;

    while (length < capacity && text[length] != '\0') {
        unsigned char ch = (unsigned char)text[length];

        if (ch < 32 || ch > 126) {
            return 0;
        }

        length++;
    }

    return length > 0 && length < capacity;
}

static int parse_entries(char *text, Vault *vault)
{
    char *line = text;

    while (*line != '\0') {
        if (vault->count >= MAX_ENTRIES) {
            return -1;
        }

        char *end = strchr(line, '\n');
        if (end == NULL) {
            return -1;
        }
        *end = '\0';

        char *username = strchr(line, '\t');
        if (username == NULL) {
            return -1;
        }
        *username = '\0';
        username++;

        char *password = strchr(username, '\t');
        if (password == NULL) {
            return -1;
        }
        *password = '\0';
        password++;

        Entry *entry = &vault->entries[vault->count];

        if (!valid_field(line, sizeof(entry->service)) ||
            !valid_field(username, sizeof(entry->username)) ||
            !valid_field(password, sizeof(entry->password))) {
            return -1;
        }

        memcpy(entry->service, line, strlen(line) + 1);
        memcpy(entry->username, username, strlen(username) + 1);
        memcpy(entry->password, password, strlen(password) + 1);

        vault->count++;
        line = end + 1;
    }

    return 0;
}

static int serialize_entries(const Vault *vault, unsigned char *text,
                             size_t capacity, size_t *length)
{
    *length = 0;

    if (vault->count > MAX_ENTRIES) {
        return -1;
    }

    for (size_t i = 0; i < vault->count; i++) {
        const Entry *entry = &vault->entries[i];

        if (!valid_field(entry->service, sizeof(entry->service)) ||
            !valid_field(entry->username, sizeof(entry->username)) ||
            !valid_field(entry->password, sizeof(entry->password))) {
            return -1;
        }

        size_t remaining = capacity - *length;

        int written = snprintf((char *)text + *length, remaining,
                               "%s\t%s\t%s\n",
                               entry->service,
                               entry->username,
                               entry->password);

        if (written < 0 || (size_t)written >= remaining) {
            return -1;
        }

        *length += (size_t)written;
    }

    return 0;
}

void vault_close(Vault *vault)
{
    sodium_memzero(vault, sizeof(*vault));
    storage_close();
}

int vault_open(const char *password, Vault *vault)
{
    unsigned char file_data[MAX_VAULT_SIZE];
    unsigned char plaintext[MAX_VAULT_SIZE + 1];
    size_t file_length = 0;
    int result = -1;

    sodium_memzero(vault, sizeof(*vault));

    if (open_vault_directory() != 0) {
        return -1;
    }

    int read_result = storage_read(file_data, sizeof(file_data), &file_length);

    if (read_result == 1) {
        fprintf(stderr, "No vault found. Run ./pwmgr init first.\n");
    } else if (read_result != 0) {
        fprintf(stderr, "Could not read the vault.\n");
    } else if (file_length < VAULT_HEADER_SIZE + crypto_secretbox_MACBYTES ||
               memcmp(file_data, "PMC1", 4) != 0) {
        fprintf(stderr, "Invalid vault format.\n");
    } else {
        memcpy(vault->salt, file_data + 4, sizeof(vault->salt));

        const unsigned char *nonce = file_data + 4 + crypto_pwhash_SALTBYTES;
        const unsigned char *ciphertext = file_data + VAULT_HEADER_SIZE;

        size_t ciphertext_length = file_length - VAULT_HEADER_SIZE;
        size_t plaintext_length = ciphertext_length - crypto_secretbox_MACBYTES;

        if (derive_key(password, vault->salt, vault->key) != 0) {
            fprintf(stderr, "Could not derive the vault key.\n");
        } else if (decrypt_data(ciphertext, ciphertext_length, vault->key,
                                nonce, plaintext, MAX_VAULT_SIZE) != 0) {
            fprintf(stderr, "Wrong master password or damaged vault.\n");
        } else if (memchr(plaintext, '\0', plaintext_length) != NULL) {
            fprintf(stderr, "Invalid credential data.\n");
        } else {
            plaintext[plaintext_length] = '\0';

            if (parse_entries((char *)plaintext, vault) != 0) {
                fprintf(stderr, "Invalid credential data.\n");
            } else {
                result = 0;
            }
        }
    }

    sodium_memzero(plaintext, sizeof(plaintext));

    if (result != 0) {
        vault_close(vault);
    }

    return result;
}

int vault_save(const Vault *vault)
{
    unsigned char plaintext[MAX_VAULT_SIZE];
    unsigned char file_data[MAX_VAULT_SIZE];
    size_t plaintext_length = 0;
    int result = -1;

    if (serialize_entries(vault, plaintext, sizeof(plaintext),
                          &plaintext_length) != 0) {
        fprintf(stderr, "Invalid entries or vault capacity exceeded.\n");
    } else {
        memcpy(file_data, "PMC1", 4);
        memcpy(file_data + 4, vault->salt, sizeof(vault->salt));

        unsigned char *nonce = file_data + 4 + crypto_pwhash_SALTBYTES;
        unsigned char *ciphertext = file_data + VAULT_HEADER_SIZE;

        if (encrypt_data(plaintext, plaintext_length, vault->key, nonce,
                         ciphertext, sizeof(file_data) - VAULT_HEADER_SIZE) != 0) {
            fprintf(stderr, "Could not encrypt the vault.\n");
        } else {
            size_t file_length = VAULT_HEADER_SIZE +
                                 crypto_secretbox_MACBYTES + plaintext_length;

            if (storage_save(file_data, file_length, 0) != 0) {
                fprintf(stderr, "Could not save the vault.\n");
            } else {
                result = 0;
            }
        }
    }

    sodium_memzero(plaintext, sizeof(plaintext));
    return result;
}

static int create_vault(const char *password){
        if (open_vault_directory() != 0) {
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

static int list_vault(const char *password)
{
    Vault vault;

    if (vault_open(password, &vault) != 0) {
        return -1;
    }

    if (vault.count == 0) {
        puts("Vault is empty.");
    } else {
        for (size_t i = 0; i < vault.count; i++) {
            printf("%s\n", vault.entries[i].service);
        }
    }

    vault_close(&vault);
    return 0;
}

static int add_entry(const char *password)
{
    Vault vault;

    if (vault_open(password, &vault) != 0) {
        return -1;
    }

    if (vault.count >= MAX_ENTRIES) {
        fprintf(stderr, "The vault is full.\n");
        vault_close(&vault);
        return -1;
    }

    Entry *entry = &vault.entries[vault.count];

    if (read_entry(entry) != 0) {
        vault_close(&vault);
        return -1;
    }

    for (size_t i = 0; i < vault.count; i++) {
        if (strcmp(vault.entries[i].service, entry->service) == 0) {
            fprintf(stderr, "An entry for this service already exists.\n");
            vault_close(&vault);
            return -1;
        }
    }

    vault.count++;

    int result = vault_save(&vault);
    vault_close(&vault);

    if (result == 0) {
        puts("Entry added.");
    }

    return result;
}

int main(int argc, char *argv[]){
    if (argc != 2){
        fprintf(stderr, "Usage: %s <init|list|add>\n", argv[0]);
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
        } else if (list_vault(password) == 0) {
            result = 0;
        }
    } else if (strcmp(argv[1], "add") == 0) {
        if (read_password("Master password: ", password,
                          sizeof(password)) != 0) {
            fprintf(stderr, "Could not read password or input was invalid.\n");
        } else if (add_entry(password) == 0) {
            result = 0;
        }
    } else {
        fprintf(stderr, "Unknown command. Available commands: init, add, list.\n");
    }

    sodium_memzero(password, sizeof(password));
    sodium_memzero(confirmation, sizeof(confirmation));

    return result;
}

