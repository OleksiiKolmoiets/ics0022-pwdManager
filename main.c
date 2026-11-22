#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "pwmgr.h"

extern char **environ;

static int copy_to_clipboard(const char *password);

int open_vault_directory(void)
{
    const char *home = getenv("HOME");
    char directory[4096];

    if (home == NULL || home[0] != '/') {
        fprintf(stderr, "Could not access the vault.\n");
        return -1;
    }

    int written = snprintf(directory, sizeof(directory), "%s/.pwmgr", home);

    if (written < 0 || (size_t)written >= sizeof(directory)) {
        fprintf(stderr, "Could not access the vault.\n");
        return -1;
    }

    if (storage_open(directory) != 0) {
        fprintf(stderr, "Could not access the vault.\n");
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

        for (size_t i = 0; i < vault->count; i++) {
            if (strcmp(vault->entries[i].service, line) == 0) {
                return -1;
            }
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
        fprintf(stderr, "Could not unlock the vault.\n");
    } else if (read_result != 0) {
        fprintf(stderr, "Could not unlock the vault.\n");
    } else if (file_length < VAULT_HEADER_SIZE + crypto_secretbox_MACBYTES ||
               memcmp(file_data, "PMC1", 4) != 0) {
        fprintf(stderr, "Could not unlock the vault.\n");
    } else {
        memcpy(vault->salt, file_data + 4, sizeof(vault->salt));

        const unsigned char *nonce = file_data + 4 + crypto_pwhash_SALTBYTES;
        const unsigned char *ciphertext = file_data + VAULT_HEADER_SIZE;

        size_t ciphertext_length = file_length - VAULT_HEADER_SIZE;
        size_t plaintext_length = ciphertext_length - crypto_secretbox_MACBYTES;

        if (derive_key(password, vault->salt, vault->key) != 0) {
            fprintf(stderr, "Could not unlock the vault.\n");
        } else if (decrypt_data(ciphertext, ciphertext_length, vault->key,
                                nonce, plaintext, MAX_VAULT_SIZE) != 0) {
            log_event("authentication", "failure");
            fprintf(stderr, "Could not unlock the vault.\n");
        } else if (memchr(plaintext, '\0', plaintext_length) != NULL) {
            fprintf(stderr, "Could not unlock the vault.\n");
        } else {
            plaintext[plaintext_length] = '\0';

            if (parse_entries((char *)plaintext, vault) != 0) {
                fprintf(stderr, "Could not unlock the vault.\n");
            } else {
                log_event("authentication", "success");
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
        fprintf(stderr, "Could not save the vault.\n");
    } else {
        memcpy(file_data, "PMC1", 4);
        memcpy(file_data + 4, vault->salt, sizeof(vault->salt));

        unsigned char *nonce = file_data + 4 + crypto_pwhash_SALTBYTES;
        unsigned char *ciphertext = file_data + VAULT_HEADER_SIZE;

        if (encrypt_data(plaintext, plaintext_length, vault->key, nonce,
                         ciphertext, sizeof(file_data) - VAULT_HEADER_SIZE) != 0) {
            fprintf(stderr, "Could not save the vault.\n");
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
        fprintf(stderr, "Could not create the vault.\n");
    } else if (encrypt_data(empty, 0, key, nonce,
                            ciphertext, crypto_secretbox_MACBYTES) != 0) {
        fprintf(stderr, "Could not create the vault.\n");
    } else if (storage_save(vault, sizeof(vault), 1) != 0) {
        fprintf(stderr, "Could not create the vault.\n");
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

static int get_entry(const char *password)
{
    Vault vault;

    if (vault_open(password, &vault) != 0) {
        return -1;
    }

    char service[MAX_SERVICE_LENGTH + 1];

    if (read_text("Service: ", service, sizeof(service)) != 0) {
        fprintf(stderr, "Invalid service name.\n");
        vault_close(&vault);
        return -1;
    }

    for (size_t i = 0; i < vault.count; i++) {
        if (strcmp(vault.entries[i].service, service) == 0) {
            printf("Service: %s\n", vault.entries[i].service);
            printf("Username: %s\n", vault.entries[i].username);

            int result = copy_to_clipboard(vault.entries[i].password);

            vault_close(&vault);

            if (result != 0) {
                fprintf(stderr,
                        "Could not copy the password to the clipboard.\n");
                return -1;
            }

            puts("Password copied to the clipboard. "
                 "Paste it, then clear the clipboard.");
            return 0;
        }
    }

    fprintf(stderr, "No entry found for this service.\n");
    vault_close(&vault);
    return -1;
}

static int copy_to_clipboard(const char *password)
{
    int fds[2];

    if (!valid_field(password, MAX_PASSWORD_LENGTH + 1) || pipe(fds) != 0) {
        return -1;
    }
    
    size_t length = strlen(password);
    ssize_t written;

    do {
        written = write(fds[1], password, length);
    } while (written < 0 && errno == EINTR);

    int closed = close(fds[1]);

    if (written < 0 || (size_t)written != length || closed != 0) {
        close(fds[0]);
        return -1;
    }

    posix_spawn_file_actions_t actions;

    if (posix_spawn_file_actions_init(&actions) != 0) {
        close(fds[0]);
        return -1;
    }

    pid_t child;
    char *const arguments[] = {
        "xclip", "-selection", "clipboard", "-in", NULL
    };
    int result = -1;

    if (posix_spawn_file_actions_adddup2(
            &actions, fds[0], STDIN_FILENO) == 0 &&
        posix_spawn_file_actions_addclose(
            &actions, fds[0]) == 0 &&
        posix_spawn_file_actions_addopen(
            &actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
        posix_spawn_file_actions_addopen(
            &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0) {
        result = posix_spawn(
            &child, "/usr/bin/xclip", &actions, NULL,
            arguments, environ);
    }

    posix_spawn_file_actions_destroy(&actions);
    close(fds[0]);

    if (result != 0) {
        return -1;
    }

    int status;
    pid_t waited;

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);

    return waited == child &&
           WIFEXITED(status) &&
           WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int delete_entry(const char *password)
{
    Vault vault;

    if (vault_open(password, &vault) != 0) {
        return -1;
    }

    char service[MAX_SERVICE_LENGTH + 1];

    if (read_text("Service: ", service, sizeof(service)) != 0) {
        fprintf(stderr, "Invalid service name.\n");
        vault_close(&vault);
        return -1;
    }

    size_t index = 0;

    while (index < vault.count &&
           strcmp(vault.entries[index].service, service) != 0) {
        index++;
    }

    if (index == vault.count) {
        fprintf(stderr, "No entry found for this service.\n");
        vault_close(&vault);
        return -1;
    }

    char confirmation[4];

    if (read_text("Type yes to delete this entry: ", confirmation,
                  sizeof(confirmation)) != 0 ||
        strcmp(confirmation, "yes") != 0) {
        puts("Deletion cancelled.");
        vault_close(&vault);
        return 1;
    }

    for (size_t i = index; i + 1 < vault.count; i++) {
        vault.entries[i] = vault.entries[i + 1];
    }

    vault.count--;
    sodium_memzero(&vault.entries[vault.count], sizeof(vault.entries[0]));

    int result = vault_save(&vault);
    vault_close(&vault);

    if (result == 0) {
        puts("Entry deleted.");
    }

    return result;
}

int main(int argc, char *argv[]){
    if (argc != 2){
        fprintf(stderr, "Usage: %s <init|list|add|get|delete>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "init") != 0 &&
        strcmp(argv[1], "add") != 0 &&
        strcmp(argv[1], "list") != 0 &&
        strcmp(argv[1], "get") != 0 &&
        strcmp(argv[1], "delete") != 0) {
        fprintf(stderr,
                "Unknown command. Use init, add, list, get or delete.\n");
        return 1;
    }

    if (getuid() != geteuid() || getgid() != getegid()) {
        fprintf(stderr, "Unsupported execution privileges.\n");
        return 1;
    }

    if (sodium_init() < 0){
        fprintf(stderr, "Could not start the password manager.\n");
        return 1;
    }

    if (setvbuf(stdin, NULL, _IONBF, 0) != 0) {
        fprintf(stderr, "Could not start the password manager.\n");
        return 1;
    }

    char password[MAX_PASSWORD_LENGTH + 1] = {0};
    char confirmation[MAX_PASSWORD_LENGTH + 1] = {0};
    int result = 1;
    int cancelled = 0;

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
    } else if (strcmp(argv[1], "get") == 0) {
        if (read_password("Master password: ", password,
                          sizeof(password)) != 0) {
            fprintf(stderr, "Could not read password or input was invalid.\n");
        } else if (get_entry(password) == 0) {
            result = 0;
        }
    } else if (strcmp(argv[1], "delete") == 0) {
        if (read_password("Master password: ", password,
                          sizeof(password)) != 0) {
            fprintf(stderr, "Could not read password or input was invalid.\n");
        } else {
            int deleted = delete_entry(password);

            if (deleted >= 0) {
                result = 0;
                cancelled = deleted == 1;
            }
        }
    } else {
        fprintf(stderr,
                "Unknown command. Available commands: init, add, list, get, delete.\n");
    }

    sodium_memzero(password, sizeof(password));
    sodium_memzero(confirmation, sizeof(confirmation));

    const char *outcome = result == 0 ? "success" : "failure";

    if (cancelled) {
        outcome = "cancelled";
    }

    log_event(argv[1], outcome);

    return result;
}

