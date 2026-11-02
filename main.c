#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "pwmgr.h"

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
        } else {
            printf("Master password confirmed.\n");
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
