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

    if (strcmp(argv[1], "init") == 0){
        printf("init recognised. Vault creation is not implemented yet.\n");
    } else if (strcmp(argv[1], "list") == 0){
        printf("list recognised. Vault listing is not implemented yet.\n");
    } else {
        fprintf(stderr, "Unknown command. Available commands: init, list.\n");
        return 1;
    }

    return 0;
}
