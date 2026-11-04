#include <stdio.h>
#include <termios.h>
#include <unistd.h>

#include "pwmgr.h"

int read_password(const char *prompt, char *password, size_t size){
    struct termios original;
    struct termios hidden;
    size_t length = 0;
    int ch;
    int invalid = 0;

    if (size < 2){
        return -1;
    }

    if (tcgetattr(STDIN_FILENO, &original) != 0){
        return -1;
    }

    hidden = original;
    hidden.c_lflag &= ~(ECHO | ECHONL);

    printf("%s", prompt);
    fflush(stdout);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &hidden) != 0){
        return -1;
    }

    while ((ch = getchar()) != '\n' && ch != EOF){
        if (ch < 32 || ch > 126 || length >= size - 1){
            invalid = 1;
        } else {
            password[length++] = (char)ch;
        }
    }

    password[length] = '\0';

    int restored = tcsetattr(STDIN_FILENO, TCSANOW, &original);
    printf("\n");

    if (restored != 0 || ch == EOF || invalid || length == 0){
        return -1;
    }

    return 0;
}

int read_text(const char *prompt, char *buffer, size_t size){
    size_t length = 0;
    int ch;
    int invalid = 0;

    if (size < 2) {
        return -1;
    }

    printf("%s", prompt);
    fflush(stdout);

    while ((ch = getchar()) != '\n' && ch != EOF) {
        if (ch < 32 || ch > 126 || length >= size - 1) {
            invalid = 1;
        } else {
            buffer[length++] = (char)ch;
        }
    }

    buffer[length] = '\0';

    if (ch == EOF || invalid || length == 0) {
        sodium_memzero(buffer, size);
        return -1;
    }

    return 0;
}

int read_entry(Entry *entry){
    sodium_memzero(entry, sizeof(*entry));

    if (read_text("Service: ", entry->service,
                  sizeof(entry->service)) != 0 ||
        read_text("Username: ", entry->username,
                  sizeof(entry->username)) != 0 ||
        read_password("Password: ", entry->password,
                      sizeof(entry->password)) != 0) {
        fprintf(stderr,
                "Input must be nonempty, printable ASCII and within the field limits.\n");
        sodium_memzero(entry, sizeof(*entry));
        return -1;
    }

    return 0;
}
