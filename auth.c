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