#ifndef PWMGR_H
#define PWMGR_H

#include <stddef.h>

#define MAX_PASSWORD_LENGTH 128
#define MIN_MASTER_PASSWORD_LENGTH 12

int read_password(const char *prompt, char *password, size_t size);

#endif