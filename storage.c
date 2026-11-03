#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pwmgr.h"

static int directory_fd = -1;
static int lock_fd = -1;

static int check_file(int fd, struct stat *info){
    if (fstat(fd, info) != 0 ||
        !S_ISREG(info->st_mode) ||
        info->st_uid != geteuid() ||
        (info->st_mode & 07777) != 0600 ||
        info->st_nlink != 1) {
        return -1;
    }

    return 0;
}

void storage_close(void){
    if (lock_fd >= 0) {
        close(lock_fd);
        lock_fd = -1;
    }

    if (directory_fd >= 0) {
        close(directory_fd);
        directory_fd = -1;
    }
}

int storage_open(const char *directory){
    struct stat info;

    if (directory_fd >= 0 || lock_fd >= 0) {
        return -1;
    }

    if (mkdir(directory, 0700) != 0 && errno != EEXIST) {
        return -1;
    }

    directory_fd = open(directory,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

    if (directory_fd < 0 ||
        fstat(directory_fd, &info) != 0 ||
        !S_ISDIR(info.st_mode) ||
        info.st_uid != geteuid() ||
        (info.st_mode & 07777) != 0700) {
        goto failure;
    }

    lock_fd = openat(directory_fd, "vault.lock",
                     O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                     0600);

    if (lock_fd < 0 || check_file(lock_fd, &info) != 0 ||
        flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
        goto failure;
    }

    return 0;

failure:
    storage_close();
    return -1;
}

int storage_read(unsigned char *data, size_t capacity, size_t *length){
    struct stat info;
    *length = 0;

    if (directory_fd < 0 || lock_fd < 0) {
        return -1;
    }

    int fd = openat(directory_fd, "vault.pmv",
                    O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

    if (fd < 0) {
        return errno == ENOENT ? 1 : -1;
    }

    if (check_file(fd, &info) != 0 || info.st_size < 0 ||
        info.st_size > MAX_VAULT_SIZE ||
        (size_t)info.st_size > capacity) {
        close(fd);
        return -1;
    }

    FILE *file = fdopen(fd, "rb");
    if (file == NULL) {
        close(fd);
        return -1;
    }

    size_t expected = (size_t)info.st_size;
    size_t count = fread(data, 1, expected, file);
    int extra = fgetc(file);
    int failed = count != expected || extra != EOF || ferror(file);

    if (fclose(file) != 0) {
        failed = 1;
    }

    if (failed) {
        return -1;
    }

    *length = count;
    return 0;
}

int storage_save(const unsigned char *data, size_t length, int create_only){
    struct stat info;
    char temporary[32];

    if (directory_fd < 0 || lock_fd < 0 || length > MAX_VAULT_SIZE) {
        return -1;
    }

    if (!create_only) {
        int current = openat(directory_fd, "vault.pmv",
                             O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);

        if (current < 0) {
            return -1;
        }

        int valid = check_file(current, &info);
        int closed = close(current);

        if (valid != 0 || closed != 0) {
            return -1;
        }
    }

    snprintf(temporary, sizeof(temporary), "vault.tmp.%08x",
             (unsigned int)randombytes_random());

    int fd = openat(directory_fd, temporary,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    if (fd < 0) {
        return -1;
    }

    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        unlinkat(directory_fd, temporary, 0);
        return -1;
    }

    int failed = fwrite(data, 1, length, file) != length;

    if (fflush(file) != 0) {
        failed = 1;
    }
    if (fsync(fileno(file)) != 0) {
        failed = 1;
    }
    if (fclose(file) != 0) {
        failed = 1;
    }

    if (!failed) {
        if (create_only) {
            if (linkat(directory_fd, temporary,
                       directory_fd, "vault.pmv", 0) != 0) {
                failed = 1;
            }
        } else if (renameat(directory_fd, temporary,
                            directory_fd, "vault.pmv") != 0) {
            failed = 1;
        }
    }

    if (unlinkat(directory_fd, temporary, 0) != 0 && create_only && !failed) {
        failed = 1;
    }

    if (failed) {
        return -1;
    }

    return fsync(directory_fd) == 0 ? 0 : -1;
}