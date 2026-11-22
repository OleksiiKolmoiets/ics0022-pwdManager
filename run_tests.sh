#!/bin/sh
set -eu

test_flags="-std=c11 -Wall -Wextra -Wpedantic -Werror -g"

if [ "${1:-}" = "--sanitize" ]; then
    test_flags="$test_flags -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"
fi

gcc $test_flags main.c auth.c crypto.c storage.c -lsodium -o pwmgr
gcc $test_flags test_crypto.c crypto.c -lsodium -o test_crypto
gcc $test_flags test_storage.c storage.c crypto.c -lsodium -o test_storage

./test_crypto
./test_storage
/usr/bin/python3 test_cli.py