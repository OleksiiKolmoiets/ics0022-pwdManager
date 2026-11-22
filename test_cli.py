import os
from pathlib import Path
import re
import stat
import tempfile

import pexpect


BINARY = str(Path(__file__).resolve().parent / "pwmgr")
MASTER = "Master12345!"
SERVICE = "service-secret"
USERNAME = "user-secret"
PASSWORD = "Test password!$123"


def run(operation, fields, expected=0):
    before = vault.read_bytes() if vault.exists() else None
    child = pexpect.spawn(
        BINARY, [operation], env=env,
        encoding="utf-8", echo=False, timeout=20
    )
    output = ""

    try:
        for prompt, answer in fields:
            child.expect_exact(prompt)
            output += child.before + child.after
            child.sendline(answer)

        child.expect(pexpect.EOF)
        output += child.before
    finally:
        child.close()

    assert child.exitstatus == expected, (operation, output)
    assert "AddressSanitizer" not in output, output
    assert "runtime error:" not in output, output

    if expected != 0:
        after = vault.read_bytes() if vault.exists() else None
        assert before == after, "Failed operation changed the vault"

    return output


def authenticated(operation, fields=(), expected=0):
    return run(
        operation,
        [("Master password: ", MASTER)] + list(fields),
        expected
    )


with tempfile.TemporaryDirectory(prefix="pwmgr-test-") as test_home:
    env = os.environ.copy()
    env["HOME"] = test_home
    env["DISPLAY"] = ""

    directory = Path(test_home) / ".pwmgr"
    vault = directory / "vault.pmv"
    log = directory / "events.log"

    # Initialization and protection against overwriting a vault.
    run("init", [("Choose a master password: ", "short")], 1)
    run("init", [
        ("Choose a master password: ", MASTER),
        ("Confirm master password: ", "different-password")
    ], 1)
    assert not vault.exists()

    init_fields = [
        ("Choose a master password: ", MASTER),
        ("Confirm master password: ", MASTER)
    ]
    run("init", init_fields)
    run("init", init_fields, 1)
    assert "Vault is empty." in authenticated("list")
    print("PASS initialization and overwrite protection")

    # Normal addition, listing and duplicate rejection.
    entry = [
        ("Service: ", SERVICE),
        ("Username: ", USERNAME),
        ("Password: ", PASSWORD)
    ]
    authenticated("add", entry)

    output = authenticated("list")
    assert SERVICE in output
    assert USERNAME not in output and PASSWORD not in output

    authenticated("add", entry, 1)

    # Authentication is required for every record command.
    for operation in ("add", "list", "get", "delete"):
        output = run(
            operation,
            [("Master password: ", "wrong-password")],
            1
        )
        assert "Could not unlock the vault." in output
        assert "Service: " not in output

    print("PASS duplicate rejection and authentication for all record commands")

    # Empty, oversized and tab-containing fields.
    field_cases = [
        ("Service: ", [], 64),
        ("Username: ", [("Service: ", "invalid-test")], 128),
        ("Password: ", [
            ("Service: ", "invalid-test"),
            ("Username: ", "student")
        ], 128),
    ]

    for prompt, prefix, limit in field_cases:
        for value in ("", "A" * (limit + 1), "bad\tvalue"):
            authenticated("add", prefix + [(prompt, value)], 1)

    # Exact maximum lengths must still work.
    maximum = [
        ("Service: ", "S" * 64),
        ("Username: ", "U" * 128),
        ("Password: ", "P" * 128)
    ]
    authenticated("add", maximum)
    assert "S" * 64 in authenticated("list")

    for operation in ("get", "delete"):
        authenticated(operation, [("Service: ", "S" * 65)], 1)
        authenticated(operation, [("Service: ", "missing-service")], 1)

    print("PASS empty, oversized, control-character and maximum-length inputs")

    # No display: copying must fail without exposing the password.
    output = authenticated("get", [("Service: ", SERVICE)], 1)
    assert "Could not copy the password to the clipboard." in output
    assert PASSWORD not in output

    # Cancellation must preserve the vault.
    before = vault.read_bytes()
    authenticated("delete", [
        ("Service: ", SERVICE),
        ("Type yes to delete this entry: ", "no")
    ])
    assert vault.read_bytes() == before
    assert log.read_text().splitlines()[-1].endswith(
        "operation=delete result=cancelled"
    )

    # Confirmed deletion must persist.
    authenticated("delete", [
        ("Service: ", SERVICE),
        ("Type yes to delete this entry: ", "yes")
    ])
    assert SERVICE not in authenticated("list")
    print("PASS clipboard failure, cancellation and persistent deletion")

    # Check ownership and permission settings.
    for path, mode in (
        (directory, 0o700),
        (vault, 0o600),
        (directory / "vault.lock", 0o600),
        (log, 0o600),
    ):
        assert stat.S_IMODE(path.stat().st_mode) == mode
        assert path.stat().st_uid == os.geteuid()

    vault.chmod(0o644)
    try:
        for operation in ("add", "list", "get", "delete"):
            authenticated(operation, expected=1)
    finally:
        vault.chmod(0o600)

    directory.chmod(0o755)
    try:
        authenticated("list", expected=1)
    finally:
        directory.chmod(0o700)

    backup = directory / "vault.saved"
    vault.rename(backup)
    vault.symlink_to(backup)
    try:
        authenticated("list", expected=1)
    finally:
        vault.unlink()
        backup.rename(vault)

    print("PASS ownership metadata, unsafe permissions and symlink rejection")

    # Corrupted ciphertext, wrong format and a truncated file.
    saved = vault.read_bytes()
    changed = bytearray(saved)
    changed[-1] ^= 1

    try:
        for corrupted in (
            bytes(changed),
            b"BAD!" + saved[4:],
            saved[:10],
        ):
            vault.write_bytes(corrupted)
            output = authenticated("list", expected=1)
            assert "Could not unlock the vault." in output
    finally:
        vault.write_bytes(saved)

    authenticated("list")
    print("PASS tampered, invalid-format and truncated vault rejection")

    # Logging failure should warn without changing the command result.
    log.chmod(0o644)
    saved_log = log.read_bytes()
    try:
        output = authenticated("list")
        assert "Could not write the event log." in output
        assert log.read_bytes() == saved_log
    finally:
        log.chmod(0o600)

    pattern = (
        r"timestamp=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z "
        r"operation=(init|add|list|get|delete|authentication) "
        r"result=(success|failure|cancelled)"
    )
    text = log.read_text()

    assert all(re.fullmatch(pattern, line) for line in text.splitlines())

    for secret in (MASTER, SERVICE, USERNAME, PASSWORD, "wrong-password"):
        assert secret not in text

    assert "operation=authentication result=failure" in text
    print("PASS structured logging, secret exclusion and logging failure handling")

print("All CLI tests passed.")