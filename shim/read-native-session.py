#!/usr/bin/env python3
"""Read Grok Bot's signed-in Cursor session through the Linux secure store.

The JSON result is intended for the parent shim process over a private stdout
pipe. It must never be printed to a terminal or capture log.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

import secretstorage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


SAFE_STORAGE_SCHEMA = "chrome_libsecret_os_crypt_password_v2"
SAFE_STORAGE_APPLICATION = "Grok Bot"


def safe_storage_password() -> bytes:
    bus = secretstorage.dbus_init()
    for collection in secretstorage.get_all_collections(bus):
        collection.unlock()
        for item in collection.get_all_items():
            attributes = item.get_attributes()
            if (
                attributes.get("application") == SAFE_STORAGE_APPLICATION
                and attributes.get("xdg:schema") == SAFE_STORAGE_SCHEMA
            ):
                return item.get_secret()
    raise RuntimeError("Grok Bot's secure-storage key is unavailable")


def decrypt_value(value: str, password: bytes) -> str:
    raw = base64.b64decode(value)
    if raw[:3] not in (b"v10", b"v11"):
        return value
    key = hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1, 16)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor()
    padded = decryptor.update(raw[3:]) + decryptor.finalize()
    padding = padded[-1]
    if not 1 <= padding <= 16 or padded[-padding:] != bytes([padding]) * padding:
        raise RuntimeError("Grok Bot's secure-storage value could not be decrypted")
    return padded[:-padding].decode("utf-8")


def main() -> None:
    if len(sys.argv) != 2:
        raise RuntimeError("usage: read-native-session.py <grok-bot-profile>")
    source = Path(sys.argv[1]).expanduser().resolve() / "sand-secrets.json"
    stored = json.loads(source.read_text(encoding="utf-8"))
    password = safe_storage_password()
    session = {
        "refreshToken": decrypt_value(stored.get("cursor-refresh-token", ""), password),
        "machineId": decrypt_value(stored.get("cursor-machine-id", ""), password),
    }
    if not session["refreshToken"] or not session["machineId"]:
        raise RuntimeError("the Grok Bot profile does not contain a signed-in session")
    sys.stdout.write(json.dumps(session, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # Keep stderr bounded and credential-free.
        sys.stderr.write(f"native session read failed: {error}\n")
        raise SystemExit(1)
