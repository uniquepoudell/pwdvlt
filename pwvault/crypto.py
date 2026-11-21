"""Encryption for the vault file.

All the real cryptography comes from libsodium (through PyNaCl). This module
only wires it together:

  master password --Argon2id--> 32-byte key --XChaCha20-Poly1305--> ciphertext

Nothing here is hand-written crypto. If you change anything in this file,
keep it that way.
"""

from __future__ import annotations

import base64
import json

import nacl.exceptions
import nacl.pwhash
import nacl.utils
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)

FORMAT_VERSION = 1
CIPHER_NAME = "xchacha20poly1305-ietf"
KDF_NAME = "argon2id"

# "Moderate" libsodium limits: about 256 MiB of memory and a fraction of a
# second per unlock on a normal laptop. That makes guessing the master
# password very slow for an attacker who steals the vault file.
DEFAULT_OPSLIMIT = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
DEFAULT_MEMLIMIT = nacl.pwhash.argon2id.MEMLIMIT_MODERATE


class DecryptionError(Exception):
    """Wrong master password, or the vault file was changed or damaged."""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def derive_key(password: str, salt: bytes, opslimit: int, memlimit: int) -> bytes:
    """Turn the master password into a 32-byte encryption key with Argon2id."""
    return nacl.pwhash.argon2id.kdf(
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        password.encode("utf-8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )


def new_header(opslimit: int = DEFAULT_OPSLIMIT, memlimit: int = DEFAULT_MEMLIMIT) -> dict:
    """Make the public (unencrypted) part of a new vault, with a fresh random salt."""
    return {
        "version": FORMAT_VERSION,
        "cipher": CIPHER_NAME,
        "kdf": {
            "name": KDF_NAME,
            "opslimit": opslimit,
            "memlimit": memlimit,
            "salt": _b64e(nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)),
        },
    }


def _associated_data(header: dict) -> bytes:
    # The header is not secret, but it is authenticated: if anyone edits the
    # salt or the KDF settings in the file, decryption fails instead of
    # silently using weaker settings.
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


def check_header(header: dict) -> None:
    if header.get("version") != FORMAT_VERSION:
        raise DecryptionError(f"Unsupported vault version: {header.get('version')!r}")
    if header.get("cipher") != CIPHER_NAME or header.get("kdf", {}).get("name") != KDF_NAME:
        raise DecryptionError("Unsupported cipher or key derivation in vault file")


def key_for_header(password: str, header: dict) -> bytes:
    check_header(header)
    kdf = header["kdf"]
    return derive_key(password, _b64d(kdf["salt"]), kdf["opslimit"], kdf["memlimit"])


def encrypt(key: bytes, header: dict, plaintext: bytes) -> dict:
    """Encrypt with a fresh random nonce. Returns the full vault-file dict."""
    nonce = nacl.utils.random(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, _associated_data(header), nonce, key
    )
    return {**header, "nonce": _b64e(nonce), "ciphertext": _b64e(ciphertext)}


def split_file(data: dict) -> tuple[dict, bytes, bytes]:
    """Split a vault-file dict into (header, nonce, ciphertext)."""
    try:
        header = {k: data[k] for k in ("version", "cipher", "kdf")}
        return header, _b64d(data["nonce"]), _b64d(data["ciphertext"])
    except (KeyError, TypeError, ValueError) as exc:
        raise DecryptionError("Vault file is damaged or not a vault") from exc


def decrypt(key: bytes, header: dict, nonce: bytes, ciphertext: bytes) -> bytes:
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, _associated_data(header), nonce, key
        )
    except nacl.exceptions.CryptoError as exc:
        raise DecryptionError(
            "Could not unlock the vault: wrong master password, or the file was changed"
        ) from exc
