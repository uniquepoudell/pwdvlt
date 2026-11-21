"""The vault: a dictionary of entries, stored encrypted in one local file."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import crypto


def default_vault_path() -> Path:
    env = os.environ.get("PWVAULT_PATH")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".pwvault" / "vault.json"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class VaultExistsError(Exception):
    pass


class VaultNotFoundError(Exception):
    pass


class Vault:
    """An unlocked vault. Holds the derived key in memory until it is dropped."""

    def __init__(self, path: Path, header: dict, key: bytes, entries: dict):
        self.path = path
        self._header = header
        self._key = key
        self.entries: dict[str, dict] = entries

    # ----- opening and creating -------------------------------------------

    @classmethod
    def create(cls, path: Path, master_password: str, **kdf_limits) -> "Vault":
        if path.exists():
            raise VaultExistsError(f"A vault already exists at {path}")
        header = crypto.new_header(**kdf_limits)
        key = crypto.key_for_header(master_password, header)
        vault = cls(path, header, key, {})
        vault.save()
        return vault

    @classmethod
    def open(cls, path: Path, master_password: str) -> "Vault":
        if not path.exists():
            raise VaultNotFoundError(
                f"No vault at {path}. Create one first with: pwvault init"
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise crypto.DecryptionError("Vault file is damaged or not a vault") from exc
        header, nonce, ciphertext = crypto.split_file(data)
        key = crypto.key_for_header(master_password, header)
        plaintext = crypto.decrypt(key, header, nonce, ciphertext)
        entries = json.loads(plaintext.decode("utf-8"))["entries"]
        return cls(path, header, key, entries)

    # ----- saving ------------------------------------------------------------

    def save(self) -> None:
        plaintext = json.dumps({"entries": self.entries}, sort_keys=True).encode("utf-8")
        data = crypto.encrypt(self._key, self._header, plaintext)

        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass  # e.g. a shared folder we don't own; the file itself is still 600

        # Write to a temp file and rename it over the old one, so a crash or
        # full disk never leaves you with a half-written (unreadable) vault.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".vault-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ----- entries -----------------------------------------------------------

    def add(self, name: str, password: str, username: str = "", url: str = "",
            notes: str = "", overwrite: bool = False) -> None:
        existing = self.entries.get(name)
        if existing and not overwrite:
            raise KeyError(f"An entry named {name!r} already exists")
        now = _now()
        self.entries[name] = {
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "created": existing["created"] if existing else now,
            "updated": now,
        }

    def get(self, name: str) -> dict:
        try:
            return self.entries[name]
        except KeyError:
            raise KeyError(f"No entry named {name!r}") from None

    def delete(self, name: str) -> None:
        if name not in self.entries:
            raise KeyError(f"No entry named {name!r}")
        del self.entries[name]

    def names(self) -> list[str]:
        return sorted(self.entries, key=str.lower)
