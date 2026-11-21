"""Strong random passwords, using the operating system's secure random source."""

from __future__ import annotations

import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
# Characters that are easy to misread (0/O, 1/l/I) are left out.
AMBIGUOUS = set("0O1lI|")


def generate_password(length: int = 20, symbols: bool = True) -> str:
    if length < 8:
        raise ValueError("Use at least 8 characters")

    groups = [
        [c for c in string.ascii_lowercase if c not in AMBIGUOUS],
        [c for c in string.ascii_uppercase if c not in AMBIGUOUS],
        [c for c in string.digits if c not in AMBIGUOUS],
    ]
    if symbols:
        groups.append(list(SYMBOLS))
    alphabet = [c for group in groups for c in group]

    # Draw until the password has at least one character from every group.
    # (Rejecting and redrawing keeps every allowed password equally likely.)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in group for c in password) for group in groups):
            return password
