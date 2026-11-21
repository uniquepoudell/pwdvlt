"""Command-line interface: pwvault init | add | get | list | delete | generate"""

from __future__ import annotations

import argparse
import getpass
import sys
import time
from pathlib import Path

from . import __version__, clipboard
from .crypto import DecryptionError
from .generator import generate_password
from .vault import Vault, VaultExistsError, VaultNotFoundError, default_vault_path

MIN_MASTER_LENGTH = 12


class CliError(Exception):
    pass


def _ask_master(confirm: bool = False) -> str:
    password = getpass.getpass("Master password: ")
    if confirm:
        if len(password) < MIN_MASTER_LENGTH:
            raise CliError(f"Use a master password of at least {MIN_MASTER_LENGTH} characters.")
        if getpass.getpass("Repeat master password: ") != password:
            raise CliError("The passwords did not match.")
    return password


def _open(args) -> Vault:
    return Vault.open(args.vault, _ask_master())


# ----- commands ----------------------------------------------------------------


def cmd_init(args) -> None:
    if args.vault.exists():
        raise CliError(f"A vault already exists at {args.vault}")
    print("Choose a master password. It is the only key to your vault:")
    print("if you forget it, nobody can recover your passwords.")
    Vault.create(args.vault, _ask_master(confirm=True))
    print(f"Created an empty vault at {args.vault}")


def cmd_add(args) -> None:
    vault = _open(args)
    if args.name in vault.entries and not args.force:
        raise CliError(f"{args.name!r} already exists. Use --force to replace it.")
    if args.generate:
        password = generate_password(args.length, symbols=not args.no_symbols)
    else:
        password = getpass.getpass(f"Password for {args.name}: ")
        if not password:
            raise CliError("Empty password. Use --generate to make one.")
    vault.add(args.name, password, username=args.username or "", url=args.url or "",
              notes=args.notes or "", overwrite=args.force)
    vault.save()
    print(f"Saved {args.name!r}" + (" with a generated password." if args.generate else "."))
    if args.generate and not args.show:
        print(f"See it with: pwvault get {args.name}")
    elif args.generate:
        print(password)


def _copy_and_clear(secret: str, seconds: int) -> bool:
    if not clipboard.copy(secret):
        return False
    if seconds <= 0:
        print("Password copied to the clipboard.")
        return True
    try:
        for left in range(seconds, 0, -1):
            print(f"\rPassword copied. Clearing the clipboard in {left:>2}s (Ctrl+C to clear now) ",
                  end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    clipboard.copy("")
    print("\rClipboard cleared." + " " * 60)
    return True


def cmd_get(args) -> None:
    entry = _open(args).get(args.name)
    for label in ("username", "url", "notes"):
        if entry.get(label):
            print(f"{label.capitalize():9} {entry[label]}")
    if args.show:
        print(f"{'Password':9} {entry['password']}")
        return
    if not _copy_and_clear(entry["password"], args.clear_after):
        print("No clipboard tool found (install xclip, xsel or wl-copy on Linux).")
        print("Use --show to print the password instead.")


def cmd_list(args) -> None:
    vault = _open(args)
    names = vault.names()
    if not names:
        print("The vault is empty. Add an entry with: pwvault add NAME")
        return
    width = max(len(n) for n in names)
    for name in names:
        user = vault.entries[name].get("username", "")
        print(f"{name:<{width}}  {user}".rstrip())


def cmd_delete(args) -> None:
    vault = _open(args)
    vault.get(args.name)  # fail early if it does not exist
    if not args.yes:
        answer = input(f"Delete {args.name!r}? This cannot be undone. [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Nothing deleted.")
            return
    vault.delete(args.name)
    vault.save()
    print(f"Deleted {args.name!r}.")


def cmd_generate(args) -> None:
    password = generate_password(args.length, symbols=not args.no_symbols)
    if args.copy:
        if not _copy_and_clear(password, args.clear_after):
            print("No clipboard tool found; printing instead.")
            print(password)
    else:
        print(password)


# ----- argument parsing --------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pwvault", description="An offline password manager.")
    p.add_argument("--version", action="version", version=f"pwvault {__version__}")
    p.add_argument("--vault", type=Path, default=None,
                   help="vault file (default: $PWVAULT_PATH or ~/.pwvault/vault.json)")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    s = sub.add_parser("init", help="create a new, empty vault")
    s.set_defaults(func=cmd_init)

    def gen_opts(s):
        s.add_argument("-l", "--length", type=int, default=20, help="length (default 20)")
        s.add_argument("--no-symbols", action="store_true", help="letters and digits only")

    s = sub.add_parser("add", help="add an entry")
    s.add_argument("name", help="a name for the entry, e.g. github")
    s.add_argument("-u", "--username")
    s.add_argument("--url")
    s.add_argument("--notes")
    s.add_argument("-g", "--generate", action="store_true", help="generate a strong password")
    s.add_argument("--show", action="store_true", help="print the generated password")
    s.add_argument("-f", "--force", action="store_true", help="replace an existing entry")
    gen_opts(s)
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("get", help="copy an entry's password to the clipboard")
    s.add_argument("name")
    s.add_argument("--show", action="store_true", help="print the password instead")
    s.add_argument("--clear-after", type=int, default=20, metavar="SECONDS",
                   help="clear the clipboard after this many seconds (0 = never)")
    s.set_defaults(func=cmd_get)

    s = sub.add_parser("list", aliases=["ls"], help="list entry names")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("delete", aliases=["rm"], help="delete an entry")
    s.add_argument("name")
    s.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmation")
    s.set_defaults(func=cmd_delete)

    s = sub.add_parser("generate", aliases=["gen"], help="print a strong random password")
    gen_opts(s)
    s.add_argument("-c", "--copy", action="store_true", help="copy instead of printing")
    s.add_argument("--clear-after", type=int, default=20, metavar="SECONDS")
    s.set_defaults(func=cmd_generate)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.vault = (args.vault or default_vault_path()).expanduser()
    try:
        args.func(args)
    except (CliError, DecryptionError, VaultExistsError, VaultNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyError as exc:
        print(f"Error: {exc.args[0]}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        return 130
    return 0
