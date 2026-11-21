# pwvault

A small, offline, command-line password manager. It's a learning project: the
code is short enough to read in one sitting, and all the cryptography comes from
libsodium (through [PyNaCl](https://pynacl.readthedocs.io/)), not hand-written code.

## Set it up

You need Python 3.9 or newer.

```bash
git clone https://github.com/uniquepoudell/pwdvlt.git
cd pwdvlt
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .                   # installs PyNaCl and the `pwvault` command
```

To run the tests: `pip install -e ".[dev]"` then `pytest`.

## Use it

```bash
pwvault init                            # create the vault and choose a master password
pwvault add github -u myname            # asks for the password (hidden as you type)
pwvault add email -u me@example.com --generate   # makes a strong password for you
pwvault list                            # entry names and usernames
pwvault get github                      # copies the password, clears the clipboard after 20 s
pwvault get github --show               # prints it instead
pwvault delete github                   # asks before deleting
pwvault generate -l 24                  # just print a strong password
pwvault generate --no-symbols --copy    # letters and digits, copied to the clipboard
```

Every command except `generate` asks for the master password. Run `pwvault COMMAND --help`
for all the options.

The vault lives at `~/.pwvault/vault.json`. Use `--vault PATH` or set `PWVAULT_PATH`
to keep it somewhere else.

Copying to the clipboard uses `pbcopy` on macOS, `clip` on Windows, and `wl-copy`,
`xclip` or `xsel` on Linux. If none is installed, use `--show`.

## How it works

```
master password ──Argon2id (256 MiB, 3 passes, random salt)──▶ 32-byte key
all entries as JSON ──XChaCha20-Poly1305 (random 24-byte nonce)──▶ vault.json
```

- **Argon2id** makes each master-password guess cost about 0.4 s and 256 MiB of
  memory, so someone who steals the file can't try billions of guesses cheaply.
- **XChaCha20-Poly1305** encrypts *and* authenticates. If one byte of the file is
  changed, unlocking fails instead of returning wrong data.
- The file's header (version, salt, Argon2 settings) is readable but authenticated
  too, so nobody can quietly weaken the settings.
- Every save uses a fresh random nonce, writes to a temp file first and then renames
  it, so a crash can't leave a half-written vault. The file is `chmod 600`.
- Entry names and usernames are encrypted as well; the file reveals nothing but its size.

| File | What it does |
| --- | --- |
| `pwvault/crypto.py` | key derivation, encrypt, decrypt |
| `pwvault/vault.py` | load and save the vault, add/get/delete entries |
| `pwvault/generator.py` | random passwords from the OS's secure random source |
| `pwvault/clipboard.py` | copy to the clipboard |
| `pwvault/cli.py` | the commands |

## Limits to know about

- **Forget the master password and the vault is gone.** There is no reset, by design.
- **Back up `vault.json`** (it's safe to copy: it's encrypted). One disk failure
  otherwise loses everything.
- Python can't reliably wipe secrets from memory, and clipboard history tools may keep
  copies. Malware on your computer (a keylogger, for example) defeats any password manager.
- This hasn't had a security audit. Until it has, keep a well-reviewed manager for
  your most important logins, and **don't store crypto wallet seed phrases in it**.

## Ideas for next steps

- `pwvault edit` and `pwvault change-master` (re-encrypt with a new master password)
- `pwvault search` across names, usernames and URLs
- Encrypted export and import, for backups
- An auto-lock agent so you don't type the master password for every command
