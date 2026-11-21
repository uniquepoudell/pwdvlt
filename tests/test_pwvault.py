import json
import stat
import string

import pytest

from pwvault import cli, crypto
from pwvault.generator import generate_password
from pwvault.vault import Vault

# Tiny Argon2 limits so the tests run fast. Real vaults use the defaults.
FAST = dict(opslimit=crypto.nacl.pwhash.argon2id.OPSLIMIT_MIN,
            memlimit=crypto.nacl.pwhash.argon2id.MEMLIMIT_MIN)
MASTER = "correct horse battery staple"


@pytest.fixture
def path(tmp_path):
    return tmp_path / "vault.json"


def test_round_trip(path):
    v = Vault.create(path, MASTER, **FAST)
    v.add("github", "s3cret!", username="me")
    v.save()
    v2 = Vault.open(path, MASTER)
    assert v2.get("github")["password"] == "s3cret!"
    assert v2.get("github")["username"] == "me"


def test_file_has_no_plaintext_and_is_private(path):
    v = Vault.create(path, MASTER, **FAST)
    v.add("github", "VeryDistinctivePassword123", username="someone")
    v.save()
    raw = path.read_text()
    assert "VeryDistinctivePassword123" not in raw
    assert "github" not in raw and "someone" not in raw
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_wrong_password_fails(path):
    Vault.create(path, MASTER, **FAST)
    with pytest.raises(crypto.DecryptionError):
        Vault.open(path, "wrong password!!")


def test_tampered_ciphertext_fails(path):
    Vault.create(path, MASTER, **FAST)
    data = json.loads(path.read_text())
    ct = bytearray(crypto._b64d(data["ciphertext"]))
    ct[0] ^= 1
    data["ciphertext"] = crypto._b64e(bytes(ct))
    path.write_text(json.dumps(data))
    with pytest.raises(crypto.DecryptionError):
        Vault.open(path, MASTER)


def test_tampered_header_fails(path):
    # Changing the stored KDF settings must not be accepted silently.
    Vault.create(path, MASTER, **FAST)
    data = json.loads(path.read_text())
    data["kdf"]["opslimit"] += 1
    path.write_text(json.dumps(data))
    with pytest.raises(crypto.DecryptionError):
        Vault.open(path, MASTER)


def test_fresh_nonce_each_save(path):
    v = Vault.create(path, MASTER, **FAST)
    first = json.loads(path.read_text())["nonce"]
    v.save()
    assert json.loads(path.read_text())["nonce"] != first


def test_generator():
    for _ in range(200):
        p = generate_password(16)
        assert len(p) == 16
        assert any(c.islower() for c in p) and any(c.isupper() for c in p)
        assert any(c.isdigit() for c in p) and any(not c.isalnum() for c in p)
    assert all(c in string.ascii_letters + string.digits for c in generate_password(30, symbols=False))
    with pytest.raises(ValueError):
        generate_password(4)


def test_cli_flow(path, monkeypatch, capsys):
    monkeypatch.setattr(crypto, "DEFAULT_OPSLIMIT", FAST["opslimit"])
    monkeypatch.setattr(crypto, "DEFAULT_MEMLIMIT", FAST["memlimit"])
    monkeypatch.setattr(crypto.new_header, "__defaults__", (FAST["opslimit"], FAST["memlimit"]))
    answers = iter([MASTER, MASTER,                # init
                    MASTER, "hunter2-long",        # add email
                    MASTER,                        # add github --generate
                    MASTER,                        # list
                    MASTER,                        # get --show
                    MASTER,                        # delete
                    MASTER])                       # list
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    v = ["--vault", str(path)]

    assert cli.main(v + ["init"]) == 0
    assert cli.main(v + ["add", "email", "-u", "me@example.com"]) == 0
    assert cli.main(v + ["add", "github", "--generate"]) == 0
    capsys.readouterr()
    assert cli.main(v + ["list"]) == 0
    out = capsys.readouterr().out
    assert "email" in out and "me@example.com" in out and "github" in out
    assert cli.main(v + ["get", "email", "--show"]) == 0
    assert "hunter2-long" in capsys.readouterr().out
    assert cli.main(v + ["delete", "email", "--yes"]) == 0
    capsys.readouterr()
    assert cli.main(v + ["list"]) == 0
    assert "email" not in capsys.readouterr().out


def test_cli_wrong_password_exit_code(path, monkeypatch, capsys):
    Vault.create(path, MASTER, **FAST)
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "nope nope nope")
    assert cli.main(["--vault", str(path), "list"]) == 1
    assert "wrong master password" in capsys.readouterr().err
