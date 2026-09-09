import json
import os
import stat

import pytest

from keyfence.vault import MIN_SECRET_LENGTH, Vault, VaultError


def test_add_and_contains(tmp_path):
    v = Vault(path=tmp_path / "vault.json")
    assert v.add("meu-segredo-super-confidencial-999")
    assert v.contains("meu-segredo-super-confidencial-999")
    assert not v.contains("other-value-entirely")
    assert v.count() == 1


def test_never_stores_plaintext(tmp_path):
    v = Vault(path=tmp_path / "vault.json")
    v.add("meu-segredo-super-confidencial-999")
    raw = (tmp_path / "vault.json").read_text()
    assert "meu-segredo-super-confidencial-999" not in raw
    assert stat.S_IMODE(os.stat(tmp_path / "vault.json").st_mode) == 0o600


def test_rejects_short_secrets(tmp_path):
    v = Vault(path=tmp_path / "vault.json")
    assert v.add("abc") is False
    assert v.is_empty()


def test_add_many_counts_only_new(tmp_path):
    v = Vault(path=tmp_path / "vault.json")
    assert v.add_many(["first-secret-value", "second-secret-value", "tiny"]) == 2
    assert v.add_many(["first-secret-value"]) == 0


def test_persists_and_reloads(tmp_path):
    path = tmp_path / "vault.json"
    Vault(path=path).add("persisted-secret-value")
    reloaded = Vault(path=path)
    assert reloaded.contains("persisted-secret-value")


def test_min_length_from_file_never_below_default(tmp_path):
    path = tmp_path / "vault.json"
    path.write_text(json.dumps({"salt": "00" * 32, "hashes": [], "min_length": 3}))
    assert Vault(path=path).min_length == MIN_SECRET_LENGTH


def test_explicit_salt_is_used(tmp_path):
    v = Vault(path=tmp_path / "vault.json", salt=b"\x01" * 32)
    assert v.salt == b"\x01" * 32


def test_merge_adopts_salt_when_empty(tmp_path):
    main = Vault(path=tmp_path / "main.json")
    other = Vault(path=tmp_path / "other.json", salt=b"\x02" * 32)
    other.add("shared-secret-value")
    main.merge(other)
    assert main.salt == other.salt
    assert main.contains("shared-secret-value")


def test_merge_rejects_different_salt(tmp_path):
    main = Vault(path=tmp_path / "main.json")
    main.add("existing-secret-value")
    other = Vault(path=tmp_path / "other.json", salt=b"\x02" * 32)
    other.add("shared-secret-value")
    with pytest.raises(ValueError):
        main.merge(other)


def test_canary_is_stored_with_label_and_detected(tmp_path):
    v = Vault(path=tmp_path / "vault.json")
    assert v.add_canary("canary-value-0123456789", "/work/.env")
    assert v.contains("canary-value-0123456789")
    assert v.canary_label("canary-value-0123456789") == "/work/.env"
    assert v.canary_label("something-else-entirely") is None
    assert v.count() == 0 and v.canary_count() == 1 and not v.is_empty()
    reloaded = Vault(path=tmp_path / "vault.json")
    assert reloaded.canary_label("canary-value-0123456789") == "/work/.env"
    assert "canary-value-0123456789" not in (tmp_path / "vault.json").read_text()


def test_short_canary_is_refused(tmp_path):
    assert Vault(path=tmp_path / "vault.json").add_canary("tiny", "x") is False


def test_merge_carries_canaries(tmp_path):
    main = Vault(path=tmp_path / "main.json")
    other = Vault(path=tmp_path / "other.json", salt=main.salt)
    other.add_canary("canary-value-0123456789", "/work/.env")
    main.merge(other)
    assert main.canary_label("canary-value-0123456789") == "/work/.env"


def test_ensure_saved_writes_empty_vault_once(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(path=path)
    v.ensure_saved()
    assert path.exists()
    salt = v.salt
    v.ensure_saved()
    assert Vault(path=path).salt == salt


def test_placeholder_digest_is_stable_and_separate(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(path=path)
    v.ensure_saved()
    a = v.placeholder_digest("secret-value-one")
    assert a == Vault(path=path).placeholder_digest("secret-value-one")
    assert a != v.placeholder_digest("secret-value-two")
    assert a != v._digest("secret-value-one")
    assert len(a) == 64


@pytest.mark.parametrize("content", ["x", "", '{"salt": "zz"}', '{"hashes": []}', "[1, 2]", '{"salt": 1, "hashes": []}'])
def test_corrupted_vault_raises_actionable_error(tmp_path, content):
    path = tmp_path / "vault.json"
    path.write_text(content)
    with pytest.raises(VaultError) as exc:
        Vault(path=path)
    assert "keyfence import" in str(exc.value) and str(path) in str(exc.value)


def test_save_is_atomic_and_leaves_no_temp_file(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(path=path)
    v.add("persisted-secret-value")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["vault.json", "vault.json.lock"]
    assert json.loads(path.read_text())["hashes"]
    v.remove_files()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("content", [
    '{"salt": "%s", "hashes": "notalist"}' % ("00" * 32),
    '{"salt": "%s", "hashes": {"a": 1}}' % ("00" * 32),
    '{"salt": "%s", "hashes": [], "min_length": 999999999}' % ("00" * 32),
    '{"salt": "%s", "hashes": [], "min_length": true}' % ("00" * 32),
    '{"salt": "%s", "hashes": ["short"]}' % ("00" * 32),
    '{"salt": "%s", "hashes": [], "canaries": {"x": "y"}}' % ("00" * 32),
    '{"salt": "0011", "hashes": []}',
])
def test_wrong_field_types_are_rejected(tmp_path, content):
    path = tmp_path / "vault.json"
    path.write_text(content)
    with pytest.raises(VaultError):
        Vault(path=path)


def test_concurrent_writers_lose_nothing(tmp_path):
    import threading
    path = tmp_path / "vault.json"
    errors = []

    def worker(n):
        try:
            v = Vault(path=path)
            for i in range(30):
                v.add(f"worker-{n}-secret-{i:03d}")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    final = Vault(path=path)
    assert final.count() == 120
    assert all(final.contains(f"worker-{n}-secret-{i:03d}") for n in range(4) for i in range(30))


def test_contended_lock_warns_then_proceeds(tmp_path, capsys, monkeypatch):
    import threading
    from keyfence import vault as vault_module
    monkeypatch.setattr(vault_module, "LOCK_POLL", 0.01)
    path = tmp_path / "vault.json"
    holder = Vault(path=path)
    release = threading.Event()
    entered = threading.Event()

    def hold():
        with holder._locked():
            entered.set()
            release.wait(5)

    thread = threading.Thread(target=hold)
    thread.start()
    entered.wait(5)
    threading.Timer(0.2, release.set).start()
    Vault(path=path).add("value-added-under-contention")
    thread.join()
    assert "waiting for another keyfence command" in capsys.readouterr().err
    assert Vault(path=path).contains("value-added-under-contention")


def test_lock_held_too_long_gives_up_with_instructions(tmp_path, monkeypatch):
    from keyfence import vault as vault_module
    monkeypatch.setattr(vault_module, "LOCK_TIMEOUT", 0.05)
    monkeypatch.setattr(vault_module, "LOCK_POLL", 0.01)
    monkeypatch.setattr(vault_module, "_try_lock", lambda handle: False)
    with pytest.raises(VaultError) as exc:
        Vault(path=tmp_path / "vault.json").add("value-that-never-lands")
    assert "delete that file" in str(exc.value)


def test_windows_lock_branch_is_exercised(tmp_path, monkeypatch):
    from keyfence import vault as vault_module

    class FakeMsvcrt:
        LK_NBLCK, LK_UNLCK = 1, 2
        calls = []

        @classmethod
        def locking(cls, fd, mode, nbytes):
            cls.calls.append(mode)

    monkeypatch.setattr(vault_module, "fcntl", None)
    monkeypatch.setattr(vault_module, "msvcrt", FakeMsvcrt)
    Vault(path=tmp_path / "vault.json").add("value-on-fake-windows")
    assert FakeMsvcrt.calls == [1, 2]


def test_no_lock_backend_still_works(tmp_path, monkeypatch):
    from keyfence import vault as vault_module
    monkeypatch.setattr(vault_module, "fcntl", None)
    monkeypatch.setattr(vault_module, "msvcrt", None)
    v = Vault(path=tmp_path / "vault.json")
    assert v.add("value-without-any-lock")


def test_two_fresh_vaults_agree_on_the_salt(tmp_path):
    path = tmp_path / "vault.json"
    a, b = Vault(path=path), Vault(path=path)
    a.add("first-secret-value-1")
    b.add("second-secret-value-2")
    final = Vault(path=path)
    assert final.contains("first-secret-value-1") and final.contains("second-secret-value-2")
    assert a.salt == b.salt == final.salt


def test_chmod_failure_is_ignored(tmp_path, monkeypatch):
    def boom(*_args, **_kwargs):
        raise OSError("no chmod")
    monkeypatch.setattr("keyfence.vault.os.chmod", boom)
    v = Vault(path=tmp_path / "vault.json")
    assert v.add("persisted-secret-value")
