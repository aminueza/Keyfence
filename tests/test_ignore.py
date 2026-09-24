import json

from keyfence.ignore import IgnoreList
from keyfence.vault import Vault, value_digest

SALT = b"s" * 32
HOST = "db.internal.example.com"


def test_keys_match_case_insensitively_and_exactly():
    ignore = IgnoreList(SALT, ["DB_HOST", "service_name", "db_host"])
    assert ignore.ignores_key("db_host") and ignore.ignores_key("SERVICE_NAME")
    assert not ignore.ignores_key("DB_HOSTNAME") and not ignore.ignores_key("db")
    assert not ignore.ignores_key(None) and not ignore.ignores_key("")
    assert ignore.key_count == 2


def test_keys_accept_glob_patterns():
    ignore = IgnoreList(SALT, ["*_HOST", "REGION_?"])
    assert ignore.ignores_key("db_host") and ignore.ignores_key("Region_1")
    assert not ignore.ignores_key("host") and not ignore.ignores_key("REGION_10")


def test_values_match_by_salted_digest_and_the_clear_value_is_not_kept():
    ignore = IgnoreList(SALT, values=[HOST])
    assert ignore.ignores_value(HOST)
    assert not ignore.ignores_value(HOST + ".") and not ignore.ignores_value("")
    assert ignore.value_count == 1
    assert HOST not in repr(vars(ignore))
    assert value_digest(SALT, HOST) in repr(vars(ignore))


def test_digest_scheme_is_the_vaults(tmp_path):
    vault = Vault(path=tmp_path / "vault.json")
    vault.add(HOST)
    stored = json.loads((tmp_path / "vault.json").read_text())["hashes"]
    assert stored == [value_digest(vault.salt, HOST)]
    assert IgnoreList(vault.salt, values=[HOST]).ignores_value(HOST)
    assert IgnoreList(vault.salt, values=[HOST]).ignores_value("x") is False


def test_empty_list_ignores_nothing():
    ignore = IgnoreList()
    assert not ignore.ignores("DB_HOST", HOST)
    assert ignore.key_count == 0 and ignore.value_count == 0


def test_ignores_combines_key_and_value():
    ignore = IgnoreList(SALT, ["DB_HOST"], [HOST])
    assert ignore.ignores("DB_HOST", "whatever") and ignore.ignores("OTHER", HOST)
    assert ignore.ignores(None, HOST)
    assert not ignore.ignores("OTHER", "whatever") and not ignore.ignores(None, "whatever")
