import json

from keyfence.importer import (
    default_paths, env_values, import_files, looks_secret,
    values_from_file, values_from_json, values_from_text,
)
from keyfence.vault import Vault

MIN = 8


def test_dotenv_secret_names_are_imported():
    text = (
        "# comment\n"
        "export OPENAI_API_KEY=sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv\n"
        "DB_PASSWORD='hunter2hunter2!'\n"
        "NODE_ENV=production\n"
        "PORT=3000\n"
        "SECRET_SHORT=abc\n"
        "TEMPLATED=${OTHER}\n"
        "ANGLE=<fill-me-in-please>\n"
        "HOME_DIR=/Users/someone/projects\n"
    )
    found = values_from_text(text, MIN)
    assert found == {"sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv", "hunter2hunter2!"}


def test_high_entropy_values_are_imported_regardless_of_name():
    found = values_from_text("MYSTERY=Zq8xK2mP9vL4nR7tW3yB6cF1dH5j\n", MIN)
    assert found == {"Zq8xK2mP9vL4nR7tW3yB6cF1dH5j"}


def test_everything_flag_imports_all_long_values():
    found = values_from_text("NODE_ENV=production\nPORT=3000\n", MIN, everything=True)
    assert found == {"production"}


def test_database_url_password_is_extracted():
    found = values_from_text("DATABASE_URL=postgres://app:s3cretPassw0rd@db:5432/app\n", MIN)
    assert "s3cretPassw0rd" in found
    assert "postgres://app:s3cretPassw0rd@db:5432/app" in found


def test_plain_url_without_userinfo_is_skipped():
    assert values_from_text("API_URL=https://api.example.com/v1/endpoint\n", MIN) == set()


def test_git_credentials_line():
    found = values_from_text("https://amanda:ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789@github.com\n", MIN)
    assert "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" in found


def test_netrc_password():
    found = values_from_text("machine api.example.com login me password s3cretPassw0rd\n", MIN)
    assert found == {"s3cretPassw0rd"}


def test_aws_credentials_ini():
    text = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    found = values_from_text(text, MIN)
    assert found == {"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}


def test_npmrc_auth_token():
    found = values_from_text("//registry.npmjs.org/:_authToken=npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n", MIN)
    assert found == {"npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"}


def test_json_walk_uses_key_names():
    obj = {"auths": {"https://index.docker.io/v1/": {"auth": "dXNlcjpzZWNyZXRwYXNz"}},
           "list": [{"password": "listedPassword1"}], "n": 3, "url": "https://x.example/"}
    found = values_from_json(obj, MIN)
    assert found == {"dXNlcjpzZWNyZXRwYXNz", "listedPassword1"}


def test_values_from_file_json_and_fallback(tmp_path):
    good = tmp_path / "config.json"
    good.write_text(json.dumps({"token": "jsonTokenValue123"}))
    assert values_from_file(good, MIN) == {"jsonTokenValue123"}
    broken = tmp_path / "broken.json"
    broken.write_text("token=textTokenValue123\nnot json")
    assert values_from_file(broken, MIN) == {"textTokenValue123"}


def test_looks_secret_rules():
    assert looks_secret("API_KEY", "abcdefgh", MIN)
    assert not looks_secret("API_KEY", "abc", MIN)
    assert not looks_secret("NAME", "aaaabbbbccccddddeeee", MIN)
    assert looks_secret("NAME", "Zq8xK2mP9vL4nR7tW3yB6cF1dH5j", MIN)


def test_env_values_filters_names():
    environ = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "HOME": "/Users/someone",
        "KEYFENCE_HOME": "/tmp/whatever-long-path",
        "GITHUB_TOKEN": "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "SHORT_KEY": "abc",
        "ANTHROPIC_API_KEY": "sk-ant-api03-xYz123AbC456dEf789GhI012jKl345MnO",
    }
    assert env_values(environ, MIN) == {
        "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        "sk-ant-api03-xYz123AbC456dEf789GhI012jKl345MnO",
    }
    assert "/Users/someone" not in env_values(environ, MIN, everything=True)
    assert "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" in env_values(environ, MIN, everything=True)


def test_default_paths(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("A=1\n")
    (tmp_path / ".env.local").write_text("A=1\n")
    (tmp_path / ".env.example").write_text("A=1\n")
    (tmp_path / ".envrc").mkdir()
    fake_home = tmp_path / "home"
    (fake_home / ".aws").mkdir(parents=True)
    (fake_home / ".aws" / "credentials").write_text("[default]\n")
    monkeypatch.setattr("keyfence.importer.Path.home", classmethod(lambda cls: fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    paths = default_paths(tmp_path)
    names = [p.name for p in paths]
    assert names[:2] == [".env", ".env.local"]
    assert ".env.example" not in names
    assert paths[-1] == fake_home / ".aws" / "credentials"


def test_import_files_reports_per_file(tmp_path):
    vault = Vault(path=tmp_path / "vault.json")
    env = tmp_path / ".env"
    env.write_text("API_KEY=firstSecretValue1\n")
    empty = tmp_path / "empty.env"
    empty.write_text("PORT=1\n")
    report = import_files(vault, [env, empty])
    assert report == [(env, 1), (empty, 0)]
    assert vault.contains("firstSecretValue1")
    assert (tmp_path / "vault.json").read_text().count("firstSecretValue1") == 0
