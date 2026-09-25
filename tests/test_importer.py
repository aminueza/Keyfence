import json

from keyfence.ignore import IgnoreList
from keyfence.importer import (
    default_paths, env_values, import_files, looks_secret,
    values_from_file, values_from_json, values_from_text,
    _joins_secret_words,
)
from keyfence.vault import Vault

MIN = 8
HOST = "db.internal.example.com"
API_KEY = "sk-proj-Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv"
ISSUE_ENV = (
    "DB_PASSWORD=hunter2hunter2!\n"
    f"API_KEY={API_KEY}\n"
    f"DB_HOST={HOST}\n"
    "OWNER=platform-team\n"
)


def ignoring(keys=(), values=()):
    return IgnoreList(b"salt" * 8, keys, values)


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


def test_hostname_is_registered_by_entropy_without_ignore_lists():
    assert values_from_text(ISSUE_ENV, MIN) == {"hunter2hunter2!", API_KEY, HOST}


def test_ignored_key_is_skipped_even_with_everything():
    found = values_from_text(ISSUE_ENV, MIN, ignore=ignoring(keys=["db_host"]))
    assert found == {"hunter2hunter2!", API_KEY}
    everything = values_from_text(ISSUE_ENV, MIN, everything=True, ignore=ignoring(keys=["DB_HOST", "owner"]))
    assert everything == {"hunter2hunter2!", API_KEY}


def test_ignored_key_skips_the_url_password_too():
    url = "DATABASE_URL=postgres://app:s3cretPassw0rd@db:5432/app\n"
    assert "s3cretPassw0rd" in values_from_text(url, MIN)
    assert values_from_text(url, MIN, ignore=ignoring(keys=["DATABASE_URL"])) == set()


def test_ignored_value_is_skipped_wherever_it_appears():
    ignore = ignoring(values=[HOST, "s3cretPassw0rd"])
    assert values_from_text(ISSUE_ENV, MIN, ignore=ignore) == {"hunter2hunter2!", API_KEY}
    assert values_from_text(ISSUE_ENV, MIN, everything=True, ignore=ignore) == {"hunter2hunter2!", API_KEY, "platform-team"}
    url = "DATABASE_URL=postgres://app:s3cretPassw0rd@db:5432/app\n"
    assert values_from_text(url, MIN, ignore=ignore) == {"postgres://app:s3cretPassw0rd@db:5432/app"}
    netrc = "machine api.example.com login me password s3cretPassw0rd\n"
    assert values_from_text(netrc, MIN, ignore=ignore) == set()
    bare = "https://amanda:s3cretPassw0rd@github.com\n"
    assert "s3cretPassw0rd" in values_from_text(bare, MIN)
    assert "s3cretPassw0rd" not in values_from_text(bare, MIN, ignore=ignore)


def test_json_walk_honours_ignore_lists():
    obj = {"auths": {"registry": {"auth": "dXNlcjpzZWNyZXRwYXNz"}}, "db_host": HOST, "token": "listedToken12345"}
    assert values_from_json(obj, MIN, everything=True) == {"dXNlcjpzZWNyZXRwYXNz", HOST, "listedToken12345"}
    ignore = ignoring(keys=["auth"], values=["listedToken12345"])
    assert values_from_json(obj, MIN, everything=True, ignore=ignore) == {HOST}


def test_env_values_honour_ignore_lists():
    token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    environ = {"GITHUB_TOKEN": token, "DB_HOST": HOST, "SERVICE_NAME": "billing-service-eu", "OTHER": HOST}
    ignore = ignoring(keys=["*_NAME", "DB_HOST"], values=[HOST])
    assert env_values(environ, MIN, everything=True, ignore=ignore) == {token}
    assert env_values(environ, MIN, everything=True) == {token, HOST, "billing-service-eu"}


def test_import_files_honour_ignore_lists(tmp_path):
    vault = Vault(path=tmp_path / "vault.json")
    env = tmp_path / ".env"
    env.write_text(ISSUE_ENV)
    ignore = IgnoreList(vault.salt, ["DB_HOST"], ["hunter2hunter2!"])
    assert import_files(vault, [env], ignore=ignore) == [(env, 1)]
    assert vault.contains(API_KEY)
    assert not vault.contains(HOST) and not vault.contains("hunter2hunter2!")
    raw = (tmp_path / "vault.json").read_text()
    assert HOST not in raw and "hunter2hunter2!" not in raw
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"token": "jsonTokenValue123", "db_host": HOST}))
    assert values_from_file(config, MIN, everything=True, ignore=ignore) == {"jsonTokenValue123"}


def test_secret_name_matches_whole_words_only():
    assert not looks_secret("GIT_AUTHOR_EMAIL", "dev@example.com", MIN)
    assert not looks_secret("GIT_AUTHOR_NAME", "Jane Doe", MIN)
    assert not looks_secret("KEYBOARD_LAYOUT", "us-intl-mac", MIN)
    assert not looks_secret("MONKEY_ISLAND", "game-save-3", MIN)
    assert not looks_secret("COMPASS_URL", "localhost:9000", MIN)
    assert not looks_secret("BYPASS_CACHE", "sometimes", MIN)
    assert not looks_secret("CAPITAL_CITY", "Amsterdam-NL", MIN)
    assert not looks_secret("RAPID_MODE", "always-on", MIN)
    assert looks_secret("GIT_AUTHOR_TOKEN", "dev@example.com", MIN)


def test_one_letter_segment_is_not_a_secret_name():
    assert not looks_secret("AWS_S3_BUCKET", "acme-bucket", MIN)
    assert not looks_secret("S3_ENDPOINT", "localhost:9000", MIN)
    assert not looks_secret("s3Client", "acme-bucket", MIN)
    assert env_values({"AWS_S3_BUCKET": "acme-bucket"}, MIN) == set()


def test_secret_name_still_matches_real_secret_names():
    for name in ("GITHUB_TOKEN", "DB_PASSWORD", "STRIPE_SECRET_KEY", "OPENAI_APIKEY",
                 "authToken", "aws_secret_access_key", "credentials", "SESSION_COOKIE",
                 "senha", "SENTRY_DSN", "PRIVATE_KEY", "_authToken", "apiKeys",
                 "PASSPHRASE", "GPG_PASSPHRASE", "SSH_PASSCODE", "AUTHORIZATION",
                 "PGPASSWORD", "SSHPASS", "ACCESSTOKEN", "REFRESHTOKEN",
                 "CLIENTSECRET", "DBPASSWORD", "SECRETACCESSKEY",
                 "//registry.npmjs.org/:_authToken"):
        assert looks_secret(name, "short-value", MIN), name


def test_a_name_that_points_at_a_file_is_not_a_secret_name():
    assert not looks_secret("PGPASSFILE", "pgpass.conf", MIN)
    assert not looks_secret("HTPASSWD_PATH", "site.htpasswd", MIN)


def test_a_word_glued_in_front_of_a_long_secret_word_still_matches():
    assert looks_secret("DBPASSWORD", "hunter2hunter", MIN)
    assert not looks_secret("TOKENIZER_PATH", "bpe-v2.model", MIN)
    assert not looks_secret("SECRETARY_DESK", "room-14-desk", MIN)
    assert not looks_secret("MONKEYKEY", "game-save-3", MIN)


def test_env_values_keeps_the_git_author_email():
    environ = {"GIT_AUTHOR_EMAIL": "dev@example.com", "GITHUB_TOKEN": "tokenValue123"}
    assert env_values(environ, MIN) == {"tokenValue123"}


def test_acronym_glued_to_camelcase_matches():
    assert looks_secret("APIkey", "short-value", MIN)
    assert looks_secret("googleAPIkey", "short-value", MIN)


def test_glued_pass_names_match():
    for name in ("DBPASS", "SMTPPASS", "ADMINPASS", "DBPASSWD", "KEYSTOREPASS", "DBSENHA"):
        assert looks_secret(name, "short-value", MIN), name


def test_glued_pass_false_positives_stay_out():
    assert not looks_secret("COMPASS_URL", "localhost:9000", MIN)
    assert not looks_secret("BYPASS_CACHE", "sometimes", MIN)
    assert not looks_secret("HTPASSWD_PATH", "site.htpasswd", MIN)


def test_length_bound_in_joins_secret_words():
    # A long segment that is NOT composed of secret words.
    # Without the length bound (first = 0), this would be O(n^2) and slow.
    # With the bound, it's O(n * _LONGEST_SECRET_WORD) and fast.
    long_segment = "x" * 5000
    import time
    start = time.monotonic()
    result = _joins_secret_words(long_segment)
    elapsed = time.monotonic() - start
    assert result is False
    assert elapsed < 0.5, f"took {elapsed:.3f}s, bound not effective"
