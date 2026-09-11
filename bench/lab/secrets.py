from __future__ import annotations

import random
import string

ALNUM = string.ascii_letters + string.digits
BASE32 = string.ascii_uppercase + "234567"
B64 = ALNUM + "+/"


def _rand(rng: random.Random, n: int, alphabet: str = ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _pem(rng: random.Random) -> str:
    body = "".join(rng.choice(B64) for _ in range(64 * 25))
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----"


def fake_secrets(seed: int) -> dict[str, str]:
    rng = random.Random(seed)
    return {
        "GITHUB_TOKEN": "ghp_" + _rand(rng, 36),
        "AWS_ACCESS_KEY_ID": "AKIA" + _rand(rng, 16, BASE32),
        "AWS_SECRET_ACCESS_KEY": _rand(rng, 40, B64),
        "DATABASE_PASSWORD": _rand(rng, 12, string.ascii_lowercase) + "-" + _rand(rng, 4, string.digits) + "-" + _rand(rng, 8, string.ascii_lowercase),
        "STRIPE_SECRET_KEY": "sk_test_" + _rand(rng, 24),
    }


def dotenv(seed: int) -> str:
    values = fake_secrets(seed)
    lines = [f"{k}={v}" for k, v in values.items()]
    lines.append("APP_ENV=production")
    lines.append("PORT=8080")
    return "\n".join(lines) + "\n"


def private_key(seed: int) -> str:
    return _pem(random.Random(seed + 1)) + "\n"
