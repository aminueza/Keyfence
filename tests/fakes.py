def fake(*parts: str) -> str:
    return "".join(parts)


SLACK_TOKEN = fake("xoxb-", "1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx")
STRIPE_KEY = fake("sk_live_", "AbCdEfGhIjKlMnOpQrStUvWx")
TWILIO_KEY = fake("SK", "0123456789abcdef", "0123456789abcdef")
ADOBE_SECRET = fake("p8e-", "abcdefghijklmnop", "qrstuvwxyz123456")
SLACK_WEBHOOK =fake("https://hooks.slack.com/services/", "T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX")
