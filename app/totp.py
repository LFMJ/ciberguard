"""Códigos de un solo uso (TOTP, RFC 6238) compatibles con Google Authenticator, Microsoft Authenticator, etc."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def now_code(secret, at=None):
    return _code(secret, int((at or time.time()) // STEP))


def verify(secret, code, last_step=None, at=None):
    """Devuelve el paso de tiempo aceptado, o None. Tolera ±30 s de desfase del reloj y rechaza códigos ya usados."""
    code = (code or "").replace(" ", "")
    if not secret or len(code) != DIGITS or not code.isdigit():
        return None
    current = int((at or time.time()) // STEP)
    for step in (current - 1, current, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(_code(secret, step), code):
            return step
    return None


def provisioning_uri(secret, username, issuer="CiberGuard"):
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&digits={DIGITS}&period={STEP}"


def qr_data_uri(uri):
    import segno

    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2)


def format_secret(secret):
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
