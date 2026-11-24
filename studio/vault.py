"""Locking secrets that are kept for people, such as their own AI keys, so they are never stored as plain text.

AES-256-GCM: the saved text can only be read with the key, and any change to it (or moving it to someone else's row)
is noticed and refused. The key is 32 random bytes kept in its own file (config.SECRET_KEY_FILE), readable only by
the app, or given as PEAKCUT_SECRET_KEY. It is never written into the database or NeakClips' own folder by default
on a server: see DEPLOY.md.

Each locked value is bound to what it belongs to (the `purpose`, for example "ai_key:u_1234"), so a value copied
from one account to another cannot be opened there."""
import base64
import os
import secrets
import threading
from pathlib import Path

from . import config

_lock = threading.Lock()
_key = None
VERSION = "v1"


class VaultError(RuntimeError):
    pass


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        raise VaultError("The 'cryptography' package is missing. Run: pip install -r requirements.txt")
    return AESGCM


def _decode(text: str) -> bytes:
    text = (text or "").strip()
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raw = b""
    if len(raw) != 32:
        try:
            raw = bytes.fromhex(text)
        except ValueError:
            raw = b""
    if len(raw) != 32:
        raise VaultError("The secret key must be 32 bytes, written as base64 or hex.")
    return raw


def _load() -> bytes:
    if config.env("PEAKCUT_SECRET_KEY"):
        return _decode(config.env("PEAKCUT_SECRET_KEY"))
    f = Path(config.SECRET_KEY_FILE)
    if f.is_file():
        return _decode(f.read_text(encoding="ascii", errors="ignore"))
    # The first time: make a new key, readable by this app only.
    if not f.parent.exists():
        f.parent.mkdir(parents=True, mode=0o700)       # a folder of its own: only the app may look inside
    raw = secrets.token_bytes(32)
    fd = os.open(str(f), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as out:
        out.write(base64.urlsafe_b64encode(raw).decode() + "\n")
    print(f"  Made a new secret key for saved AI keys: {f}\n  Back this file up on its own.", flush=True)
    return raw


def key() -> bytes:
    global _key
    if _key is None:
        with _lock:
            if _key is None:
                _key = _load()
    return _key


def lock(plain: str, purpose: str) -> str:
    """The text, encrypted and bound to `purpose`. A fresh random nonce every time."""
    nonce = secrets.token_bytes(12)
    sealed = _aesgcm()(key()).encrypt(nonce, plain.encode("utf-8"), purpose.encode("utf-8"))
    return f"{VERSION}:" + base64.urlsafe_b64encode(nonce + sealed).decode()


def unlock(token: str, purpose: str) -> str:
    """The original text. Raises VaultError if it was changed, belongs elsewhere, or the key is not the same."""
    try:
        version, body = str(token or "").split(":", 1)
        raw = base64.urlsafe_b64decode(body)
    except (ValueError, TypeError):
        raise VaultError("Not a locked value.")
    if version != VERSION or len(raw) < 12 + 16:
        raise VaultError("Not a locked value.")
    try:
        return _aesgcm()(key()).decrypt(raw[:12], raw[12:], purpose.encode("utf-8")).decode("utf-8")
    except VaultError:
        raise
    except Exception:  # noqa: BLE001 - InvalidTag: changed, moved, or a different key
        raise VaultError("A saved secret could not be opened.")
