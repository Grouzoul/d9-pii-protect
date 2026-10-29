"""Chiffrement réversible des PII — AES-256-GCM, marqueurs auto-porteurs [[PII:TYPE:b64]].

La sécurité repose sur la CUSTODY DE LA CLÉ (PII_PROTECT_KEY), pas sur l'obscurité.
Nonce aléatoire par valeur -> pas de fuite d'égalité ; pas de déchiffrement sans la clé.
"""
import base64, os, re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ===== CLÉ : en prod, injecter via secret / KMS. Pas de valeur par défaut en production. =====
_KEY = (os.environ.get("PII_PROTECT_KEY") or "demo-key-change-me-0123456789abc").encode()[:32].ljust(32, b"0")
_aes = AESGCM(_KEY)

MARKER_RE = re.compile(r"\[\[PII:([A-Z_]+):([A-Za-z0-9_\-]+={0,2})\]\]")

def encrypt(plain: str) -> str:
    nonce = os.urandom(12)
    return base64.urlsafe_b64encode(nonce + _aes.encrypt(nonce, plain.encode(), None)).decode()

def decrypt(token: str) -> str:
    raw = base64.urlsafe_b64decode(token.encode())
    return _aes.decrypt(raw[:12], raw[12:], None).decode()

def marker(entity: str, plain: str) -> str:
    return f"[[PII:{entity}:{encrypt(plain)}]]"

def rehydrate(text: str):
    """Remplace chaque marqueur par sa valeur déchiffrée. Retourne (texte, nb)."""
    n = 0
    def repl(m):
        nonlocal n
        try:
            v = decrypt(m.group(2)); n += 1; return v
        except Exception:
            return m.group(0)
    return MARKER_RE.sub(repl, text), n
