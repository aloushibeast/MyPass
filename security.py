import os
import base64
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from werkzeug.security import generate_password_hash, check_password_hash


#Password hashing (for master password + security answers)

def hash_password(plain: str) -> str:
    return generate_password_hash(plain)


def verify_password(hashed: str, plain: str) -> bool:
    return check_password_hash(hashed, plain)


#AES-256 Encryption Helper

class AESEncryption:
    """
    Uses AES-256 GCM for encrypting sensitive fields in the vault.
    Key is derived from the user's master password + salt.
    """
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES key must be 32 bytes for AES-256")
        self.key = key

    def encrypt(self, plaintext: str) -> str:
        if plaintext is None:
            return None
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)  # 96-bit nonce
        data = plaintext.encode("utf-8")
        cipher = aesgcm.encrypt(nonce, data, None)
        return base64.b64encode(nonce + cipher).decode("utf-8")

    def decrypt(self, token: str) -> str:
        if token is None:
            return None
        raw = base64.b64decode(token.encode("utf-8"))
        nonce = raw[:12]
        cipher = raw[12:]
        aesgcm = AESGCM(self.key)
        data = aesgcm.decrypt(nonce, cipher, None)
        return data.decode("utf-8")


def derive_key_from_master(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from master password + salt using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return kdf.derive(master_password.encode("utf-8"))


def generate_salt() -> bytes:
    return secrets.token_bytes(16)


#Password Builder Pattern (for password generation)

@dataclass
class PasswordRequirements:
    length: int = 16
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True


class PasswordBuilder:
    def __init__(self):
        self.requirements = PasswordRequirements()

    def set_length(self, length: int):
        self.requirements.length = length
        return self

    def use_upper(self, flag: bool):
        self.requirements.use_upper = flag
        return self

    def use_lower(self, flag: bool):
        self.requirements.use_lower = flag
        return self

    def use_digits(self, flag: bool):
        self.requirements.use_digits = flag
        return self

    def use_symbols(self, flag: bool):
        self.requirements.use_symbols = flag
        return self

    def build(self) -> str:
        import string
        chars = ""
        if self.requirements.use_upper:
            chars += string.ascii_uppercase
        if self.requirements.use_lower:
            chars += string.ascii_lowercase
        if self.requirements.use_digits:
            chars += string.digits
        if self.requirements.use_symbols:
            chars += "!@#$%^&*()-_=+[]{};:,.<>/?"

        if not chars:
            chars = string.ascii_letters

        return "".join(secrets.choice(chars) for _ in range(self.requirements.length))
