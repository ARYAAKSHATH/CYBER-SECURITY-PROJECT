import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordEncryption:
    @staticmethod
    def generate_salt():
        """Generate a random 32-byte salt for key derivation."""
        return os.urandom(32)
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes) -> bytes:
        """Derive an encryption key from password using PBKDF2."""
        password_bytes = password.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # NIST recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        return key
    
    @staticmethod
    def encrypt_password(plain_password: str, encryption_key: bytes) -> str:
        """Encrypt a password using Fernet symmetric encryption."""
        fernet = Fernet(encryption_key)
        encrypted_password = fernet.encrypt(plain_password.encode('utf-8'))
        return base64.urlsafe_b64encode(encrypted_password).decode('utf-8')
    
    @staticmethod
    def decrypt_password(encrypted_password: str, encryption_key: bytes) -> str:
        """Decrypt a password using Fernet symmetric encryption."""
        try:
            fernet = Fernet(encryption_key)
            encrypted_data = base64.urlsafe_b64decode(encrypted_password.encode('utf-8'))
            decrypted_password = fernet.decrypt(encrypted_data)
            return decrypted_password.decode('utf-8')
        except Exception as e:
            raise ValueError("Failed to decrypt password. Invalid key or corrupted data.")