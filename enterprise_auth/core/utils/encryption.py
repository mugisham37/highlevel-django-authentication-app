"""
Encryption utilities for sensitive data storage.

This module provides secure encryption/decryption utilities for storing
sensitive data like OAuth tokens, MFA secrets, and other confidential information.
Uses Fernet symmetric encryption with key derivation from Django's SECRET_KEY.
"""

import base64
import hashlib
import secrets
from typing import Optional, Union

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


class EncryptionError(Exception):
    """Base exception for encryption-related errors."""
    pass


class DecryptionError(EncryptionError):
    """Exception raised when decryption fails."""
    pass


class EncryptionService:
    """
    Service for encrypting and decrypting sensitive data.
    
    Uses Fernet symmetric encryption with PBKDF2 key derivation.
    Each encrypted value includes a unique salt for additional security.
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        """
        Initialize the encryption service.
        
        Args:
            secret_key: Optional secret key. If not provided, uses Django's SECRET_KEY.
        """
        self.secret_key = secret_key or settings.SECRET_KEY
        if not self.secret_key:
            raise ImproperlyConfigured("SECRET_KEY must be set for encryption")
    
    def _derive_key(self, salt: bytes) -> bytes:
        """
        Derive encryption key from secret key and salt using PBKDF2.
        
        Args:
            salt: Random salt bytes
            
        Returns:
            Derived key bytes suitable for Fernet
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # OWASP recommended minimum
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.secret_key.encode()))
        return key
    
    def encrypt(self, data: Union[str, bytes]) -> str:
        """
        Encrypt data with a unique salt.
        
        Args:
            data: Data to encrypt (string or bytes)
            
        Returns:
            Base64-encoded encrypted data with embedded salt
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Generate random salt
            salt = secrets.token_bytes(16)
            
            # Derive key from secret and salt
            key = self._derive_key(salt)
            fernet = Fernet(key)
            
            # Encrypt the data
            encrypted_data = fernet.encrypt(data)
            
            # Combine salt and encrypted data
            combined = salt + encrypted_data
            
            # Return base64-encoded result
            return base64.urlsafe_b64encode(combined).decode('ascii')
            
        except Exception as e:
            raise EncryptionError(f"Failed to encrypt data: {str(e)}") from e
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt data that was encrypted with encrypt().
        
        Args:
            encrypted_data: Base64-encoded encrypted data with embedded salt
            
        Returns:
            Decrypted data as string
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            # Decode base64
            combined = base64.urlsafe_b64decode(encrypted_data.encode('ascii'))
            
            # Extract salt and encrypted data
            salt = combined[:16]
            encrypted_bytes = combined[16:]
            
            # Derive key from secret and salt
            key = self._derive_key(salt)
            fernet = Fernet(key)
            
            # Decrypt the data
            decrypted_data = fernet.decrypt(encrypted_bytes)
            
            return decrypted_data.decode('utf-8')
            
        except (InvalidToken, ValueError, UnicodeDecodeError) as e:
            raise DecryptionError(f"Failed to decrypt data: {str(e)}") from e
        except Exception as e:
            raise DecryptionError(f"Unexpected error during decryption: {str(e)}") from e
    
    def encrypt_dict(self, data: dict) -> dict:
        """
        Encrypt all string values in a dictionary.
        
        Args:
            data: Dictionary with string values to encrypt
            
        Returns:
            Dictionary with encrypted string values
        """
        encrypted = {}
        for key, value in data.items():
            if isinstance(value, str):
                encrypted[key] = self.encrypt(value)
            elif isinstance(value, dict):
                encrypted[key] = self.encrypt_dict(value)
            else:
                encrypted[key] = value
        return encrypted
    
    def decrypt_dict(self, encrypted_data: dict) -> dict:
        """
        Decrypt all encrypted string values in a dictionary.
        
        Args:
            encrypted_data: Dictionary with encrypted string values
            
        Returns:
            Dictionary with decrypted string values
        """
        decrypted = {}
        for key, value in encrypted_data.items():
            if isinstance(value, str):
                try:
                    decrypted[key] = self.decrypt(value)
                except DecryptionError:
                    # If decryption fails, assume it's not encrypted
                    decrypted[key] = value
            elif isinstance(value, dict):
                decrypted[key] = self.decrypt_dict(value)
            else:
                decrypted[key] = value
        return decrypted


class HashingService:
    """
    Service for creating secure hashes of sensitive data.
    
    Useful for creating searchable hashes of sensitive data
    without storing the actual values.
    """
    
    @staticmethod
    def hash_data(data: Union[str, bytes], salt: Optional[bytes] = None) -> str:
        """
        Create a secure hash of data using SHA-256.
        
        Args:
            data: Data to hash
            salt: Optional salt. If not provided, generates random salt.
            
        Returns:
            Base64-encoded hash with embedded salt
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if salt is None:
            salt = secrets.token_bytes(16)
        
        # Create hash with salt
        hasher = hashlib.sha256()
        hasher.update(salt)
        hasher.update(data)
        hash_bytes = hasher.digest()
        
        # Combine salt and hash
        combined = salt + hash_bytes
        
        return base64.urlsafe_b64encode(combined).decode('ascii')
    
    @staticmethod
    def verify_hash(data: Union[str, bytes], hashed_data: str) -> bool:
        """
        Verify that data matches the given hash.
        
        Args:
            data: Original data to verify
            hashed_data: Base64-encoded hash with embedded salt
            
        Returns:
            True if data matches hash, False otherwise
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Decode the hash
            combined = base64.urlsafe_b64decode(hashed_data.encode('ascii'))
            
            # Extract salt and hash
            salt = combined[:16]
            original_hash = combined[16:]
            
            # Create hash of provided data with same salt
            hasher = hashlib.sha256()
            hasher.update(salt)
            hasher.update(data)
            new_hash = hasher.digest()
            
            # Compare hashes using constant-time comparison
            return secrets.compare_digest(original_hash, new_hash)
            
        except Exception:
            return False


# Global encryption service instance
encryption_service = EncryptionService()


def encrypt_sensitive_data(data: Union[str, bytes]) -> str:
    """
    Convenience function to encrypt sensitive data.
    
    Args:
        data: Data to encrypt
        
    Returns:
        Encrypted data as base64 string
    """
    return encryption_service.encrypt(data)


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """
    Convenience function to decrypt sensitive data.
    
    Args:
        encrypted_data: Encrypted data as base64 string
        
    Returns:
        Decrypted data as string
    """
    return encryption_service.decrypt(encrypted_data)


def hash_sensitive_data(data: Union[str, bytes]) -> str:
    """
    Convenience function to hash sensitive data.
    
    Args:
        data: Data to hash
        
    Returns:
        Hash as base64 string
    """
    return HashingService.hash_data(data)


def verify_sensitive_hash(data: Union[str, bytes], hashed_data: str) -> bool:
    """
    Convenience function to verify sensitive data hash.
    
    Args:
        data: Original data
        hashed_data: Hash to verify against
        
    Returns:
        True if data matches hash
    """
    return HashingService.verify_hash(data, hashed_data)