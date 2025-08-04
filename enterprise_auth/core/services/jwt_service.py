"""
JWT Token Service for Enterprise Authentication System.

This module provides comprehensive JWT token management including:
- RS256 signing algorithm with key rotation support
- Access token generation with 15-minute expiration
- Refresh token generation with 30-day expiration and rotation
- Device fingerprinting for token binding
- Token validation and introspection
- Distributed token blacklist management
"""

import uuid
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, asdict
from enum import Enum

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.conf import settings
from django.core.cache import caches
from django.utils import timezone
from django.http import HttpRequest

from ..models.user import UserProfile
from ..utils.encryption import encryption_service
from ..utils.request_utils import create_device_fingerprint, get_device_info, get_client_ip


class TokenType(Enum):
    """Enumeration of token types."""
    ACCESS = "access"
    REFRESH = "refresh"


class TokenStatus(Enum):
    """Enumeration of token statuses."""
    VALID = "valid"
    EXPIRED = "expired"
    INVALID = "invalid"
    BLACKLISTED = "blacklisted"
    REVOKED = "revoked"


@dataclass
class TokenClaims:
    """Data class for JWT token claims."""
    user_id: str
    email: str
    token_type: str
    token_id: str
    device_id: str
    device_fingerprint: str
    issued_at: int
    expires_at: int
    scopes: List[str]
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JWT payload."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TokenClaims':
        """Create TokenClaims from dictionary."""
        return cls(**data)


@dataclass
class TokenPair:
    """Data class for access and refresh token pair."""
    access_token: str
    refresh_token: str
    access_token_expires_at: datetime
    refresh_token_expires_at: datetime
    token_type: str = "Bearer"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token,
            'token_type': self.token_type,
            'expires_in': int((self.access_token_expires_at - timezone.now()).total_seconds()),
            'refresh_expires_in': int((self.refresh_token_expires_at - timezone.now()).total_seconds()),
        }


@dataclass
class TokenValidationResult:
    """Data class for token validation results."""
    status: TokenStatus
    claims: Optional[TokenClaims] = None
    error_message: Optional[str] = None
    
    @property
    def is_valid(self) -> bool:
        """Check if token is valid."""
        return self.status == TokenStatus.VALID
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return self.status == TokenStatus.EXPIRED


@dataclass
class DeviceInfo:
    """Data class for device information."""
    device_id: str
    device_fingerprint: str
    device_type: str
    browser: str
    operating_system: str
    ip_address: str
    user_agent: str
    
    @classmethod
    def from_request(cls, request: HttpRequest) -> 'DeviceInfo':
        """Create DeviceInfo from Django request."""
        device_info = get_device_info(request)
        device_fingerprint = create_device_fingerprint(request)
        
        # Create a unique device ID based on fingerprint and user agent
        device_data = f"{device_fingerprint}:{device_info['user_agent']}"
        device_id = hashlib.sha256(device_data.encode()).hexdigest()[:32]
        
        return cls(
            device_id=device_id,
            device_fingerprint=device_fingerprint,
            device_type=device_info['device_type'],
            browser=device_info['browser'],
            operating_system=device_info['operating_system'],
            ip_address=get_client_ip(request) or '',
            user_agent=device_info['user_agent'],
        )


class JWTKeyManager:
    """
    Manages JWT signing keys with rotation support.
    
    Uses RS256 algorithm with RSA key pairs for enhanced security.
    Supports key rotation for compliance and security best practices.
    """
    
    def __init__(self):
        self.cache = caches['default']
        self.cache_timeout = 3600  # 1 hour
        self._current_key_id = None
        self._private_key = None
        self._public_key = None
    
    def get_current_key_id(self) -> str:
        """Get the current key ID."""
        if not self._current_key_id:
            self._current_key_id = self.cache.get('jwt_current_key_id')
            if not self._current_key_id:
                self._current_key_id = self._generate_new_key_pair()
        return self._current_key_id
    
    def get_private_key(self, key_id: Optional[str] = None) -> rsa.RSAPrivateKey:
        """Get private key for signing."""
        if not key_id:
            key_id = self.get_current_key_id()
        
        if not self._private_key or key_id != self._current_key_id:
            encrypted_key = self.cache.get(f'jwt_private_key_{key_id}')
            if not encrypted_key:
                raise ValueError(f"Private key not found for key ID: {key_id}")
            
            # Decrypt the private key
            decrypted_key = encryption_service.decrypt(encrypted_key)
            self._private_key = serialization.load_pem_private_key(
                decrypted_key.encode(),
                password=None
            )
        
        return self._private_key
    
    def get_public_key(self, key_id: Optional[str] = None) -> rsa.RSAPublicKey:
        """Get public key for verification."""
        if not key_id:
            key_id = self.get_current_key_id()
        
        if not self._public_key or key_id != self._current_key_id:
            public_key_pem = self.cache.get(f'jwt_public_key_{key_id}')
            if not public_key_pem:
                raise ValueError(f"Public key not found for key ID: {key_id}")
            
            self._public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        return self._public_key
    
    def _generate_new_key_pair(self) -> str:
        """Generate a new RSA key pair and store in cache."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Generate key ID
        key_id = str(uuid.uuid4())
        
        # Encrypt and store private key
        encrypted_private_key = encryption_service.encrypt(private_pem.decode())
        self.cache.set(f'jwt_private_key_{key_id}', encrypted_private_key, self.cache_timeout)
        self.cache.set(f'jwt_public_key_{key_id}', public_pem.decode(), self.cache_timeout)
        self.cache.set('jwt_current_key_id', key_id, self.cache_timeout)
        
        # Store key metadata
        key_metadata = {
            'key_id': key_id,
            'created_at': timezone.now().isoformat(),
            'algorithm': 'RS256',
            'key_size': 2048,
        }
        self.cache.set(f'jwt_key_metadata_{key_id}', key_metadata, self.cache_timeout)
        
        return key_id
    
    def rotate_keys(self) -> str:
        """Rotate to a new key pair."""
        old_key_id = self.get_current_key_id()
        new_key_id = self._generate_new_key_pair()
        
        # Mark old key as rotated but keep it for verification
        old_metadata = self.cache.get(f'jwt_key_metadata_{old_key_id}', {})
        old_metadata['rotated_at'] = timezone.now().isoformat()
        old_metadata['status'] = 'rotated'
        self.cache.set(f'jwt_key_metadata_{old_key_id}', old_metadata, self.cache_timeout * 24)  # Keep for 24 hours
        
        # Reset cached keys
        self._current_key_id = new_key_id
        self._private_key = None
        self._public_key = None
        
        return new_key_id
    
    def get_key_metadata(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific key."""
        return self.cache.get(f'jwt_key_metadata_{key_id}')


class TokenBlacklistService:
    """
    Manages JWT token blacklist using Redis for distributed storage.
    
    Provides efficient token revocation and blacklist checking
    with automatic cleanup of expired entries.
    """
    
    def __init__(self):
        self.cache = caches['default']
        self.blacklist_prefix = 'jwt_blacklist'
    
    def blacklist_token(self, token_id: str, expires_at: datetime, reason: str = 'revoked') -> bool:
        """
        Add a token to the blacklist.
        
        Args:
            token_id: Unique token identifier
            expires_at: When the token expires
            reason: Reason for blacklisting
            
        Returns:
            True if successfully blacklisted
        """
        try:
            blacklist_data = {
                'token_id': token_id,
                'blacklisted_at': timezone.now().isoformat(),
                'expires_at': expires_at.isoformat(),
                'reason': reason,
            }
            
            # Calculate TTL based on token expiration
            ttl = int((expires_at - timezone.now()).total_seconds())
            if ttl > 0:
                cache_key = f'{self.blacklist_prefix}:{token_id}'
                self.cache.set(cache_key, blacklist_data, ttl)
                return True
            
            return False
        except Exception:
            return False
    
    def is_token_blacklisted(self, token_id: str) -> bool:
        """
        Check if a token is blacklisted.
        
        Args:
            token_id: Token identifier to check
            
        Returns:
            True if token is blacklisted
        """
        try:
            cache_key = f'{self.blacklist_prefix}:{token_id}'
            return self.cache.get(cache_key) is not None
        except Exception:
            return False
    
    def get_blacklist_info(self, token_id: str) -> Optional[Dict[str, Any]]:
        """
        Get blacklist information for a token.
        
        Args:
            token_id: Token identifier
            
        Returns:
            Blacklist information or None if not blacklisted
        """
        try:
            cache_key = f'{self.blacklist_prefix}:{token_id}'
            return self.cache.get(cache_key)
        except Exception:
            return None
    
    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired blacklisted tokens.
        
        Returns:
            Number of tokens cleaned up
        """
        # Redis automatically handles TTL expiration, so this is mainly for logging
        # In a real implementation, you might want to track cleanup statistics
        return 0
    
    def revoke_all_user_tokens(self, user_id: str, reason: str = 'user_revoked') -> bool:
        """
        Revoke all tokens for a specific user.
        
        This is a placeholder for bulk revocation functionality.
        In practice, you'd need to track active tokens per user.
        
        Args:
            user_id: User identifier
            reason: Reason for revocation
            
        Returns:
            True if successful
        """
        # This would require additional tracking of active tokens per user
        # For now, we'll implement this as a marker that can be checked
        try:
            revocation_data = {
                'user_id': user_id,
                'revoked_at': timezone.now().isoformat(),
                'reason': reason,
            }
            
            cache_key = f'jwt_user_revocation:{user_id}'
            # Set with a long TTL (30 days) to cover refresh token lifetime
            self.cache.set(cache_key, revocation_data, 30 * 24 * 3600)
            return True
        except Exception:
            return False
    
    def is_user_tokens_revoked(self, user_id: str, issued_at: datetime) -> bool:
        """
        Check if user tokens issued before a certain time are revoked.
        
        Args:
            user_id: User identifier
            issued_at: When the token was issued
            
        Returns:
            True if tokens are revoked
        """
        try:
            cache_key = f'jwt_user_revocation:{user_id}'
            revocation_data = self.cache.get(cache_key)
            
            if not revocation_data:
                return False
            
            revoked_at = datetime.fromisoformat(revocation_data['revoked_at'].replace('Z', '+00:00'))
            return issued_at < revoked_at
        except Exception:
            return False


class JWTService:
    """
    Comprehensive JWT token service for enterprise authentication.
    
    Provides secure token generation, validation, and management with:
    - RS256 signing algorithm
    - Device binding and fingerprinting
    - Token rotation and blacklisting
    - Comprehensive validation and introspection
    """
    
    def __init__(self):
        self.key_manager = JWTKeyManager()
        self.blacklist_service = TokenBlacklistService()
        self.cache = caches['default']
        
        # Token configuration from settings
        self.access_token_lifetime = timedelta(seconds=getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME', 900))  # 15 minutes
        self.refresh_token_lifetime = timedelta(seconds=getattr(settings, 'JWT_REFRESH_TOKEN_LIFETIME', 2592000))  # 30 days
        self.issuer = getattr(settings, 'JWT_ISSUER', 'enterprise-auth')
        self.audience = getattr(settings, 'JWT_AUDIENCE', 'enterprise-auth-clients')
    
    def generate_token_pair(
        self,
        user: UserProfile,
        device_info: DeviceInfo,
        scopes: Optional[List[str]] = None,
        session_id: Optional[str] = None
    ) -> TokenPair:
        """
        Generate an access and refresh token pair.
        
        Args:
            user: User for whom to generate tokens
            device_info: Device information for binding
            scopes: Optional list of scopes for the token
            session_id: Optional session identifier
            
        Returns:
            TokenPair with access and refresh tokens
        """
        now = timezone.now()
        access_expires_at = now + self.access_token_lifetime
        refresh_expires_at = now + self.refresh_token_lifetime
        
        # Generate unique token IDs
        access_token_id = str(uuid.uuid4())
        refresh_token_id = str(uuid.uuid4())
        
        # Default scopes
        if scopes is None:
            scopes = ['read', 'write']
        
        # Create access token claims
        access_claims = TokenClaims(
            user_id=str(user.id),
            email=user.email,
            token_type=TokenType.ACCESS.value,
            token_id=access_token_id,
            device_id=device_info.device_id,
            device_fingerprint=device_info.device_fingerprint,
            issued_at=int(now.timestamp()),
            expires_at=int(access_expires_at.timestamp()),
            scopes=scopes,
            session_id=session_id,
            ip_address=device_info.ip_address,
            user_agent=device_info.user_agent,
        )
        
        # Create refresh token claims
        refresh_claims = TokenClaims(
            user_id=str(user.id),
            email=user.email,
            token_type=TokenType.REFRESH.value,
            token_id=refresh_token_id,
            device_id=device_info.device_id,
            device_fingerprint=device_info.device_fingerprint,
            issued_at=int(now.timestamp()),
            expires_at=int(refresh_expires_at.timestamp()),
            scopes=scopes,
            session_id=session_id,
            ip_address=device_info.ip_address,
            user_agent=device_info.user_agent,
        )
        
        # Generate tokens
        access_token = self._create_jwt_token(access_claims)
        refresh_token = self._create_jwt_token(refresh_claims)
        
        # Store refresh token metadata for rotation tracking
        self._store_refresh_token_metadata(refresh_token_id, user.id, device_info.device_id, refresh_expires_at)
        
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            access_token_expires_at=access_expires_at,
            refresh_token_expires_at=refresh_expires_at,
        )
    
    def validate_access_token(self, token: str, device_fingerprint: Optional[str] = None) -> TokenValidationResult:
        """
        Validate an access token.
        
        Args:
            token: JWT token to validate
            device_fingerprint: Optional device fingerprint for binding validation
            
        Returns:
            TokenValidationResult with validation status and claims
        """
        try:
            # Decode and validate token
            claims = self._decode_jwt_token(token)
            
            if not claims:
                return TokenValidationResult(
                    status=TokenStatus.INVALID,
                    error_message="Invalid token format"
                )
            
            # Check token type
            if claims.token_type != TokenType.ACCESS.value:
                return TokenValidationResult(
                    status=TokenStatus.INVALID,
                    error_message="Invalid token type"
                )
            
            # Check if token is blacklisted
            if self.blacklist_service.is_token_blacklisted(claims.token_id):
                return TokenValidationResult(
                    status=TokenStatus.BLACKLISTED,
                    error_message="Token has been revoked"
                )
            
            # Check if user tokens are globally revoked
            issued_at = datetime.fromtimestamp(claims.issued_at, tz=timezone.utc)
            if self.blacklist_service.is_user_tokens_revoked(claims.user_id, issued_at):
                return TokenValidationResult(
                    status=TokenStatus.REVOKED,
                    error_message="User tokens have been revoked"
                )
            
            # Check device binding if provided
            if device_fingerprint and claims.device_fingerprint != device_fingerprint:
                return TokenValidationResult(
                    status=TokenStatus.INVALID,
                    error_message="Device fingerprint mismatch"
                )
            
            # Check expiration
            now = timezone.now()
            expires_at = datetime.fromtimestamp(claims.expires_at, tz=timezone.utc)
            if now >= expires_at:
                return TokenValidationResult(
                    status=TokenStatus.EXPIRED,
                    error_message="Token has expired"
                )
            
            return TokenValidationResult(
                status=TokenStatus.VALID,
                claims=claims
            )
            
        except jwt.ExpiredSignatureError:
            return TokenValidationResult(
                status=TokenStatus.EXPIRED,
                error_message="Token has expired"
            )
        except jwt.InvalidTokenError as e:
            return TokenValidationResult(
                status=TokenStatus.INVALID,
                error_message=f"Invalid token: {str(e)}"
            )
        except Exception as e:
            return TokenValidationResult(
                status=TokenStatus.INVALID,
                error_message=f"Token validation error: {str(e)}"
            )
    
    def refresh_token_pair(self, refresh_token: str, device_info: DeviceInfo) -> Optional[TokenPair]:
        """
        Refresh an access token using a refresh token.
        
        Args:
            refresh_token: Valid refresh token
            device_info: Device information for new tokens
            
        Returns:
            New TokenPair or None if refresh failed
        """
        try:
            # Validate refresh token
            validation_result = self._validate_refresh_token(refresh_token, device_info.device_fingerprint)
            
            if not validation_result.is_valid:
                return None
            
            claims = validation_result.claims
            
            # Get user
            try:
                user = UserProfile.objects.get(id=claims.user_id)
            except UserProfile.DoesNotExist:
                return None
            
            # Blacklist the old refresh token (rotation)
            expires_at = datetime.fromtimestamp(claims.expires_at, tz=timezone.utc)
            self.blacklist_service.blacklist_token(claims.token_id, expires_at, 'rotated')
            
            # Generate new token pair
            new_token_pair = self.generate_token_pair(
                user=user,
                device_info=device_info,
                scopes=claims.scopes,
                session_id=claims.session_id
            )
            
            return new_token_pair
            
        except Exception:
            return None
    
    def revoke_token(self, token: str, reason: str = 'user_revoked') -> bool:
        """
        Revoke a specific token.
        
        Args:
            token: Token to revoke
            reason: Reason for revocation
            
        Returns:
            True if successfully revoked
        """
        try:
            claims = self._decode_jwt_token(token)
            if not claims:
                return False
            
            expires_at = datetime.fromtimestamp(claims.expires_at, tz=timezone.utc)
            return self.blacklist_service.blacklist_token(claims.token_id, expires_at, reason)
            
        except Exception:
            return False
    
    def revoke_all_user_tokens(self, user_id: str, reason: str = 'security_incident') -> bool:
        """
        Revoke all tokens for a specific user.
        
        Args:
            user_id: User identifier
            reason: Reason for revocation
            
        Returns:
            True if successful
        """
        return self.blacklist_service.revoke_all_user_tokens(user_id, reason)
    
    def introspect_token(self, token: str) -> Dict[str, Any]:
        """
        Introspect a token and return its metadata.
        
        Args:
            token: Token to introspect
            
        Returns:
            Dictionary with token metadata
        """
        validation_result = self.validate_access_token(token)
        
        introspection_data = {
            'active': validation_result.is_valid,
            'token_type': 'Bearer',
        }
        
        if validation_result.claims:
            claims = validation_result.claims
            introspection_data.update({
                'user_id': claims.user_id,
                'email': claims.email,
                'scopes': claims.scopes,
                'device_id': claims.device_id,
                'issued_at': claims.issued_at,
                'expires_at': claims.expires_at,
                'session_id': claims.session_id,
            })
        
        if not validation_result.is_valid:
            introspection_data['error'] = validation_result.error_message
        
        return introspection_data
    
    def _create_jwt_token(self, claims: TokenClaims) -> str:
        """Create a JWT token from claims."""
        # Get current signing key
        key_id = self.key_manager.get_current_key_id()
        private_key = self.key_manager.get_private_key(key_id)
        
        # Prepare JWT payload
        payload = claims.to_dict()
        payload.update({
            'iss': self.issuer,
            'aud': self.audience,
            'iat': claims.issued_at,
            'exp': claims.expires_at,
            'jti': claims.token_id,
        })
        
        # Create JWT headers
        headers = {
            'kid': key_id,
            'alg': 'RS256',
            'typ': 'JWT',
        }
        
        # Sign and return token
        return jwt.encode(
            payload=payload,
            key=private_key,
            algorithm='RS256',
            headers=headers
        )
    
    def _decode_jwt_token(self, token: str) -> Optional[TokenClaims]:
        """Decode and validate a JWT token."""
        try:
            # Decode header to get key ID
            unverified_header = jwt.get_unverified_header(token)
            key_id = unverified_header.get('kid')
            
            if not key_id:
                return None
            
            # Get public key for verification
            public_key = self.key_manager.get_public_key(key_id)
            
            # Decode and verify token
            payload = jwt.decode(
                jwt=token,
                key=public_key,
                algorithms=['RS256'],
                audience=self.audience,
                issuer=self.issuer,
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_iat': True,
                    'verify_aud': True,
                    'verify_iss': True,
                }
            )
            
            # Convert to TokenClaims
            return TokenClaims.from_dict(payload)
            
        except Exception:
            return None
    
    def _validate_refresh_token(self, token: str, device_fingerprint: Optional[str] = None) -> TokenValidationResult:
        """Validate a refresh token."""
        try:
            claims = self._decode_jwt_token(token)
            
            if not claims:
                return TokenValidationResult(
                    status=TokenStatus.INVALID,
                    error_message="Invalid token format"
                )
            
            # Check token type
            if claims.token_type != TokenType.REFRESH.value:
                return TokenValidationResult(
                    status=TokenStatus.INVALID,
                    error_message="Invalid token type"
                )
            
            # Check if token is blacklisted
            if self.blacklist_service.is_token_blacklisted(claims.token_id):
                return TokenValidationResult(
                    status=TokenStatus.BLACKLISTED,
                    error_message="Token has been revoked"
                )
            
            # Check device binding if provided
            if device_fingerprint and claims.device_fingerprint != device_fingerprint:
                return TokenValidationResult(
                    status=TokenStatus.INVALID,
                    error_message="Device fingerprint mismatch"
                )
            
            # Check expiration
            now = timezone.now()
            expires_at = datetime.fromtimestamp(claims.expires_at, tz=timezone.utc)
            if now >= expires_at:
                return TokenValidationResult(
                    status=TokenStatus.EXPIRED,
                    error_message="Token has expired"
                )
            
            return TokenValidationResult(
                status=TokenStatus.VALID,
                claims=claims
            )
            
        except jwt.ExpiredSignatureError:
            return TokenValidationResult(
                status=TokenStatus.EXPIRED,
                error_message="Token has expired"
            )
        except jwt.InvalidTokenError as e:
            return TokenValidationResult(
                status=TokenStatus.INVALID,
                error_message=f"Invalid token: {str(e)}"
            )
        except Exception as e:
            return TokenValidationResult(
                status=TokenStatus.INVALID,
                error_message=f"Token validation error: {str(e)}"
            )
    
    def _store_refresh_token_metadata(self, token_id: str, user_id: str, device_id: str, expires_at: datetime) -> None:
        """Store refresh token metadata for tracking."""
        metadata = {
            'token_id': token_id,
            'user_id': user_id,
            'device_id': device_id,
            'created_at': timezone.now().isoformat(),
            'expires_at': expires_at.isoformat(),
            'status': 'active',
        }
        
        # Store with TTL based on token expiration
        ttl = int((expires_at - timezone.now()).total_seconds())
        if ttl > 0:
            cache_key = f'jwt_refresh_metadata:{token_id}'
            self.cache.set(cache_key, metadata, ttl)


# Global JWT service instance
jwt_service = JWTService()