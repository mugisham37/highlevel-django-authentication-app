"""
Services package for enterprise authentication system.
"""

from .password_service import PasswordService
from .email_verification_service import EmailVerificationService
from .audit_service import AuditService, audit_service
from .jwt_service import (
    JWTService, 
    JWTKeyManager, 
    TokenBlacklistService, 
    jwt_service,
    TokenType,
    TokenStatus,
    TokenClaims,
    TokenPair,
    TokenValidationResult,
    DeviceInfo,
)
from .oauth_provider import (
    IOAuthProvider,
    BaseOAuthProvider,
    ProviderConfig,
    TokenData,
    NormalizedUserData,
    AuthorizationRequest,
)
from .oauth_registry import (
    OAuthProviderRegistry,
    ProviderInfo,
    oauth_registry,
)
from .oauth_config import (
    OAuthConfigManager,
    oauth_config_manager,
)
from .oauth_service import (
    OAuthService,
    oauth_service,
)

__all__ = [
    'PasswordService',
    'EmailVerificationService',
    'AuditService',
    'audit_service',
    'JWTService',
    'JWTKeyManager',
    'TokenBlacklistService',
    'jwt_service',
    'TokenType',
    'TokenStatus',
    'TokenClaims',
    'TokenPair',
    'TokenValidationResult',
    'DeviceInfo',
    # OAuth provider abstraction
    'IOAuthProvider',
    'BaseOAuthProvider',
    'ProviderConfig',
    'TokenData',
    'NormalizedUserData',
    'AuthorizationRequest',
    # OAuth registry
    'OAuthProviderRegistry',
    'ProviderInfo',
    'oauth_registry',
    # OAuth configuration
    'OAuthConfigManager',
    'oauth_config_manager',
    # OAuth service
    'OAuthService',
    'oauth_service',
]