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
from .social_account_linking_service import (
    SocialAccountLinkingService,
    social_linking_service,
)
from .sms_mfa_service import (
    SMSMFAService,
    sms_mfa_service,
)
from .email_mfa_service import (
    EmailMFAService,
    email_mfa_service,
)
from .backup_codes_service import (
    BackupCodesService,
    backup_codes_service,
)
from .mfa_device_management_service import (
    MFADeviceManagementService,
    mfa_device_management_service,
)
from .session_service import (
    SessionService,
    create_user_session,
    validate_user_session,
    terminate_user_session,
    cleanup_expired_sessions,
    cleanup_old_sessions,
    cleanup_old_session_activities,
    cleanup_orphaned_device_info,
    extend_session_expiration,
    get_session_statistics,
)
from .session_security_service import (
    SessionSecurityMonitoringService,
    session_security_service,
    AnomalyScore,
    ThreatAnalysis,
)
from .compliance_service import (
    GDPRComplianceService,
    CCPAComplianceService,
    SOC2AuditService,
)
from .data_portability_service import DataPortabilityService
from .privacy_rights_service import PrivacyRightsService
from .security_compliance_service import SecurityComplianceService
from .audit_integrity_service import AuditIntegrityService
from .compliance_dashboard_service import ComplianceDashboardService

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
    # Social account linking service
    'SocialAccountLinkingService',
    'social_linking_service',
    # SMS MFA service
    'SMSMFAService',
    'sms_mfa_service',
    # Email MFA service
    'EmailMFAService',
    'email_mfa_service',
    # Backup codes service
    'BackupCodesService',
    'backup_codes_service',
    # MFA device management service
    'MFADeviceManagementService',
    'mfa_device_management_service',
    # Session management service
    'SessionService',
    'create_user_session',
    'validate_user_session',
    'terminate_user_session',
    'cleanup_expired_sessions',
    'cleanup_old_sessions',
    'cleanup_old_session_activities',
    'cleanup_orphaned_device_info',
    'extend_session_expiration',
    'get_session_statistics',
    # Session security monitoring service
    'SessionSecurityMonitoringService',
    'session_security_service',
    'AnomalyScore',
    'ThreatAnalysis',
    # Compliance services
    'GDPRComplianceService',
    'CCPAComplianceService',
    'SOC2AuditService',
    'DataPortabilityService',
    'PrivacyRightsService',
    'SecurityComplianceService',
    'AuditIntegrityService',
    'ComplianceDashboardService',
]