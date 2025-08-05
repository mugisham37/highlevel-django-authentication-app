"""
URL patterns for core functionality including health checks and authentication.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views.health import redis_health, cache_stats, system_health
from .views.auth_views import (
    login,
    refresh_token,
    logout,
    introspect_token,
    validate_token,
    user_profile,
    revoke_token,
    revoke_all_user_tokens,
    revoke_device_tokens,
    bulk_revoke_tokens,
    check_token_refresh_needed,
    get_refresh_token_family,
    revoke_refresh_token_family,
)
from .views.oauth_views import (
    list_oauth_providers,
    initiate_oauth_authorization,
    handle_oauth_callback,
    list_user_oauth_identities,
    link_oauth_identity,
    unlink_oauth_identity,
    verify_social_linking,
    get_social_linking_statistics,
    oauth_provider_health,
    oauth_error_details,
    oauth_metrics_summary,
)
from .views.mfa_views import (
    setup_totp,
    confirm_totp_setup,
    verify_totp,
    verify_backup_code,
    regenerate_backup_codes,
    list_mfa_devices,
    disable_mfa_device,
    mfa_status,
)
from .views.mfa_device_management_views import (
    register_mfa_device,
    confirm_mfa_device_registration,
    list_mfa_devices as list_mfa_devices_detailed,
    remove_mfa_device,
    get_organization_mfa_policy,
    enforce_organization_mfa_policy,
    get_device_management_statistics,
    bulk_device_operation,
)
from .views.backup_codes_views import (
    BackupCodesViewSet,
    BackupCodeValidationView,
)
from .views.session_views import (
    list_user_sessions,
    get_session_details,
    terminate_session,
    terminate_all_sessions,
    extend_current_session,
    get_session_activities,
    get_user_session_statistics,
    get_current_session,
    admin_get_session_statistics,
    admin_terminate_user_sessions,
    # Enhanced concurrent session management views
    get_concurrent_session_policy,
    terminate_sessions_by_criteria,
    detect_session_sharing,
    resolve_session_conflicts,
)


app_name = 'core'

# Create router for viewsets
router = DefaultRouter()
router.register(r'mfa/backup-codes', BackupCodesViewSet, basename='backup-codes')

urlpatterns = [
    # Health check endpoints
    path('health/redis/', redis_health, name='redis_health'),
    path('health/cache/', cache_stats, name='cache_stats'),
    path('health/system/', system_health, name='system_health'),
    
    # JWT token management endpoints
    path('auth/login/', login, name='login'),
    path('auth/refresh/', refresh_token, name='refresh_token'),
    path('auth/logout/', logout, name='logout'),
    path('auth/introspect/', introspect_token, name='introspect_token'),
    path('auth/validate/', validate_token, name='validate_token'),
    path('auth/profile/', user_profile, name='user_profile'),
    
    # Token revocation endpoints
    path('auth/revoke/', revoke_token, name='revoke_token'),
    path('auth/revoke-all/', revoke_all_user_tokens, name='revoke_all_user_tokens'),
    path('auth/revoke-device/', revoke_device_tokens, name='revoke_device_tokens'),
    path('auth/bulk-revoke/', bulk_revoke_tokens, name='bulk_revoke_tokens'),
    
    # Token refresh and family management endpoints
    path('auth/check-refresh/', check_token_refresh_needed, name='check_token_refresh_needed'),
    path('auth/token-family/', get_refresh_token_family, name='get_refresh_token_family'),
    path('auth/revoke-family/', revoke_refresh_token_family, name='revoke_refresh_token_family'),
    
    # OAuth provider endpoints
    path('oauth/providers/', list_oauth_providers, name='list_oauth_providers'),
    path('oauth/<str:provider_name>/authorize/', initiate_oauth_authorization, name='initiate_oauth_authorization'),
    path('oauth/<str:provider_name>/callback/', handle_oauth_callback, name='handle_oauth_callback'),
    path('oauth/<str:provider_name>/link/', link_oauth_identity, name='link_oauth_identity'),
    path('oauth/<str:provider_name>/unlink/', unlink_oauth_identity, name='unlink_oauth_identity'),
    path('oauth/<str:provider_name>/error-details/', oauth_error_details, name='oauth_error_details'),
    path('oauth/identities/', list_user_oauth_identities, name='list_user_oauth_identities'),
    path('oauth/verify-linking/', verify_social_linking, name='verify_social_linking'),
    path('oauth/linking-statistics/', get_social_linking_statistics, name='get_social_linking_statistics'),
    path('oauth/health/', oauth_provider_health, name='oauth_provider_health'),
    path('oauth/metrics/', oauth_metrics_summary, name='oauth_metrics_summary'),
    
    # MFA endpoints
    path('mfa/setup/totp/', setup_totp, name='setup_totp'),
    path('mfa/confirm/totp/', confirm_totp_setup, name='confirm_totp_setup'),
    path('mfa/verify/totp/', verify_totp, name='verify_totp'),
    path('mfa/verify/backup-code/', verify_backup_code, name='verify_backup_code'),
    path('mfa/backup-codes/regenerate/', regenerate_backup_codes, name='regenerate_backup_codes'),
    path('mfa/devices/', list_mfa_devices, name='list_mfa_devices'),
    path('mfa/devices/disable/', disable_mfa_device, name='disable_mfa_device'),
    path('mfa/status/', mfa_status, name='mfa_status'),
    
    # MFA Device Management endpoints
    path('mfa/devices/register/', register_mfa_device, name='register_mfa_device'),
    path('mfa/devices/confirm/', confirm_mfa_device_registration, name='confirm_mfa_device_registration'),
    path('mfa/devices/detailed/', list_mfa_devices_detailed, name='list_mfa_devices_detailed'),
    path('mfa/devices/remove/', remove_mfa_device, name='remove_mfa_device'),
    path('mfa/devices/bulk/', bulk_device_operation, name='bulk_device_operation'),
    path('mfa/devices/statistics/', get_device_management_statistics, name='get_device_management_statistics'),
    
    # Organization MFA Policy endpoints
    path('mfa/organization/policy/', get_organization_mfa_policy, name='get_organization_mfa_policy'),
    path('mfa/organization/enforce/', enforce_organization_mfa_policy, name='enforce_organization_mfa_policy'),
    
    # Session management endpoints
    path('sessions/', list_user_sessions, name='list_user_sessions'),
    path('sessions/current/', get_current_session, name='get_current_session'),
    path('sessions/current/extend/', extend_current_session, name='extend_current_session'),
    path('sessions/statistics/', get_user_session_statistics, name='get_user_session_statistics'),
    path('sessions/terminate-all/', terminate_all_sessions, name='terminate_all_sessions'),
    path('sessions/<str:session_id>/', get_session_details, name='get_session_details'),
    path('sessions/<str:session_id>/terminate/', terminate_session, name='terminate_session'),
    path('sessions/<str:session_id>/activities/', get_session_activities, name='get_session_activities'),
    
    # Enhanced concurrent session management endpoints
    path('sessions/policy/', get_concurrent_session_policy, name='get_concurrent_session_policy'),
    path('sessions/terminate-by-criteria/', terminate_sessions_by_criteria, name='terminate_sessions_by_criteria'),
    path('sessions/detect-sharing/', detect_session_sharing, name='detect_session_sharing'),
    path('sessions/resolve-conflicts/', resolve_session_conflicts, name='resolve_session_conflicts'),
    
    # Admin session management endpoints
    path('admin/sessions/statistics/', admin_get_session_statistics, name='admin_get_session_statistics'),
    path('admin/users/<int:user_id>/sessions/terminate/', admin_terminate_user_sessions, name='admin_terminate_user_sessions'),
    
    # SMS MFA endpoints (placeholder - will be implemented in future tasks)
    # path('mfa/sms/', include('enterprise_auth.core.urls.sms_mfa_urls')),
    
    # Email MFA endpoints (placeholder - will be implemented in future tasks)
    # path('mfa/email/', include('enterprise_auth.core.urls.email_mfa_urls')),
    
    # Backup codes standalone validation endpoint
    path('mfa/validate-backup-code/', BackupCodeValidationView.as_view(), name='validate_backup_code_standalone'),
    
    # Session security monitoring endpoints (will be added after migrations)
    # path('security/sessions/monitor/', monitor_session, name='monitor_session'),
    
    # Include router URLs for viewsets
    path('', include(router.urls)),
]