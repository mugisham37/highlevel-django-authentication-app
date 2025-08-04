"""
URL patterns for core functionality including health checks and authentication.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views.health import redis_health, cache_stats, system_health
from .views.auth_views import (
    UserRegistrationView,
    EmailVerificationView,
    ResendVerificationView,
    EmailVerificationStatusView,
    EmailVerificationValidateTokenView,
    EmailVerificationStatsView,
    UserProfileViewSet,
    PasswordResetRequestView,
    PasswordResetConfirmView,
    PasswordResetValidateTokenView,
    PasswordStrengthCheckView,
    PasswordPolicyView,
    login,
    refresh_token,
    logout,
    introspect_token,
    validate_token,
    user_profile,
)

app_name = 'core'

# Create router for viewsets
router = DefaultRouter()
router.register(r'profile', UserProfileViewSet, basename='profile')

urlpatterns = [
    # Health check endpoints
    path('health/redis/', redis_health, name='redis_health'),
    path('health/cache/', cache_stats, name='cache_stats'),
    path('health/system/', system_health, name='system_health'),
    
    # Authentication endpoints
    path('auth/register/', UserRegistrationView.as_view(), name='register'),
    path('auth/verify-email/', EmailVerificationView.as_view(), name='verify_email'),
    path('auth/resend-verification/', ResendVerificationView.as_view(), name='resend_verification'),
    path('auth/verification-status/', EmailVerificationStatusView.as_view(), name='verification_status'),
    path('auth/verify-email/validate/', EmailVerificationValidateTokenView.as_view(), name='verify_email_validate'),
    path('auth/verification-stats/', EmailVerificationStatsView.as_view(), name='verification_stats'),
    
    # Password management endpoints
    path('auth/password/reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('auth/password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('auth/password/reset/validate/', PasswordResetValidateTokenView.as_view(), name='password_reset_validate'),
    path('auth/password/strength/', PasswordStrengthCheckView.as_view(), name='password_strength_check'),
    path('auth/password/policy/', PasswordPolicyView.as_view(), name='password_policy'),
    
    # User profile endpoints (via router)
    path('user/', include(router.urls)),
]