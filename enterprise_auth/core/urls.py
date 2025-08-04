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

app_name = 'core'

# Create router for viewsets (if needed in future)
# router = DefaultRouter()

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
]