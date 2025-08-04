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
    UserProfileViewSet,
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
    
    # User profile endpoints (via router)
    path('user/', include(router.urls)),
]