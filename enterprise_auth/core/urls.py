"""
URL patterns for core functionality including health checks.
"""

from django.urls import path
from .views.health import redis_health, cache_stats, system_health

app_name = 'core'

urlpatterns = [
    # Health check endpoints
    path('health/redis/', redis_health, name='redis_health'),
    path('health/cache/', cache_stats, name='cache_stats'),
    path('health/system/', system_health, name='system_health'),
]