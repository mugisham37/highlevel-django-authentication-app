"""
Core views for the enterprise authentication system.

This module provides system-level views for:
- Health checks
- Database status
- Performance monitoring
- System information
"""

import logging
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import cache_page
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


@require_http_methods(["GET"])
def health_check(request):
    """
    Basic health check endpoint.
    
    Returns system health status including:
    - Application status
    - Database connectivity
    - Cache connectivity
    - Basic system information
    """
    health_status = {
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
        'version': getattr(settings, 'VERSION', '1.0.0'),
        'environment': getattr(settings, 'ENVIRONMENT', 'unknown'),
        'checks': {}
    }
    
    # Check database connectivity
    try:
        from enterprise_auth.core.db.monitoring import get_database_health
        db_health = get_database_health()
        health_status['checks']['database'] = {
            'status': db_health['overall_status'],
            'details': db_health['databases']
        }
        
        if db_health['overall_status'] != 'healthy':
            health_status['status'] = 'unhealthy'
            
    except Exception as e:
        health_status['checks']['database'] = {
            'status': 'error',
            'error': str(e)
        }
        health_status['status'] = 'unhealthy'
    
    # Check cache connectivity
    try:
        from django.core.cache import cache
        cache.set('health_check', 'ok', timeout=10)
        cache_result = cache.get('health_check')
        
        health_status['checks']['cache'] = {
            'status': 'healthy' if cache_result == 'ok' else 'unhealthy'
        }
        
        if cache_result != 'ok':
            health_status['status'] = 'unhealthy'
            
    except Exception as e:
        health_status['checks']['cache'] = {
            'status': 'error',
            'error': str(e)
        }
        health_status['status'] = 'unhealthy'
    
    # Return appropriate HTTP status code
    status_code = 200 if health_status['status'] == 'healthy' else 503
    
    return JsonResponse(health_status, status=status_code)


@require_http_methods(["GET"])
@cache_page(60)  # Cache for 1 minute
def database_status(request):
    """
    Detailed database status endpoint.
    
    Returns comprehensive database information including:
    - Connection pool status
    - Performance metrics
    - Replication lag
    - Query statistics
    """
    try:
        from enterprise_auth.core.db.monitoring import get_database_health, get_database_performance
        
        status = {
            'timestamp': timezone.now().isoformat(),
            'health': get_database_health(),
            'performance': get_database_performance(),
        }
        
        return JsonResponse(status)
        
    except Exception as e:
        logger.error(f"Failed to get database status: {e}")
        return JsonResponse({
            'error': 'Failed to retrieve database status',
            'details': str(e)
        }, status=500)


@require_http_methods(["GET"])
def system_info(request):
    """
    System information endpoint.
    
    Returns basic system information for monitoring and debugging.
    """
    import sys
    import platform
    from django import get_version
    
    info = {
        'timestamp': timezone.now().isoformat(),
        'django_version': get_version(),
        'python_version': sys.version,
        'platform': platform.platform(),
        'settings': {
            'debug': settings.DEBUG,
            'databases': list(settings.DATABASES.keys()),
            'cache_backends': list(settings.CACHES.keys()),
            'installed_apps_count': len(settings.INSTALLED_APPS),
        }
    }
    
    # Add database router information
    if hasattr(settings, 'DATABASE_ROUTERS'):
        info['settings']['database_routers'] = settings.DATABASE_ROUTERS
    
    return JsonResponse(info)