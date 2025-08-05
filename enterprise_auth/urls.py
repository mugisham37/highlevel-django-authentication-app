"""
URL configuration for enterprise_auth project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods


@never_cache
@require_http_methods(["GET"])
def health_check(request):
    """Simple health check endpoint."""
    return JsonResponse({
        'status': 'healthy',
        'service': 'enterprise-auth-backend',
        'version': '1.0.0'
    })


@never_cache
@require_http_methods(["GET"])
def readiness_check(request):
    """Enhanced readiness check endpoint for Kubernetes."""
    try:
        from enterprise_auth.core.db.monitoring import get_database_health
        db_health = get_database_health()
        db_status = db_health['overall_status']
    except Exception:
        db_status = 'unhealthy'
    
    # Check cache connectivity
    try:
        from django.core.cache import cache
        cache.set('health_check', 'test', 1)
        cache_result = cache.get('health_check')
        cache_status = 'healthy' if cache_result == 'test' else 'unhealthy'
    except Exception:
        cache_status = 'unhealthy'
    
    status = 'healthy' if db_status == 'healthy' and cache_status == 'healthy' else 'unhealthy'
    status_code = 200 if status == 'healthy' else 503
    
    return JsonResponse({
        'status': status,
        'checks': {
            'database': db_status,
            'cache': cache_status,
        }
    }, status=status_code)


@never_cache
@require_http_methods(["GET"])
def database_status(request):
    """Detailed database status endpoint."""
    try:
        from enterprise_auth.core.db.monitoring import get_database_health, get_database_performance
        from django.utils import timezone
        
        status = {
            'timestamp': timezone.now().isoformat(),
            'health': get_database_health(),
            'performance': get_database_performance(),
        }
        
        return JsonResponse(status)
        
    except Exception as e:
        return JsonResponse({
            'error': 'Failed to retrieve database status',
            'details': str(e)
        }, status=500)


urlpatterns = [
    # Health checks
    path('health/', health_check, name='health_check'),
    path('ready/', readiness_check, name='readiness_check'),
    path('health/database/', database_status, name='database_status'),
    
    # Admin interface
    path('admin/', admin.site.urls),
    
    # Core functionality endpoints
    path('api/v1/core/', include('enterprise_auth.core.urls')),
    
    # API integration endpoints (temporarily disabled)
    # path('api/v1/', include('enterprise_auth.api.urls')),
    
    # Monitoring and observability endpoints (temporarily disabled)
    # path('monitoring/', include('enterprise_auth.core.monitoring.urls')),
]

# Serve static and media files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    
    # Add debug toolbar URLs in development
    if 'debug_toolbar' in settings.INSTALLED_APPS:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns
