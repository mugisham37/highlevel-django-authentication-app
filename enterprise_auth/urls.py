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
    """Readiness check endpoint for Kubernetes."""
    # Check database connectivity
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        db_status = 'healthy'
    except Exception:
        db_status = 'unhealthy'
    
    # Check cache connectivity
    try:
        from django.core.cache import cache
        cache.set('health_check', 'test', 1)
        cache.get('health_check')
        cache_status = 'healthy'
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


urlpatterns = [
    # Health checks
    path('health/', health_check, name='health_check'),
    path('ready/', readiness_check, name='readiness_check'),
    
    # Admin interface
    path('admin/', admin.site.urls),
    
    # API endpoints (will be added in future tasks)
    # path('api/v1/', include('enterprise_auth.api.urls')),
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
