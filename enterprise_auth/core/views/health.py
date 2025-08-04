"""
Health check views for monitoring Redis and other system components.
"""

import logging
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from enterprise_auth.core.cache.redis_config import redis_health_check
from enterprise_auth.core.cache.cache_manager import cache_manager
from enterprise_auth.core.cache.session_storage import session_manager
import time

logger = logging.getLogger(__name__)


@require_http_methods(["GET"])
@csrf_exempt
def redis_health(request):
    """
    Redis health check endpoint.
    
    Returns:
        JSON response with Redis health status and metrics
    """
    try:
        health_result = redis_health_check()
        
        # Determine HTTP status code based on health
        status_code = 200 if health_result['status'] == 'healthy' else 503
        
        return JsonResponse(health_result, status=status_code)
        
    except Exception as e:
        logger.error(f"Redis health check endpoint failed: {e}")
        return JsonResponse({
            'status': 'error',
            'error': str(e),
            'timestamp': time.time()
        }, status=500)


@require_http_methods(["GET"])
@csrf_exempt
def cache_stats(request):
    """
    Cache statistics endpoint.
    
    Returns:
        JSON response with comprehensive cache statistics
    """
    try:
        # Get cache statistics
        cache_stats_data = cache_manager.get_cache_stats()
        
        # Get session statistics
        session_stats_data = session_manager.get_session_stats()
        
        # Combine all statistics
        stats = {
            'cache': cache_stats_data,
            'sessions': session_stats_data,
            'timestamp': time.time(),
            'status': 'healthy'
        }
        
        return JsonResponse(stats, status=200)
        
    except Exception as e:
        logger.error(f"Cache stats endpoint failed: {e}")
        return JsonResponse({
            'status': 'error',
            'error': str(e),
            'timestamp': time.time()
        }, status=500)


@require_http_methods(["GET"])
@csrf_exempt
def system_health(request):
    """
    Comprehensive system health check endpoint.
    
    Returns:
        JSON response with overall system health status
    """
    try:
        start_time = time.time()
        
        # Check Redis health
        redis_result = redis_health_check()
        
        # Check cache performance
        cache_stats_data = cache_manager.get_cache_stats()
        
        # Check session storage
        session_stats_data = session_manager.get_session_stats()
        
        # Determine overall health
        overall_healthy = redis_result['status'] == 'healthy'
        
        # Calculate response time
        response_time = (time.time() - start_time) * 1000
        
        health_data = {
            'status': 'healthy' if overall_healthy else 'unhealthy',
            'response_time_ms': round(response_time, 2),
            'components': {
                'redis': redis_result,
                'cache': {
                    'status': 'healthy' if cache_stats_data else 'unhealthy',
                    'stats': cache_stats_data
                },
                'sessions': {
                    'status': 'healthy' if session_stats_data else 'unhealthy',
                    'stats': session_stats_data
                }
            },
            'timestamp': time.time()
        }
        
        status_code = 200 if overall_healthy else 503
        
        return JsonResponse(health_data, status=status_code)
        
    except Exception as e:
        logger.error(f"System health check failed: {e}")
        return JsonResponse({
            'status': 'error',
            'error': str(e),
            'timestamp': time.time()
        }, status=500)