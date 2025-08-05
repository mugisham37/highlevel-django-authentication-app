"""
Health check endpoints for Enterprise Authentication Backend.
Provides comprehensive health, readiness, and startup probes for Kubernetes.
"""

import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

from django.conf import settings
from django.core.cache import cache
from django.db import connections
from django.http import JsonResponse, HttpResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

import redis
from celery import current_app as celery_app


class HealthCheckStatus:
    """Health check status constants."""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"


class HealthChecker:
    """Comprehensive health checking for the application."""
    
    def __init__(self):
        self.checks = {
            'database': self._check_database,
            'redis': self._check_redis,
            'cache': self._check_cache,
            'celery': self._check_celery,
            'disk_space': self._check_disk_space,
            'memory': self._check_memory,
        }
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks and return comprehensive status."""
        start_time = time.time()
        results = {}
        overall_status = HealthCheckStatus.HEALTHY
        
        for check_name, check_func in self.checks.items():
            try:
                check_start = time.time()
                status, details = check_func()
                check_duration = time.time() - check_start
                
                results[check_name] = {
                    'status': status,
                    'details': details,
                    'duration_ms': round(check_duration * 1000, 2)
                }
                
                # Update overall status
                if status == HealthCheckStatus.UNHEALTHY:
                    overall_status = HealthCheckStatus.UNHEALTHY
                elif status == HealthCheckStatus.DEGRADED and overall_status == HealthCheckStatus.HEALTHY:
                    overall_status = HealthCheckStatus.DEGRADED
                    
            except Exception as e:
                results[check_name] = {
                    'status': HealthCheckStatus.UNHEALTHY,
                    'details': {'error': str(e)},
                    'duration_ms': 0
                }
                overall_status = HealthCheckStatus.UNHEALTHY
        
        total_duration = time.time() - start_time
        
        return {
            'status': overall_status,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': getattr(settings, 'VERSION', '1.0.0'),
            'environment': getattr(settings, 'ENVIRONMENT', 'unknown'),
            'checks': results,
            'total_duration_ms': round(total_duration * 1000, 2)
        }
    
    def run_basic_checks(self) -> Dict[str, Any]:
        """Run basic health checks for liveness probe."""
        basic_checks = ['database', 'redis']
        start_time = time.time()
        results = {}
        overall_status = HealthCheckStatus.HEALTHY
        
        for check_name in basic_checks:
            if check_name in self.checks:
                try:
                    check_start = time.time()
                    status, details = self.checks[check_name]()
                    check_duration = time.time() - check_start
                    
                    results[check_name] = {
                        'status': status,
                        'details': details,
                        'duration_ms': round(check_duration * 1000, 2)
                    }
                    
                    if status == HealthCheckStatus.UNHEALTHY:
                        overall_status = HealthCheckStatus.UNHEALTHY
                        
                except Exception as e:
                    results[check_name] = {
                        'status': HealthCheckStatus.UNHEALTHY,
                        'details': {'error': str(e)},
                        'duration_ms': 0
                    }
                    overall_status = HealthCheckStatus.UNHEALTHY
        
        total_duration = time.time() - start_time
        
        return {
            'status': overall_status,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'checks': results,
            'total_duration_ms': round(total_duration * 1000, 2)
        }
    
    def _check_database(self) -> Tuple[str, Dict[str, Any]]:
        """Check database connectivity and performance."""
        try:
            db_conn = connections['default']
            
            # Test connection
            with db_conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            
            # Check connection pool status
            pool_info = {
                'vendor': db_conn.vendor,
                'is_usable': db_conn.is_usable(),
            }
            
            # Simple performance test
            start_time = time.time()
            with db_conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM django_migrations")
                migration_count = cursor.fetchone()[0]
            query_time = time.time() - start_time
            
            details = {
                'connection': pool_info,
                'migration_count': migration_count,
                'query_time_ms': round(query_time * 1000, 2)
            }
            
            # Determine status based on query performance
            if query_time > 1.0:  # > 1 second is concerning
                return HealthCheckStatus.DEGRADED, details
            else:
                return HealthCheckStatus.HEALTHY, details
                
        except Exception as e:
            return HealthCheckStatus.UNHEALTHY, {'error': str(e)}
    
    def _check_redis(self) -> Tuple[str, Dict[str, Any]]:
        """Check Redis connectivity and performance."""
        try:
            # Test default cache
            cache_key = 'health_check_test'
            test_value = f'test_{int(time.time())}'
            
            start_time = time.time()
            cache.set(cache_key, test_value, timeout=60)
            retrieved_value = cache.get(cache_key)
            cache.delete(cache_key)
            operation_time = time.time() - start_time
            
            if retrieved_value != test_value:
                return HealthCheckStatus.UNHEALTHY, {
                    'error': 'Cache value mismatch',
                    'expected': test_value,
                    'actual': retrieved_value
                }
            
            # Get Redis info if using Redis cache
            redis_info = {}
            try:
                if hasattr(cache, '_cache') and hasattr(cache._cache, '_client'):
                    redis_client = cache._cache._client.get_client()
                    info = redis_client.info()
                    redis_info = {
                        'version': info.get('redis_version'),
                        'connected_clients': info.get('connected_clients'),
                        'used_memory_human': info.get('used_memory_human'),
                        'keyspace_hits': info.get('keyspace_hits', 0),
                        'keyspace_misses': info.get('keyspace_misses', 0)
                    }
            except Exception:
                pass  # Redis info is optional
            
            details = {
                'operation_time_ms': round(operation_time * 1000, 2),
                'redis_info': redis_info
            }
            
            # Determine status based on operation performance
            if operation_time > 0.5:  # > 500ms is concerning
                return HealthCheckStatus.DEGRADED, details
            else:
                return HealthCheckStatus.HEALTHY, details
                
        except Exception as e:
            return HealthCheckStatus.UNHEALTHY, {'error': str(e)}
    
    def _check_cache(self) -> Tuple[str, Dict[str, Any]]:
        """Check cache functionality."""
        try:
            # Test cache operations
            test_key = 'health_check_cache_test'
            test_data = {'timestamp': time.time(), 'test': True}
            
            start_time = time.time()
            
            # Set, get, and delete operations
            cache.set(test_key, test_data, timeout=60)
            retrieved_data = cache.get(test_key)
            cache.delete(test_key)
            
            operation_time = time.time() - start_time
            
            if retrieved_data != test_data:
                return HealthCheckStatus.UNHEALTHY, {
                    'error': 'Cache data integrity check failed'
                }
            
            details = {
                'operation_time_ms': round(operation_time * 1000, 2),
                'operations': ['set', 'get', 'delete']
            }
            
            return HealthCheckStatus.HEALTHY, details
            
        except Exception as e:
            return HealthCheckStatus.UNHEALTHY, {'error': str(e)}
    
    def _check_celery(self) -> Tuple[str, Dict[str, Any]]:
        """Check Celery worker connectivity."""
        try:
            # Check if Celery is configured
            if not hasattr(settings, 'CELERY_BROKER_URL'):
                return HealthCheckStatus.DEGRADED, {
                    'message': 'Celery not configured'
                }
            
            # Inspect active workers
            inspect = celery_app.control.inspect()
            
            start_time = time.time()
            active_workers = inspect.active()
            stats = inspect.stats()
            operation_time = time.time() - start_time
            
            if not active_workers:
                return HealthCheckStatus.DEGRADED, {
                    'message': 'No active Celery workers found',
                    'operation_time_ms': round(operation_time * 1000, 2)
                }
            
            worker_count = len(active_workers)
            total_tasks = sum(len(tasks) for tasks in active_workers.values())
            
            details = {
                'active_workers': worker_count,
                'active_tasks': total_tasks,
                'operation_time_ms': round(operation_time * 1000, 2),
                'worker_stats': stats
            }
            
            return HealthCheckStatus.HEALTHY, details
            
        except Exception as e:
            return HealthCheckStatus.DEGRADED, {
                'error': str(e),
                'message': 'Celery check failed but not critical'
            }
    
    def _check_disk_space(self) -> Tuple[str, Dict[str, Any]]:
        """Check available disk space."""
        try:
            import shutil
            
            # Check disk space for common paths
            paths_to_check = ['/tmp', '/app', '/var/log']
            disk_info = {}
            
            for path in paths_to_check:
                try:
                    total, used, free = shutil.disk_usage(path)
                    usage_percent = (used / total) * 100
                    
                    disk_info[path] = {
                        'total_gb': round(total / (1024**3), 2),
                        'used_gb': round(used / (1024**3), 2),
                        'free_gb': round(free / (1024**3), 2),
                        'usage_percent': round(usage_percent, 2)
                    }
                except (OSError, FileNotFoundError):
                    continue
            
            if not disk_info:
                return HealthCheckStatus.DEGRADED, {
                    'message': 'Could not check disk space'
                }
            
            # Check if any path has > 90% usage
            high_usage_paths = [
                path for path, info in disk_info.items()
                if info['usage_percent'] > 90
            ]
            
            if high_usage_paths:
                return HealthCheckStatus.DEGRADED, {
                    'disk_info': disk_info,
                    'high_usage_paths': high_usage_paths,
                    'message': 'High disk usage detected'
                }
            
            return HealthCheckStatus.HEALTHY, {'disk_info': disk_info}
            
        except Exception as e:
            return HealthCheckStatus.DEGRADED, {
                'error': str(e),
                'message': 'Disk space check failed but not critical'
            }
    
    def _check_memory(self) -> Tuple[str, Dict[str, Any]]:
        """Check memory usage."""
        try:
            import psutil
            
            # Get memory information
            memory = psutil.virtual_memory()
            
            memory_info = {
                'total_gb': round(memory.total / (1024**3), 2),
                'available_gb': round(memory.available / (1024**3), 2),
                'used_gb': round(memory.used / (1024**3), 2),
                'usage_percent': memory.percent
            }
            
            # Check if memory usage is concerning
            if memory.percent > 90:
                return HealthCheckStatus.DEGRADED, {
                    'memory_info': memory_info,
                    'message': 'High memory usage detected'
                }
            elif memory.percent > 95:
                return HealthCheckStatus.UNHEALTHY, {
                    'memory_info': memory_info,
                    'message': 'Critical memory usage detected'
                }
            
            return HealthCheckStatus.HEALTHY, {'memory_info': memory_info}
            
        except ImportError:
            return HealthCheckStatus.DEGRADED, {
                'message': 'psutil not available for memory checking'
            }
        except Exception as e:
            return HealthCheckStatus.DEGRADED, {
                'error': str(e),
                'message': 'Memory check failed but not critical'
            }


# Global health checker instance
health_checker = HealthChecker()


@never_cache
@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    """
    Basic health check endpoint for load balancers and monitoring.
    Returns 200 if the application is healthy, 503 if unhealthy.
    """
    try:
        result = health_checker.run_basic_checks()
        
        if result['status'] == HealthCheckStatus.HEALTHY:
            return JsonResponse(result, status=200)
        else:
            return JsonResponse(result, status=503)
            
    except Exception as e:
        return JsonResponse({
            'status': HealthCheckStatus.UNHEALTHY,
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, status=503)


@never_cache
@csrf_exempt
@require_http_methods(["GET"])
def health_check_detailed(request):
    """
    Detailed health check endpoint with comprehensive system status.
    Includes all subsystem checks and performance metrics.
    """
    try:
        result = health_checker.run_all_checks()
        
        if result['status'] == HealthCheckStatus.HEALTHY:
            return JsonResponse(result, status=200)
        elif result['status'] == HealthCheckStatus.DEGRADED:
            return JsonResponse(result, status=200)  # Still operational
        else:
            return JsonResponse(result, status=503)
            
    except Exception as e:
        return JsonResponse({
            'status': HealthCheckStatus.UNHEALTHY,
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, status=503)


@never_cache
@csrf_exempt
@require_http_methods(["GET"])
def readiness_check(request):
    """
    Kubernetes readiness probe endpoint.
    Checks if the application is ready to receive traffic.
    """
    try:
        # For readiness, we check critical dependencies
        critical_checks = ['database', 'redis']
        results = {}
        overall_status = HealthCheckStatus.HEALTHY
        
        for check_name in critical_checks:
            if check_name in health_checker.checks:
                try:
                    status, details = health_checker.checks[check_name]()
                    results[check_name] = {'status': status, 'details': details}
                    
                    if status == HealthCheckStatus.UNHEALTHY:
                        overall_status = HealthCheckStatus.UNHEALTHY
                        
                except Exception as e:
                    results[check_name] = {
                        'status': HealthCheckStatus.UNHEALTHY,
                        'details': {'error': str(e)}
                    }
                    overall_status = HealthCheckStatus.UNHEALTHY
        
        result = {
            'status': overall_status,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'checks': results
        }
        
        if overall_status == HealthCheckStatus.HEALTHY:
            return JsonResponse(result, status=200)
        else:
            return JsonResponse(result, status=503)
            
    except Exception as e:
        return JsonResponse({
            'status': HealthCheckStatus.UNHEALTHY,
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, status=503)


@never_cache
@csrf_exempt
@require_http_methods(["GET"])
def startup_check(request):
    """
    Kubernetes startup probe endpoint.
    Checks if the application has started successfully.
    """
    try:
        # For startup, we do minimal checks to avoid delaying startup
        result = {
            'status': HealthCheckStatus.HEALTHY,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'message': 'Application started successfully'
        }
        
        return JsonResponse(result, status=200)
        
    except Exception as e:
        return JsonResponse({
            'status': HealthCheckStatus.UNHEALTHY,
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, status=503)


@never_cache
@csrf_exempt
@require_http_methods(["GET"])
def liveness_check(request):
    """
    Kubernetes liveness probe endpoint.
    Checks if the application is alive and should not be restarted.
    """
    try:
        # For liveness, we do very basic checks
        # If this fails, Kubernetes will restart the pod
        result = {
            'status': HealthCheckStatus.HEALTHY,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'uptime_seconds': time.time() - getattr(settings, 'START_TIME', time.time())
        }
        
        return JsonResponse(result, status=200)
        
    except Exception as e:
        return JsonResponse({
            'status': HealthCheckStatus.UNHEALTHY,
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, status=503)


@never_cache
@csrf_exempt
@require_http_methods(["GET"])
def version_info(request):
    """
    Application version and build information endpoint.
    """
    try:
        version_info = {
            'version': getattr(settings, 'VERSION', '1.0.0'),
            'build_date': getattr(settings, 'BUILD_DATE', 'unknown'),
            'git_commit': getattr(settings, 'GIT_COMMIT', 'unknown'),
            'environment': getattr(settings, 'ENVIRONMENT', 'unknown'),
            'django_version': getattr(settings, 'DJANGO_VERSION', 'unknown'),
            'python_version': getattr(settings, 'PYTHON_VERSION', 'unknown'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        return JsonResponse(version_info, status=200)
        
    except Exception as e:
        return JsonResponse({
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }, status=500)