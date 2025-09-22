"""
Comprehensive health check system for monitoring system components.
Provides detailed health status endpoints and system monitoring.
"""

import time
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from django.conf import settings
from django.core.cache import cache, caches
from django.db import connections, connection
from django.utils import timezone
import redis

# Conditional PostgreSQL import for development environment
try:
    import psycopg
    PSYCOPG_AVAILABLE = True
except ImportError:
    PSYCOPG_AVAILABLE = False

from .logging_config import get_structured_logger

logger = get_structured_logger(__name__)


class HealthStatus(Enum):
    """Health check status enumeration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    name: str
    status: HealthStatus
    message: str
    duration_ms: float
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class HealthCheck:
    """Base class for health checks."""
    
    def __init__(self, name: str, timeout: float = 5.0):
        self.name = name
        self.timeout = timeout
    
    def check(self) -> HealthCheckResult:
        """Perform the health check."""
        start_time = time.time()
        
        try:
            result = self._perform_check()
            duration_ms = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                name=self.name,
                status=result.get('status', HealthStatus.UNKNOWN),
                message=result.get('message', 'Health check completed'),
                duration_ms=duration_ms,
                timestamp=timezone.now(),
                details=result.get('details', {}),
                error=result.get('error')
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Health check {self.name} failed", error=str(e))
            
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                duration_ms=duration_ms,
                timestamp=timezone.now(),
                error=str(e)
            )
    
    def _perform_check(self) -> Dict[str, Any]:
        """Override this method to implement the actual health check."""
        raise NotImplementedError


class DatabaseHealthCheck(HealthCheck):
    """Health check for database connectivity and performance."""
    
    def __init__(self, db_alias: str = 'default'):
        super().__init__(f"database_{db_alias}")
        self.db_alias = db_alias
    
    def _perform_check(self) -> Dict[str, Any]:
        """Check database health."""
        conn = connections[self.db_alias]
        
        # Test basic connectivity
        start_time = time.time()
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
        
        query_time_ms = (time.time() - start_time) * 1000
        
        if result[0] != 1:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': 'Database query returned unexpected result',
                'details': {'query_time_ms': query_time_ms}
            }
        
        # Check connection pool status
        pool_info = self._get_connection_pool_info(conn)
        
        # Determine status based on query time and pool usage
        if query_time_ms > 1000:  # 1 second
            status = HealthStatus.UNHEALTHY
            message = f"Database query too slow: {query_time_ms:.2f}ms"
        elif query_time_ms > 100:  # 100ms
            status = HealthStatus.DEGRADED
            message = f"Database query slow: {query_time_ms:.2f}ms"
        else:
            status = HealthStatus.HEALTHY
            message = f"Database healthy: {query_time_ms:.2f}ms"
        
        return {
            'status': status,
            'message': message,
            'details': {
                'query_time_ms': query_time_ms,
                'pool_info': pool_info,
                'db_alias': self.db_alias
            }
        }
    
    def _get_connection_pool_info(self, conn) -> Dict[str, Any]:
        """Get connection pool information."""
        try:
            # This is database-specific; adjust based on your setup
            return {
                'vendor': conn.vendor,
                'is_usable': conn.is_usable(),
                'queries_count': len(conn.queries) if hasattr(conn, 'queries') else 0
            }
        except Exception as e:
            return {'error': str(e)}


class RedisHealthCheck(HealthCheck):
    """Health check for Redis connectivity and performance."""
    
    def __init__(self, cache_alias: str = 'default'):
        super().__init__(f"redis_{cache_alias}")
        self.cache_alias = cache_alias
    
    def _perform_check(self) -> Dict[str, Any]:
        """Check Redis health."""
        cache_instance = caches[self.cache_alias]
        
        # Test basic connectivity with ping
        start_time = time.time()
        test_key = f"health_check_{int(time.time())}"
        test_value = "health_check_value"
        
        try:
            # Test set operation
            cache_instance.set(test_key, test_value, timeout=60)
            
            # Test get operation
            retrieved_value = cache_instance.get(test_key)
            
            # Test delete operation
            cache_instance.delete(test_key)
            
            operation_time_ms = (time.time() - start_time) * 1000
            
            if retrieved_value != test_value:
                return {
                    'status': HealthStatus.UNHEALTHY,
                    'message': 'Redis set/get operation failed',
                    'details': {
                        'operation_time_ms': operation_time_ms,
                        'expected': test_value,
                        'actual': retrieved_value
                    }
                }
            
            # Get Redis info if available
            redis_info = self._get_redis_info(cache_instance)
            
            # Determine status based on operation time
            if operation_time_ms > 100:  # 100ms
                status = HealthStatus.DEGRADED
                message = f"Redis operations slow: {operation_time_ms:.2f}ms"
            else:
                status = HealthStatus.HEALTHY
                message = f"Redis healthy: {operation_time_ms:.2f}ms"
            
            return {
                'status': status,
                'message': message,
                'details': {
                    'operation_time_ms': operation_time_ms,
                    'cache_alias': self.cache_alias,
                    'redis_info': redis_info
                }
            }
            
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': f"Redis operation failed: {str(e)}",
                'details': {'cache_alias': self.cache_alias},
                'error': str(e)
            }
    
    def _get_redis_info(self, cache_instance) -> Dict[str, Any]:
        """Get Redis server information."""
        try:
            # Try to get Redis client info
            if hasattr(cache_instance, '_cache'):
                client = cache_instance._cache.get_client()
                if hasattr(client, 'info'):
                    info = client.info()
                    return {
                        'redis_version': info.get('redis_version'),
                        'used_memory_human': info.get('used_memory_human'),
                        'connected_clients': info.get('connected_clients'),
                        'uptime_in_seconds': info.get('uptime_in_seconds')
                    }
        except Exception as e:
            return {'info_error': str(e)}
        
        return {}


class CeleryHealthCheck(HealthCheck):
    """Health check for Celery worker availability."""
    
    def __init__(self):
        super().__init__("celery")
    
    def _perform_check(self) -> Dict[str, Any]:
        """Check Celery health."""
        try:
            from celery import current_app
            
            # Get active workers
            inspect = current_app.control.inspect()
            active_workers = inspect.active()
            
            if not active_workers:
                return {
                    'status': HealthStatus.UNHEALTHY,
                    'message': 'No active Celery workers found',
                    'details': {'active_workers': 0}
                }
            
            worker_count = len(active_workers)
            
            # Check worker stats
            stats = inspect.stats()
            worker_stats = {}
            
            for worker_name, worker_info in (stats or {}).items():
                worker_stats[worker_name] = {
                    'pool': worker_info.get('pool', {}),
                    'total_tasks': worker_info.get('total', {})
                }
            
            return {
                'status': HealthStatus.HEALTHY,
                'message': f"Celery healthy: {worker_count} workers active",
                'details': {
                    'active_workers': worker_count,
                    'worker_names': list(active_workers.keys()),
                    'worker_stats': worker_stats
                }
            }
            
        except ImportError:
            return {
                'status': HealthStatus.UNKNOWN,
                'message': 'Celery not available',
                'details': {}
            }
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': f"Celery check failed: {str(e)}",
                'error': str(e)
            }


class ExternalServiceHealthCheck(HealthCheck):
    """Health check for external services (OAuth providers, SMS, etc.)."""
    
    def __init__(self, service_name: str, check_function: Callable):
        super().__init__(f"external_{service_name}")
        self.service_name = service_name
        self.check_function = check_function
    
    def _perform_check(self) -> Dict[str, Any]:
        """Check external service health."""
        try:
            result = self.check_function()
            return result
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': f"External service {self.service_name} check failed: {str(e)}",
                'error': str(e)
            }


class SystemResourceHealthCheck(HealthCheck):
    """Health check for system resources (memory, disk, etc.)."""
    
    def __init__(self):
        super().__init__("system_resources")
    
    def _perform_check(self) -> Dict[str, Any]:
        """Check system resource health."""
        try:
            import psutil
            
            # Check memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Check disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Determine overall status
            if memory_percent > 90 or disk_percent > 90 or cpu_percent > 90:
                status = HealthStatus.UNHEALTHY
                message = "System resources critically high"
            elif memory_percent > 80 or disk_percent > 80 or cpu_percent > 80:
                status = HealthStatus.DEGRADED
                message = "System resources high"
            else:
                status = HealthStatus.HEALTHY
                message = "System resources normal"
            
            return {
                'status': status,
                'message': message,
                'details': {
                    'memory_percent': memory_percent,
                    'disk_percent': disk_percent,
                    'cpu_percent': cpu_percent,
                    'memory_available_gb': memory.available / (1024**3),
                    'disk_free_gb': disk.free / (1024**3)
                }
            }
            
        except ImportError:
            return {
                'status': HealthStatus.UNKNOWN,
                'message': 'psutil not available for system resource monitoring',
                'details': {}
            }
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': f"System resource check failed: {str(e)}",
                'error': str(e)
            }


class HealthCheckRegistry:
    """Registry for managing health checks."""
    
    def __init__(self):
        self.checks: Dict[str, HealthCheck] = {}
        self.check_results: Dict[str, HealthCheckResult] = {}
        self.last_check_time: Optional[datetime] = None
        self._setup_default_checks()
    
    def _setup_default_checks(self):
        """Setup default health checks."""
        # Database health check
        self.register(DatabaseHealthCheck())
        
        # Redis health checks for all configured caches
        for cache_alias in settings.CACHES.keys():
            self.register(RedisHealthCheck(cache_alias))
        
        # Celery health check
        self.register(CeleryHealthCheck())
        
        # System resources health check
        self.register(SystemResourceHealthCheck())
        
        # External service health checks
        self._setup_external_service_checks()
    
    def _setup_external_service_checks(self):
        """Setup external service health checks."""
        # OAuth provider health checks
        oauth_providers = getattr(settings, 'OAUTH_PROVIDERS', {})
        for provider_name in oauth_providers.keys():
            self.register(ExternalServiceHealthCheck(
                f"oauth_{provider_name}",
                lambda: self._check_oauth_provider(provider_name)
            ))
        
        # SMS service health check (Twilio)
        if getattr(settings, 'TWILIO_ACCOUNT_SID', None):
            self.register(ExternalServiceHealthCheck(
                "twilio_sms",
                self._check_twilio_service
            ))
    
    def _check_oauth_provider(self, provider_name: str) -> Dict[str, Any]:
        """Check OAuth provider availability."""
        # This is a simplified check - in practice, you might want to
        # make a lightweight API call to verify the provider is accessible
        provider_config = settings.OAUTH_PROVIDERS.get(provider_name, {})
        
        if not provider_config.get('client_id') or not provider_config.get('client_secret'):
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': f"OAuth provider {provider_name} not configured",
                'details': {'provider': provider_name}
            }
        
        return {
            'status': HealthStatus.HEALTHY,
            'message': f"OAuth provider {provider_name} configured",
            'details': {'provider': provider_name}
        }
    
    def _check_twilio_service(self) -> Dict[str, Any]:
        """Check Twilio SMS service availability."""
        try:
            from twilio.rest import Client
            
            account_sid = settings.TWILIO_ACCOUNT_SID
            auth_token = settings.TWILIO_AUTH_TOKEN
            
            if not account_sid or not auth_token:
                return {
                    'status': HealthStatus.UNHEALTHY,
                    'message': 'Twilio credentials not configured',
                    'details': {}
                }
            
            # Create client and check account info
            client = Client(account_sid, auth_token)
            account = client.api.accounts(account_sid).fetch()
            
            return {
                'status': HealthStatus.HEALTHY,
                'message': 'Twilio service accessible',
                'details': {
                    'account_status': account.status,
                    'account_type': account.type
                }
            }
            
        except ImportError:
            return {
                'status': HealthStatus.UNKNOWN,
                'message': 'Twilio SDK not available',
                'details': {}
            }
        except Exception as e:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': f"Twilio service check failed: {str(e)}",
                'error': str(e)
            }
    
    def register(self, health_check: HealthCheck):
        """Register a health check."""
        self.checks[health_check.name] = health_check
        logger.info(f"Registered health check: {health_check.name}")
    
    def unregister(self, name: str):
        """Unregister a health check."""
        if name in self.checks:
            del self.checks[name]
            if name in self.check_results:
                del self.check_results[name]
            logger.info(f"Unregistered health check: {name}")
    
    def run_check(self, name: str) -> HealthCheckResult:
        """Run a specific health check."""
        if name not in self.checks:
            raise ValueError(f"Health check '{name}' not found")
        
        result = self.checks[name].check()
        self.check_results[name] = result
        
        logger.info(
            f"Health check completed: {name}",
            status=result.status.value,
            duration_ms=result.duration_ms
        )
        
        return result
    
    def run_all_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all registered health checks."""
        results = {}
        
        for name in self.checks.keys():
            try:
                results[name] = self.run_check(name)
            except Exception as e:
                logger.error(f"Failed to run health check {name}", error=str(e))
                results[name] = HealthCheckResult(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Health check execution failed: {str(e)}",
                    duration_ms=0,
                    timestamp=timezone.now(),
                    error=str(e)
                )
        
        self.last_check_time = timezone.now()
        return results
    
    def get_system_health_summary(self) -> Dict[str, Any]:
        """Get overall system health summary."""
        if not self.check_results:
            self.run_all_checks()
        
        total_checks = len(self.check_results)
        healthy_checks = sum(1 for r in self.check_results.values() 
                           if r.status == HealthStatus.HEALTHY)
        degraded_checks = sum(1 for r in self.check_results.values() 
                            if r.status == HealthStatus.DEGRADED)
        unhealthy_checks = sum(1 for r in self.check_results.values() 
                             if r.status == HealthStatus.UNHEALTHY)
        
        # Determine overall status
        if unhealthy_checks > 0:
            overall_status = HealthStatus.UNHEALTHY
        elif degraded_checks > 0:
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY
        
        # Calculate health score (0-100)
        health_score = (healthy_checks / total_checks) * 100 if total_checks > 0 else 0
        
        return {
            'overall_status': overall_status.value,
            'health_score': round(health_score, 2),
            'total_checks': total_checks,
            'healthy_checks': healthy_checks,
            'degraded_checks': degraded_checks,
            'unhealthy_checks': unhealthy_checks,
            'last_check_time': self.last_check_time.isoformat() if self.last_check_time else None,
            'checks': {name: {
                'status': result.status.value,
                'message': result.message,
                'duration_ms': result.duration_ms,
                'timestamp': result.timestamp.isoformat()
            } for name, result in self.check_results.items()}
        }


class SystemHealthMonitor:
    """System health monitoring with alerting capabilities."""
    
    def __init__(self, registry: HealthCheckRegistry):
        self.registry = registry
        self.health_history: List[Dict[str, Any]] = []
        self.alert_thresholds = {
            'health_score_critical': 50.0,
            'health_score_warning': 80.0,
            'consecutive_failures': 3
        }
    
    def monitor_health(self) -> Dict[str, Any]:
        """Monitor system health and trigger alerts if needed."""
        health_summary = self.registry.get_system_health_summary()
        
        # Store health history
        self.health_history.append({
            'timestamp': timezone.now(),
            'health_score': health_summary['health_score'],
            'overall_status': health_summary['overall_status'],
            'unhealthy_checks': health_summary['unhealthy_checks']
        })
        
        # Keep only last 100 entries
        if len(self.health_history) > 100:
            self.health_history = self.health_history[-100:]
        
        # Check for alert conditions
        self._check_alert_conditions(health_summary)
        
        return health_summary
    
    def _check_alert_conditions(self, health_summary: Dict[str, Any]):
        """Check if any alert conditions are met."""
        health_score = health_summary['health_score']
        
        # Critical health score alert
        if health_score < self.alert_thresholds['health_score_critical']:
            self._trigger_alert(
                'critical',
                f"System health critically low: {health_score}%",
                health_summary
            )
        elif health_score < self.alert_thresholds['health_score_warning']:
            self._trigger_alert(
                'warning',
                f"System health degraded: {health_score}%",
                health_summary
            )
        
        # Check for consecutive failures
        if len(self.health_history) >= self.alert_thresholds['consecutive_failures']:
            recent_unhealthy = [
                h['unhealthy_checks'] > 0 
                for h in self.health_history[-self.alert_thresholds['consecutive_failures']:]
            ]
            
            if all(recent_unhealthy):
                self._trigger_alert(
                    'critical',
                    f"System has been unhealthy for {self.alert_thresholds['consecutive_failures']} consecutive checks",
                    health_summary
                )
    
    def _trigger_alert(self, severity: str, message: str, context: Dict[str, Any]):
        """Trigger a health alert."""
        logger.error(
            f"Health alert: {message}",
            severity=severity,
            context=context,
            event_type='health_alert'
        )
        
        # Here you would integrate with your alerting system
        # (email, Slack, PagerDuty, etc.)


# Global health check registry and monitor
health_check_registry = HealthCheckRegistry()
system_health_monitor = SystemHealthMonitor(health_check_registry)