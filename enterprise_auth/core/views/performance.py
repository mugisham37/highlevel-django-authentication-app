"""
Performance monitoring API views.
Provides endpoints for accessing performance metrics, SLA reports, and system health.
"""

import logging
from typing import Dict, Any
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import cache_page
from django.contrib.admin.views.decorators import staff_member_required
from django.utils.decorators import method_decorator
from django.views import View
from django.conf import settings
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework import status
from ..monitoring.performance import (
    performance_collector, sla_monitor, performance_benchmark, 
    performance_alerting, PROMETHEUS_AVAILABLE, CONTENT_TYPE_LATEST
)
from ..cache.cache_manager import cache_manager
from ..db.optimization import db_performance_monitor
from ..tasks.monitoring import get_task_monitoring_report

logger = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def performance_metrics(request):
    """
    Get comprehensive performance metrics.
    
    Returns:
        JSON response with performance metrics
    """
    try:
        # Get basic performance metrics
        metrics = {
            'cache_stats': cache_manager.get_cache_stats(),
            'sla_compliance': sla_monitor.get_sla_compliance_report(hours=1),
            'task_monitoring': get_task_monitoring_report(),
            'database_performance': db_performance_monitor.get_performance_report(hours=1),
            'system_health': {
                'monitoring_enabled': getattr(settings, 'PERFORMANCE_MONITORING_ENABLED', True),
                'prometheus_available': PROMETHEUS_AVAILABLE,
                'cache_warming_enabled': getattr(settings, 'CACHE_WARMING_ENABLED', True),
                'db_optimization_enabled': getattr(settings, 'DB_OPTIMIZATION_ENABLED', True)
            }
        }
        
        return Response(metrics, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}")
        return Response(
            {'error': 'Failed to retrieve performance metrics'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def sla_report(request):
    """
    Get SLA compliance report.
    
    Query Parameters:
        hours: Number of hours to analyze (default: 24)
    """
    try:
        hours = int(request.GET.get('hours', 24))
        if hours < 1 or hours > 168:  # Max 1 week
            hours = 24
        
        report = sla_monitor.get_sla_compliance_report(hours=hours)
        
        return Response(report, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Failed to generate SLA report: {e}")
        return Response(
            {'error': 'Failed to generate SLA report'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def cache_performance(request):
    """
    Get cache performance metrics and analysis.
    """
    try:
        cache_stats = cache_manager.get_cache_stats()
        
        # Get cache analysis from recent task execution
        from django.core.cache import cache
        cache_analysis = cache.get('cache:performance_analysis', {})
        
        response_data = {
            'current_stats': cache_stats,
            'analysis': cache_analysis,
            'recommendations': cache_analysis.get('recommendations', [])
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Failed to get cache performance: {e}")
        return Response(
            {'error': 'Failed to retrieve cache performance'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def database_performance(request):
    """
    Get database performance metrics and analysis.
    """
    try:
        hours = int(request.GET.get('hours', 1))
        if hours < 1 or hours > 24:
            hours = 1
        
        # Get database performance report
        db_report = db_performance_monitor.get_performance_report(hours=hours)
        
        # Get database analysis from recent task execution
        from django.core.cache import cache
        db_analysis = cache.get('db:performance_analysis', {})
        
        response_data = {
            'performance_report': db_report,
            'analysis': db_analysis,
            'recommendations': db_analysis.get('optimization_recommendations', [])
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Failed to get database performance: {e}")
        return Response(
            {'error': 'Failed to retrieve database performance'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def task_monitoring(request):
    """
    Get Celery task monitoring report.
    """
    try:
        report = get_task_monitoring_report()
        return Response(report, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Failed to get task monitoring report: {e}")
        return Response(
            {'error': 'Failed to retrieve task monitoring report'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminUser])
def run_benchmark(request):
    """
    Run performance benchmark test.
    
    Request Body:
        {
            "test_name": "string",
            "iterations": integer (optional, default: 100)
        }
    """
    try:
        test_name = request.data.get('test_name')
        iterations = request.data.get('iterations', 100)
        
        if not test_name:
            return Response(
                {'error': 'test_name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Define available benchmark tests
        benchmark_tests = {
            'cache_operations': _benchmark_cache_operations,
            'database_queries': _benchmark_database_queries,
            'authentication': _benchmark_authentication,
            'api_endpoints': _benchmark_api_endpoints
        }
        
        if test_name not in benchmark_tests:
            return Response(
                {'error': f'Unknown test: {test_name}. Available tests: {list(benchmark_tests.keys())}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Run benchmark
        test_function = benchmark_tests[test_name]
        results = performance_benchmark.run_benchmark(test_name, test_function, iterations)
        
        return Response(results, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Benchmark test failed: {e}")
        return Response(
            {'error': 'Benchmark test failed'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def system_health(request):
    """
    Get overall system health status.
    """
    try:
        # Calculate system health score
        health_data = _calculate_system_health()
        
        return Response(health_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Failed to get system health: {e}")
        return Response(
            {'error': 'Failed to retrieve system health'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@require_http_methods(["GET"])
def prometheus_metrics(request):
    """
    Prometheus metrics endpoint.
    
    Returns:
        Prometheus-formatted metrics
    """
    if not getattr(settings, 'PROMETHEUS_METRICS_ENABLED', True):
        return HttpResponse('Metrics disabled', status=404)
    
    if not PROMETHEUS_AVAILABLE:
        return HttpResponse('Prometheus client not available', status=503)
    
    try:
        metrics_data = performance_collector.get_metrics_data()
        return HttpResponse(metrics_data, content_type=CONTENT_TYPE_LATEST)
        
    except Exception as e:
        logger.error(f"Failed to generate Prometheus metrics: {e}")
        return HttpResponse('Internal Server Error', status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminUser])
def performance_alerts(request):
    """
    Get recent performance alerts.
    """
    try:
        # Get recent alerts from the alerting system
        recent_alerts = list(performance_alerting.alert_history)[-50:]  # Last 50 alerts
        
        # Group alerts by severity
        alerts_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for alert in recent_alerts:
            severity = alert.get('severity', 'medium')
            alerts_by_severity[severity].append({
                'metric_name': alert['metric_name'],
                'current_value': alert['current_value'],
                'threshold': alert['threshold'],
                'timestamp': alert['timestamp'].isoformat(),
                'labels': alert.get('labels', {})
            })
        
        response_data = {
            'total_alerts': len(recent_alerts),
            'alerts_by_severity': alerts_by_severity,
            'alert_summary': {
                'critical': len(alerts_by_severity['critical']),
                'high': len(alerts_by_severity['high']),
                'medium': len(alerts_by_severity['medium']),
                'low': len(alerts_by_severity['low'])
            }
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        logger.error(f"Failed to get performance alerts: {e}")
        return Response(
            {'error': 'Failed to retrieve performance alerts'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# Benchmark test functions
def _benchmark_cache_operations():
    """Benchmark cache operations."""
    from django.core.cache import cache
    import time
    
    # Test cache set/get operations
    test_key = f"benchmark_test_{int(time.time())}"
    test_value = {'test': 'data', 'timestamp': time.time()}
    
    cache.set(test_key, test_value, timeout=60)
    retrieved_value = cache.get(test_key)
    cache.delete(test_key)
    
    if retrieved_value != test_value:
        raise Exception("Cache operation failed")


def _benchmark_database_queries():
    """Benchmark database queries."""
    from django.contrib.auth import get_user_model
    
    User = get_user_model()
    
    # Simple query benchmark
    users = User.objects.filter(is_active=True)[:10]
    user_count = len(list(users))
    
    if user_count < 0:  # This should never happen
        raise Exception("Database query failed")


def _benchmark_authentication():
    """Benchmark authentication operations."""
    # This would test JWT token generation/validation
    # For now, just a placeholder
    import time
    time.sleep(0.001)  # Simulate auth operation


def _benchmark_api_endpoints():
    """Benchmark API endpoint response times."""
    # This would make internal API calls
    # For now, just a placeholder
    import time
    time.sleep(0.005)  # Simulate API call


def _calculate_system_health() -> Dict[str, Any]:
    """Calculate overall system health score."""
    health_components = {}
    overall_score = 100.0
    
    try:
        # Cache health (25% weight)
        cache_stats = cache_manager.get_cache_stats()
        cache_hit_rate = cache_stats.get('hit_rate', 0)
        cache_health = min(100, cache_hit_rate * 1.2)  # Scale up slightly
        health_components['cache'] = {
            'score': cache_health,
            'status': 'healthy' if cache_health >= 80 else 'degraded' if cache_health >= 60 else 'unhealthy',
            'details': {
                'hit_rate': cache_hit_rate,
                'memory_usage': cache_stats.get('used_memory_human', 'unknown')
            }
        }
        overall_score -= (100 - cache_health) * 0.25
        
    except Exception as e:
        health_components['cache'] = {'score': 0, 'status': 'error', 'error': str(e)}
        overall_score -= 25
    
    try:
        # Database health (30% weight)
        db_health_check = db_performance_monitor.connection_monitor.check_connection_health()
        db_response_time = db_health_check.get('response_time_ms', 0)
        
        if db_health_check.get('status') == 'healthy':
            if db_response_time <= 50:
                db_health = 100
            elif db_response_time <= 100:
                db_health = 80
            elif db_response_time <= 200:
                db_health = 60
            else:
                db_health = 40
        else:
            db_health = 0
        
        health_components['database'] = {
            'score': db_health,
            'status': db_health_check.get('status', 'unknown'),
            'details': {
                'response_time_ms': db_response_time
            }
        }
        overall_score -= (100 - db_health) * 0.30
        
    except Exception as e:
        health_components['database'] = {'score': 0, 'status': 'error', 'error': str(e)}
        overall_score -= 30
    
    try:
        # SLA compliance (25% weight)
        sla_report = sla_monitor.get_sla_compliance_report(hours=1)
        sla_compliance = sla_report.get('overall_compliance', 100)
        
        health_components['sla_compliance'] = {
            'score': sla_compliance,
            'status': 'healthy' if sla_compliance >= 95 else 'degraded' if sla_compliance >= 90 else 'unhealthy',
            'details': sla_report
        }
        overall_score -= (100 - sla_compliance) * 0.25
        
    except Exception as e:
        health_components['sla_compliance'] = {'score': 0, 'status': 'error', 'error': str(e)}
        overall_score -= 25
    
    try:
        # Task monitoring (20% weight)
        task_report = get_task_monitoring_report()
        task_stats = task_report.get('task_statistics', {}).get('overview', {})
        success_rate = task_stats.get('overall_success_rate', 100)
        
        health_components['task_processing'] = {
            'score': success_rate,
            'status': 'healthy' if success_rate >= 95 else 'degraded' if success_rate >= 90 else 'unhealthy',
            'details': {
                'success_rate': success_rate,
                'total_tasks': task_stats.get('total_tasks_executed', 0),
                'recent_failures': task_stats.get('total_failures', 0)
            }
        }
        overall_score -= (100 - success_rate) * 0.20
        
    except Exception as e:
        health_components['task_processing'] = {'score': 0, 'status': 'error', 'error': str(e)}
        overall_score -= 20
    
    # Ensure score is within bounds
    overall_score = max(0, min(100, overall_score))
    
    # Determine overall status
    if overall_score >= 90:
        overall_status = 'healthy'
    elif overall_score >= 70:
        overall_status = 'degraded'
    else:
        overall_status = 'unhealthy'
    
    logger.info(f"System health calculated: {overall_score:.2f}% ({overall_status})")
    
    return {
        'overall_score': round(overall_score, 2),
        'overall_status': overall_status,
        'components': health_components,
        'timestamp': timezone.now().isoformat()
    }