"""
URL patterns for performance monitoring endpoints.
"""

from django.urls import path
from ..views.performance import (
    performance_metrics,
    sla_report,
    cache_performance,
    database_performance,
    task_monitoring,
    run_benchmark,
    system_health,
    prometheus_metrics,
    performance_alerts
)

app_name = 'performance'

urlpatterns = [
    # Main performance metrics endpoint
    path('metrics/', performance_metrics, name='metrics'),
    
    # SLA monitoring
    path('sla/', sla_report, name='sla_report'),
    
    # Component-specific performance
    path('cache/', cache_performance, name='cache_performance'),
    path('database/', database_performance, name='database_performance'),
    path('tasks/', task_monitoring, name='task_monitoring'),
    
    # System health and alerts
    path('health/', system_health, name='system_health'),
    path('alerts/', performance_alerts, name='performance_alerts'),
    
    # Benchmarking
    path('benchmark/', run_benchmark, name='run_benchmark'),
    
    # Prometheus metrics (no authentication required for monitoring systems)
    path('prometheus/', prometheus_metrics, name='prometheus_metrics'),
]