"""
Comprehensive monitoring and observability system for enterprise authentication.

This module provides:
- Structured logging with JSON format and correlation IDs
- Prometheus metrics collection and custom business metrics
- Health checks and status endpoints
- Sentry integration for error tracking
- Grafana dashboard configurations
- Business intelligence dashboards
- Compliance and audit reporting
- Real-time monitoring and alerting
"""

from .performance import (
    performance_collector,
    sla_monitor,
    performance_benchmark,
    performance_alerting,
    monitor_performance
)

from .logging_config import (
    get_structured_logger,
    security_logger,
    audit_logger,
    performance_logger,
    business_logger
)

from .health_checks import (
    health_check_registry,
    system_health_monitor
)

from .metrics import (
    business_metrics_collector,
    compliance_metrics_collector,
    security_metrics_collector
)

from .dashboards import (
    grafana_dashboard_generator,
    business_intelligence_dashboard
)

from .alerting import (
    alert_manager,
    notification_channels
)

__all__ = [
    # Performance monitoring
    'performance_collector',
    'sla_monitor', 
    'performance_benchmark',
    'performance_alerting',
    'monitor_performance',
    
    # Logging
    'get_structured_logger',
    'security_logger',
    'audit_logger',
    'performance_logger',
    'business_logger',
    
    # Health checks
    'health_check_registry',
    'system_health_monitor',
    
    # Metrics
    'business_metrics_collector',
    'compliance_metrics_collector',
    'security_metrics_collector',
    
    # Dashboards
    'grafana_dashboard_generator',
    'business_intelligence_dashboard',
    
    # Alerting
    'alert_manager',
    'notification_channels'
]