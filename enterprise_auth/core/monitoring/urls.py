"""
URL configuration for monitoring and observability endpoints.
"""

from django.urls import path
from . import views

app_name = 'monitoring'

urlpatterns = [
    # Health check endpoints
    path('health/', views.HealthCheckView.as_view(), name='health_check'),
    path('health/detailed/', views.DetailedHealthCheckView.as_view(), name='detailed_health_check'),
    path('status/', views.system_status_view, name='system_status'),
    
    # Metrics endpoints
    path('metrics/', views.metrics_endpoint, name='prometheus_metrics'),
    path('metrics/business/', views.business_metrics_view, name='business_metrics'),
    path('metrics/security/', views.security_metrics_view, name='security_metrics'),
    path('metrics/performance/', views.performance_report_view, name='performance_report'),
    
    # Compliance and reporting
    path('compliance/report/', views.compliance_report_view, name='compliance_report'),
    
    # Dashboard configuration
    path('dashboards/', views.dashboard_config_view, name='dashboard_config'),
    
    # Alert management
    path('alerts/create/', views.create_alert_view, name='create_alert'),
    path('alerts/<str:alert_id>/acknowledge/', views.acknowledge_alert_view, name='acknowledge_alert'),
    path('alerts/<str:alert_id>/resolve/', views.resolve_alert_view, name='resolve_alert'),
]