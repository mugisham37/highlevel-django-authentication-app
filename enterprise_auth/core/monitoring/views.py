"""
Monitoring and observability API endpoints.
Provides health checks, metrics, and monitoring data access.
"""

import json
import logging
from typing import Dict, Any
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import never_cache
from django.utils.decorators import method_decorator
from django.views import View
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from .health_checks import health_check_registry, system_health_monitor
from .performance import performance_collector
from .metrics import (
    business_metrics_collector,
    compliance_metrics_collector,
    security_metrics_collector
)
from .dashboards import grafana_dashboard_generator, business_intelligence_dashboard
from .alerting import alert_manager
from .logging_config import get_structured_logger

logger = get_structured_logger(__name__)


@method_decorator(never_cache, name='dispatch')
class HealthCheckView(View):
    """Health check endpoint for system monitoring."""
    
    def get(self, request):
        """Get system health status."""
        try:
            # Run health checks
            health_summary = system_health_monitor.monitor_health()
            
            # Determine HTTP status code based on health
            if health_summary['overall_status'] == 'unhealthy':
                http_status = 503  # Service Unavailable
            elif health_summary['overall_status'] == 'degraded':
                http_status = 200  # OK but with warnings
            else:
                http_status = 200  # OK
            
            return JsonResponse(health_summary, status=http_status)
            
        except Exception as e:
            logger.error("Health check failed", error=str(e))
            return JsonResponse({
                'overall_status': 'unhealthy',
                'error': 'Health check system failure',
                'message': str(e)
            }, status=503)


@method_decorator(never_cache, name='dispatch')
class DetailedHealthCheckView(View):
    """Detailed health check endpoint with individual component status."""
    
    def get(self, request):
        """Get detailed health status for all components."""
        try:
            # Run all health checks
            check_results = health_check_registry.run_all_checks()
            
            # Format results
            detailed_results = {}
            overall_healthy = True
            
            for check_name, result in check_results.items():
                detailed_results[check_name] = {
                    'status': result.status.value,
                    'message': result.message,
                    'duration_ms': result.duration_ms,
                    'timestamp': result.timestamp.isoformat(),
                    'details': result.details
                }
                
                if result.status.value in ['unhealthy', 'degraded']:
                    overall_healthy = False
            
            response_data = {
                'overall_status': 'healthy' if overall_healthy else 'unhealthy',
                'checks': detailed_results,
                'summary': health_check_registry.get_system_health_summary()
            }
            
            http_status = 200 if overall_healthy else 503
            return JsonResponse(response_data, status=http_status)
            
        except Exception as e:
            logger.error("Detailed health check failed", error=str(e))
            return JsonResponse({
                'overall_status': 'unhealthy',
                'error': 'Detailed health check system failure',
                'message': str(e)
            }, status=503)


@require_http_methods(["GET"])
@never_cache
def metrics_endpoint(request):
    """Prometheus metrics endpoint."""
    try:
        # Get Prometheus metrics data
        metrics_data = performance_collector.get_metrics_data()
        
        # Return metrics in Prometheus format
        return HttpResponse(
            metrics_data,
            content_type='text/plain; version=0.0.4; charset=utf-8'
        )
        
    except Exception as e:
        logger.error("Metrics endpoint failed", error=str(e))
        return HttpResponse(
            "# Metrics collection failed\n",
            content_type='text/plain',
            status=500
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def business_metrics_view(request):
    """Get business metrics and KPIs."""
    try:
        # Get business KPIs
        kpis = business_metrics_collector.get_business_kpis()
        
        # Get user analytics
        user_analytics = business_intelligence_dashboard.get_user_analytics(
            days=int(request.GET.get('days', 30))
        )
        
        # Get authentication analytics
        auth_analytics = business_intelligence_dashboard.get_authentication_analytics(
            days=int(request.GET.get('days', 7))
        )
        
        return Response({
            'kpis': kpis,
            'user_analytics': user_analytics,
            'authentication_analytics': auth_analytics
        })
        
    except Exception as e:
        logger.error("Business metrics view failed", error=str(e))
        return Response(
            {'error': 'Failed to retrieve business metrics'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def security_metrics_view(request):
    """Get security metrics and analytics."""
    try:
        # Get security analytics
        security_analytics = business_intelligence_dashboard.get_security_analytics(
            days=int(request.GET.get('days', 7))
        )
        
        # Get active alerts
        active_alerts = alert_manager.get_active_alerts()
        alert_summary = alert_manager.get_alert_summary()
        
        return Response({
            'security_analytics': security_analytics,
            'active_alerts': [
                {
                    'id': alert.id,
                    'name': alert.name,
                    'severity': alert.severity.value,
                    'status': alert.status.value,
                    'message': alert.message,
                    'timestamp': alert.timestamp.isoformat(),
                    'source': alert.source
                }
                for alert in active_alerts
            ],
            'alert_summary': alert_summary
        })
        
    except Exception as e:
        logger.error("Security metrics view failed", error=str(e))
        return Response(
            {'error': 'Failed to retrieve security metrics'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def compliance_report_view(request):
    """Get compliance report."""
    try:
        regulation = request.GET.get('regulation', 'gdpr')
        
        # Get compliance report
        compliance_report = business_intelligence_dashboard.get_compliance_report(regulation)
        
        return Response({
            'compliance_report': compliance_report
        })
        
    except Exception as e:
        logger.error("Compliance report view failed", error=str(e))
        return Response(
            {'error': 'Failed to retrieve compliance report'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_config_view(request):
    """Get Grafana dashboard configurations."""
    try:
        dashboard_name = request.GET.get('dashboard')
        
        if dashboard_name:
            # Get specific dashboard
            config = grafana_dashboard_generator.get_dashboard_config(dashboard_name)
            if not config:
                return Response(
                    {'error': f'Dashboard {dashboard_name} not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            return Response(config)
        else:
            # Get all dashboards
            all_dashboards = grafana_dashboard_generator.get_all_dashboards()
            return Response({
                'dashboards': list(all_dashboards.keys()),
                'configs': all_dashboards
            })
        
    except Exception as e:
        logger.error("Dashboard config view failed", error=str(e))
        return Response(
            {'error': 'Failed to retrieve dashboard configuration'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_alert_view(request):
    """Create a manual alert."""
    try:
        data = request.data
        
        # Validate required fields
        required_fields = ['name', 'severity', 'message', 'source']
        for field in required_fields:
            if field not in data:
                return Response(
                    {'error': f'Missing required field: {field}'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Create alert
        from .alerting import AlertSeverity
        severity_map = {
            'low': AlertSeverity.LOW,
            'medium': AlertSeverity.MEDIUM,
            'high': AlertSeverity.HIGH,
            'critical': AlertSeverity.CRITICAL
        }
        
        severity = severity_map.get(data['severity'].lower())
        if not severity:
            return Response(
                {'error': 'Invalid severity level'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        alert = alert_manager.create_alert(
            name=data['name'],
            severity=severity,
            message=data['message'],
            source=data['source'],
            labels=data.get('labels', {}),
            annotations=data.get('annotations', {})
        )
        
        return Response({
            'alert_id': alert.id,
            'status': 'created',
            'message': 'Alert created successfully'
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error("Create alert view failed", error=str(e))
        return Response(
            {'error': 'Failed to create alert'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def acknowledge_alert_view(request, alert_id):
    """Acknowledge an alert."""
    try:
        acknowledged_by = request.user.email if hasattr(request.user, 'email') else str(request.user)
        
        alert_manager.acknowledge_alert(alert_id, acknowledged_by)
        
        return Response({
            'status': 'acknowledged',
            'message': 'Alert acknowledged successfully'
        })
        
    except Exception as e:
        logger.error("Acknowledge alert view failed", error=str(e))
        return Response(
            {'error': 'Failed to acknowledge alert'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def resolve_alert_view(request, alert_id):
    """Resolve an alert."""
    try:
        resolved_by = request.user.email if hasattr(request.user, 'email') else str(request.user)
        
        alert_manager.resolve_alert(alert_id, resolved_by)
        
        return Response({
            'status': 'resolved',
            'message': 'Alert resolved successfully'
        })
        
    except Exception as e:
        logger.error("Resolve alert view failed", error=str(e))
        return Response(
            {'error': 'Failed to resolve alert'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([AllowAny])
def system_status_view(request):
    """Public system status endpoint."""
    try:
        # Get basic system health without sensitive details
        health_summary = health_check_registry.get_system_health_summary()
        
        # Remove sensitive information
        public_status = {
            'status': health_summary['overall_status'],
            'health_score': health_summary['health_score'],
            'last_check_time': health_summary['last_check_time'],
            'services': {}
        }
        
        # Add high-level service status
        for check_name, check_result in health_summary['checks'].items():
            service_category = check_name.split('_')[0]  # e.g., 'database', 'redis', 'celery'
            
            if service_category not in public_status['services']:
                public_status['services'][service_category] = {
                    'status': check_result['status'],
                    'last_check': check_result['timestamp']
                }
        
        return Response(public_status)
        
    except Exception as e:
        logger.error("System status view failed", error=str(e))
        return Response(
            {'status': 'unknown', 'error': 'Status check failed'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def performance_report_view(request):
    """Get performance report and SLA compliance."""
    try:
        from .performance import sla_monitor
        
        # Get SLA compliance report
        hours = int(request.GET.get('hours', 24))
        sla_report = sla_monitor.get_sla_compliance_report(hours)
        
        # Get recent performance metrics
        recent_metrics = performance_collector.get_recent_metrics(
            minutes=int(request.GET.get('minutes', 60))
        )
        
        return Response({
            'sla_report': sla_report,
            'recent_metrics': [
                {
                    'name': metric.name,
                    'value': metric.value,
                    'timestamp': metric.timestamp.isoformat(),
                    'labels': metric.labels,
                    'unit': metric.unit
                }
                for metric in recent_metrics
            ]
        })
        
    except Exception as e:
        logger.error("Performance report view failed", error=str(e))
        return Response(
            {'error': 'Failed to retrieve performance report'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )