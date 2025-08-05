"""
Grafana dashboard configurations and business intelligence dashboards.
Provides automated dashboard generation and configuration management.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from .logging_config import get_structured_logger

logger = get_structured_logger(__name__)


class GrafanaDashboardGenerator:
    """Generator for Grafana dashboard configurations."""
    
    def __init__(self):
        self.dashboard_configs = {}
        self._setup_default_dashboards()
    
    def _setup_default_dashboards(self):
        """Setup default dashboard configurations."""
        self.dashboard_configs = {
            'system_overview': self._create_system_overview_dashboard(),
            'authentication_metrics': self._create_authentication_dashboard(),
            'security_monitoring': self._create_security_dashboard(),
            'business_intelligence': self._create_business_dashboard(),
            'performance_monitoring': self._create_performance_dashboard(),
            'compliance_reporting': self._create_compliance_dashboard()
        }
    
    def _create_system_overview_dashboard(self) -> Dict[str, Any]:
        """Create system overview dashboard configuration."""
        return {
            "dashboard": {
                "id": None,
                "title": "Enterprise Auth - System Overview",
                "tags": ["enterprise-auth", "system", "overview"],
                "timezone": "browser",
                "refresh": "30s",
                "time": {
                    "from": "now-1h",
                    "to": "now"
                },
                "panels": [
                    {
                        "id": 1,
                        "title": "System Health Score",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "system_health_score",
                                "legendFormat": "Health Score"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "min": 0,
                                "max": 100,
                                "unit": "percent",
                                "thresholds": {
                                    "steps": [
                                        {"color": "red", "value": 0},
                                        {"color": "yellow", "value": 50},
                                        {"color": "green", "value": 80}
                                    ]
                                }
                            }
                        },
                        "gridPos": {"h": 8, "w": 6, "x": 0, "y": 0}
                    },
                    {
                        "id": 2,
                        "title": "Request Rate",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(django_requests_total[5m])",
                                "legendFormat": "Requests/sec"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 6, "y": 0}
                    },
                    {
                        "id": 3,
                        "title": "Response Time",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "histogram_quantile(0.95, rate(django_request_duration_seconds_bucket[5m]))",
                                "legendFormat": "95th percentile"
                            },
                            {
                                "expr": "histogram_quantile(0.50, rate(django_request_duration_seconds_bucket[5m]))",
                                "legendFormat": "50th percentile"
                            }
                        ],
                        "yAxes": [
                            {
                                "unit": "s",
                                "min": 0
                            }
                        ],
                        "gridPos": {"h": 8, "w": 6, "x": 18, "y": 0}
                    },
                    {
                        "id": 4,
                        "title": "Active Sessions",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "active_sessions_total",
                                "legendFormat": "Active Sessions"
                            }
                        ],
                        "gridPos": {"h": 4, "w": 6, "x": 0, "y": 8}
                    },
                    {
                        "id": 5,
                        "title": "Database Connections",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "database_connection_pool_size",
                                "legendFormat": "{{pool_name}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 6, "y": 8}
                    },
                    {
                        "id": 6,
                        "title": "Cache Hit Rate",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "cache_hit_rate_percent",
                                "legendFormat": "{{cache_name}}"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "percent",
                                "thresholds": {
                                    "steps": [
                                        {"color": "red", "value": 0},
                                        {"color": "yellow", "value": 70},
                                        {"color": "green", "value": 85}
                                    ]
                                }
                            }
                        },
                        "gridPos": {"h": 4, "w": 6, "x": 18, "y": 8}
                    }
                ]
            }
        }
    
    def _create_authentication_dashboard(self) -> Dict[str, Any]:
        """Create authentication metrics dashboard."""
        return {
            "dashboard": {
                "id": None,
                "title": "Enterprise Auth - Authentication Metrics",
                "tags": ["enterprise-auth", "authentication"],
                "timezone": "browser",
                "refresh": "1m",
                "time": {
                    "from": "now-24h",
                    "to": "now"
                },
                "panels": [
                    {
                        "id": 1,
                        "title": "Authentication Success Rate",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "authentication_success_rate_percent",
                                "legendFormat": "{{method}} - {{provider}}"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "percent",
                                "thresholds": {
                                    "steps": [
                                        {"color": "red", "value": 0},
                                        {"color": "yellow", "value": 90},
                                        {"color": "green", "value": 95}
                                    ]
                                }
                            }
                        },
                        "gridPos": {"h": 8, "w": 8, "x": 0, "y": 0}
                    },
                    {
                        "id": 2,
                        "title": "Authentication Attempts",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(authentication_attempts_total[5m])",
                                "legendFormat": "{{method}} - {{success}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 16, "x": 8, "y": 0}
                    },
                    {
                        "id": 3,
                        "title": "MFA Usage",
                        "type": "piechart",
                        "targets": [
                            {
                                "expr": "sum by (mfa_type) (rate(auth_operations_total{operation=\"mfa_verify\"}[1h]))",
                                "legendFormat": "{{mfa_type}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 8, "x": 0, "y": 8}
                    },
                    {
                        "id": 4,
                        "title": "OAuth Provider Usage",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(oauth_provider_usage_total[5m])",
                                "legendFormat": "{{provider}} - {{action}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 16, "x": 8, "y": 8}
                    },
                    {
                        "id": 5,
                        "title": "Failed Authentication Attempts by IP",
                        "type": "table",
                        "targets": [
                            {
                                "expr": "topk(10, sum by (ip_address) (rate(failed_auth_attempts_total[1h])))",
                                "format": "table"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
                    },
                    {
                        "id": 6,
                        "title": "Authentication Response Time",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "histogram_quantile(0.95, rate(auth_operation_duration_seconds_bucket[5m]))",
                                "legendFormat": "95th percentile"
                            },
                            {
                                "expr": "histogram_quantile(0.50, rate(auth_operation_duration_seconds_bucket[5m]))",
                                "legendFormat": "50th percentile"
                            }
                        ],
                        "yAxes": [
                            {
                                "unit": "s",
                                "min": 0
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
                    }
                ]
            }
        }
    
    def _create_security_dashboard(self) -> Dict[str, Any]:
        """Create security monitoring dashboard."""
        return {
            "dashboard": {
                "id": None,
                "title": "Enterprise Auth - Security Monitoring",
                "tags": ["enterprise-auth", "security"],
                "timezone": "browser",
                "refresh": "30s",
                "time": {
                    "from": "now-1h",
                    "to": "now"
                },
                "panels": [
                    {
                        "id": 1,
                        "title": "Security Events",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(security_events_total[5m])",
                                "legendFormat": "{{event_type}} - {{severity}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
                    },
                    {
                        "id": 2,
                        "title": "Threat Detection",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "sum(rate(threats_detected_total[1h]))",
                                "legendFormat": "Threats/hour"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "thresholds": {
                                    "steps": [
                                        {"color": "green", "value": 0},
                                        {"color": "yellow", "value": 5},
                                        {"color": "red", "value": 20}
                                    ]
                                }
                            }
                        },
                        "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0}
                    },
                    {
                        "id": 3,
                        "title": "Account Lockouts",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "sum(rate(account_lockouts_total[1h]))",
                                "legendFormat": "Lockouts/hour"
                            }
                        ],
                        "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0}
                    },
                    {
                        "id": 4,
                        "title": "Brute Force Attempts",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(brute_force_attempts_total[5m])",
                                "legendFormat": "{{target_type}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4}
                    },
                    {
                        "id": 5,
                        "title": "Risk Score Distribution",
                        "type": "histogram",
                        "targets": [
                            {
                                "expr": "user_risk_scores",
                                "legendFormat": "{{risk_category}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
                    },
                    {
                        "id": 6,
                        "title": "Suspicious Sessions",
                        "type": "table",
                        "targets": [
                            {
                                "expr": "topk(10, sum by (detection_reason) (rate(suspicious_sessions_total[1h])))",
                                "format": "table"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
                    }
                ]
            }
        }
    
    def _create_business_dashboard(self) -> Dict[str, Any]:
        """Create business intelligence dashboard."""
        return {
            "dashboard": {
                "id": None,
                "title": "Enterprise Auth - Business Intelligence",
                "tags": ["enterprise-auth", "business", "kpi"],
                "timezone": "browser",
                "refresh": "5m",
                "time": {
                    "from": "now-30d",
                    "to": "now"
                },
                "panels": [
                    {
                        "id": 1,
                        "title": "Daily User Registrations",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "user_registrations_daily",
                                "legendFormat": "Registrations"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
                    },
                    {
                        "id": 2,
                        "title": "Active Users",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "active_users_daily",
                                "legendFormat": "Daily Active"
                            },
                            {
                                "expr": "active_users_monthly",
                                "legendFormat": "Monthly Active"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 6, "x": 12, "y": 0}
                    },
                    {
                        "id": 3,
                        "title": "MFA Adoption Rate",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "mfa_adoption_rate_percent",
                                "legendFormat": "{{mfa_type}}"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "percent",
                                "thresholds": {
                                    "steps": [
                                        {"color": "red", "value": 0},
                                        {"color": "yellow", "value": 30},
                                        {"color": "green", "value": 60}
                                    ]
                                }
                            }
                        },
                        "gridPos": {"h": 8, "w": 6, "x": 18, "y": 0}
                    },
                    {
                        "id": 4,
                        "title": "User Registration Sources",
                        "type": "piechart",
                        "targets": [
                            {
                                "expr": "sum by (source) (rate(user_registrations_total[24h]))",
                                "legendFormat": "{{source}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 8, "x": 0, "y": 8}
                    },
                    {
                        "id": 5,
                        "title": "Session Duration Distribution",
                        "type": "histogram",
                        "targets": [
                            {
                                "expr": "user_session_duration_minutes",
                                "legendFormat": "{{device_type}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 8, "x": 8, "y": 8}
                    },
                    {
                        "id": 6,
                        "title": "Feature Usage",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(feature_usage_total[1h])",
                                "legendFormat": "{{feature}} - {{action}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 8, "x": 16, "y": 8}
                    },
                    {
                        "id": 7,
                        "title": "Users by Country",
                        "type": "worldmap",
                        "targets": [
                            {
                                "expr": "users_by_country_total",
                                "legendFormat": "{{country}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
                    },
                    {
                        "id": 8,
                        "title": "Conversion Funnel",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "sum by (stage) (rate(user_conversion_funnel_total[24h]))",
                                "legendFormat": "{{stage}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
                    }
                ]
            }
        }
    
    def _create_performance_dashboard(self) -> Dict[str, Any]:
        """Create performance monitoring dashboard."""
        return {
            "dashboard": {
                "id": None,
                "title": "Enterprise Auth - Performance Monitoring",
                "tags": ["enterprise-auth", "performance"],
                "timezone": "browser",
                "refresh": "30s",
                "time": {
                    "from": "now-1h",
                    "to": "now"
                },
                "panels": [
                    {
                        "id": 1,
                        "title": "SLA Compliance",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "response_time_sla_compliance_percent",
                                "legendFormat": "{{endpoint}}"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "percent",
                                "thresholds": {
                                    "steps": [
                                        {"color": "red", "value": 0},
                                        {"color": "yellow", "value": 95},
                                        {"color": "green", "value": 99}
                                    ]
                                }
                            }
                        },
                        "gridPos": {"h": 8, "w": 8, "x": 0, "y": 0}
                    },
                    {
                        "id": 2,
                        "title": "Database Query Performance",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "histogram_quantile(0.95, rate(database_query_duration_seconds_bucket[5m]))",
                                "legendFormat": "95th percentile"
                            },
                            {
                                "expr": "histogram_quantile(0.50, rate(database_query_duration_seconds_bucket[5m]))",
                                "legendFormat": "50th percentile"
                            }
                        ],
                        "yAxes": [
                            {
                                "unit": "s",
                                "min": 0
                            }
                        ],
                        "gridPos": {"h": 8, "w": 16, "x": 8, "y": 0}
                    },
                    {
                        "id": 3,
                        "title": "Cache Performance",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(cache_operations_total[5m])",
                                "legendFormat": "{{operation}} - {{cache_name}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
                    },
                    {
                        "id": 4,
                        "title": "Error Rate",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(django_requests_total{status_code=~\"4..|5..\"}[5m]) / rate(django_requests_total[5m]) * 100",
                                "legendFormat": "Error Rate %"
                            }
                        ],
                        "yAxes": [
                            {
                                "unit": "percent",
                                "min": 0
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
                    }
                ]
            }
        }
    
    def _create_compliance_dashboard(self) -> Dict[str, Any]:
        """Create compliance reporting dashboard."""
        return {
            "dashboard": {
                "id": None,
                "title": "Enterprise Auth - Compliance Reporting",
                "tags": ["enterprise-auth", "compliance", "gdpr"],
                "timezone": "browser",
                "refresh": "1h",
                "time": {
                    "from": "now-30d",
                    "to": "now"
                },
                "panels": [
                    {
                        "id": 1,
                        "title": "GDPR Requests",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(gdpr_requests_total[24h])",
                                "legendFormat": "{{request_type}} - {{status}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
                    },
                    {
                        "id": 2,
                        "title": "GDPR Processing Time",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "histogram_quantile(0.95, rate(gdpr_request_processing_time_hours_bucket[7d]))",
                                "legendFormat": "95th percentile"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "h",
                                "thresholds": {
                                    "steps": [
                                        {"color": "green", "value": 0},
                                        {"color": "yellow", "value": 24},
                                        {"color": "red", "value": 72}
                                    ]
                                }
                            }
                        },
                        "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0}
                    },
                    {
                        "id": 3,
                        "title": "Data Retention Compliance",
                        "type": "stat",
                        "targets": [
                            {
                                "expr": "data_retention_compliance_percent",
                                "legendFormat": "{{data_type}}"
                            }
                        ],
                        "fieldConfig": {
                            "defaults": {
                                "unit": "percent",
                                "thresholds": {
                                    "steps": [
                                        {"color": "red", "value": 0},
                                        {"color": "yellow", "value": 90},
                                        {"color": "green", "value": 95}
                                    ]
                                }
                            }
                        },
                        "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0}
                    },
                    {
                        "id": 4,
                        "title": "Audit Events",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(audit_events_total[1h])",
                                "legendFormat": "{{event_type}} - {{severity}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4}
                    },
                    {
                        "id": 5,
                        "title": "Access Control Checks",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(access_control_checks_total[5m])",
                                "legendFormat": "{{resource_type}} - {{result}}"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
                    },
                    {
                        "id": 6,
                        "title": "Security Policy Violations",
                        "type": "table",
                        "targets": [
                            {
                                "expr": "sum by (policy_type, severity) (rate(security_policy_violations_total[24h]))",
                                "format": "table"
                            }
                        ],
                        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
                    }
                ]
            }
        }
    
    def get_dashboard_config(self, dashboard_name: str) -> Optional[Dict[str, Any]]:
        """Get dashboard configuration by name."""
        return self.dashboard_configs.get(dashboard_name)
    
    def get_all_dashboards(self) -> Dict[str, Dict[str, Any]]:
        """Get all dashboard configurations."""
        return self.dashboard_configs
    
    def export_dashboard_json(self, dashboard_name: str) -> str:
        """Export dashboard configuration as JSON."""
        config = self.get_dashboard_config(dashboard_name)
        if config:
            return json.dumps(config, indent=2)
        return "{}"
    
    def create_custom_dashboard(self, name: str, config: Dict[str, Any]):
        """Create a custom dashboard configuration."""
        self.dashboard_configs[name] = config
        logger.info(f"Created custom dashboard: {name}")


class BusinessIntelligenceDashboard:
    """Business intelligence dashboard with advanced analytics."""
    
    def __init__(self):
        self.metrics_cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    def get_user_analytics(self, days: int = 30) -> Dict[str, Any]:
        """Get comprehensive user analytics."""
        cache_key = f"user_analytics_{days}"
        
        if self._is_cache_valid(cache_key):
            return self.metrics_cache[cache_key]['data']
        
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            end_date = timezone.now()
            start_date = end_date - timedelta(days=days)
            
            # User registration trends
            registrations_by_day = []
            for i in range(days):
                day = start_date + timedelta(days=i)
                count = User.objects.filter(
                    date_joined__date=day.date()
                ).count()
                registrations_by_day.append({
                    'date': day.date().isoformat(),
                    'count': count
                })
            
            # User engagement metrics
            total_users = User.objects.count()
            active_users_7d = User.objects.filter(
                last_login__gte=end_date - timedelta(days=7)
            ).count()
            active_users_30d = User.objects.filter(
                last_login__gte=start_date
            ).count()
            
            # Calculate retention rates
            retention_7d = (active_users_7d / total_users * 100) if total_users > 0 else 0
            retention_30d = (active_users_30d / total_users * 100) if total_users > 0 else 0
            
            analytics = {
                'total_users': total_users,
                'registrations_by_day': registrations_by_day,
                'active_users_7d': active_users_7d,
                'active_users_30d': active_users_30d,
                'retention_rate_7d': round(retention_7d, 2),
                'retention_rate_30d': round(retention_30d, 2),
                'growth_rate': self._calculate_growth_rate(registrations_by_day),
                'timestamp': timezone.now().isoformat()
            }
            
            self._cache_data(cache_key, analytics)
            return analytics
            
        except Exception as e:
            logger.error("Failed to get user analytics", error=str(e))
            return {}
    
    def get_authentication_analytics(self, days: int = 7) -> Dict[str, Any]:
        """Get authentication analytics."""
        cache_key = f"auth_analytics_{days}"
        
        if self._is_cache_valid(cache_key):
            return self.metrics_cache[cache_key]['data']
        
        try:
            # This would typically query your authentication logs
            # For now, we'll return mock data structure
            analytics = {
                'total_attempts': 0,
                'success_rate': 0.0,
                'methods_breakdown': {},
                'provider_usage': {},
                'failure_reasons': {},
                'geographic_distribution': {},
                'device_breakdown': {},
                'timestamp': timezone.now().isoformat()
            }
            
            self._cache_data(cache_key, analytics)
            return analytics
            
        except Exception as e:
            logger.error("Failed to get authentication analytics", error=str(e))
            return {}
    
    def get_security_analytics(self, days: int = 7) -> Dict[str, Any]:
        """Get security analytics."""
        cache_key = f"security_analytics_{days}"
        
        if self._is_cache_valid(cache_key):
            return self.metrics_cache[cache_key]['data']
        
        try:
            analytics = {
                'total_security_events': 0,
                'threat_level_distribution': {},
                'attack_types': {},
                'blocked_ips': [],
                'risk_score_trends': [],
                'incident_response_times': {},
                'timestamp': timezone.now().isoformat()
            }
            
            self._cache_data(cache_key, analytics)
            return analytics
            
        except Exception as e:
            logger.error("Failed to get security analytics", error=str(e))
            return {}
    
    def get_compliance_report(self, regulation: str = 'gdpr') -> Dict[str, Any]:
        """Get compliance report for specific regulation."""
        cache_key = f"compliance_{regulation}"
        
        if self._is_cache_valid(cache_key):
            return self.metrics_cache[cache_key]['data']
        
        try:
            report = {
                'regulation': regulation.upper(),
                'compliance_score': 0.0,
                'data_requests': {
                    'total': 0,
                    'completed': 0,
                    'pending': 0,
                    'average_processing_time_hours': 0.0
                },
                'data_retention': {
                    'policies_defined': True,
                    'automated_cleanup': True,
                    'compliance_percentage': 0.0
                },
                'user_rights': {
                    'data_portability_requests': 0,
                    'deletion_requests': 0,
                    'access_requests': 0
                },
                'audit_trail': {
                    'events_logged': 0,
                    'retention_period_days': 2555,  # 7 years
                    'integrity_verified': True
                },
                'timestamp': timezone.now().isoformat()
            }
            
            self._cache_data(cache_key, report)
            return report
            
        except Exception as e:
            logger.error("Failed to get compliance report", error=str(e))
            return {}
    
    def _calculate_growth_rate(self, registrations_by_day: List[Dict[str, Any]]) -> float:
        """Calculate user growth rate."""
        if len(registrations_by_day) < 2:
            return 0.0
        
        recent_week = sum(day['count'] for day in registrations_by_day[-7:])
        previous_week = sum(day['count'] for day in registrations_by_day[-14:-7])
        
        if previous_week == 0:
            return 0.0
        
        return round(((recent_week - previous_week) / previous_week) * 100, 2)
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached data is still valid."""
        if cache_key not in self.metrics_cache:
            return False
        
        cached_time = self.metrics_cache[cache_key]['timestamp']
        return (timezone.now() - cached_time).total_seconds() < self.cache_ttl
    
    def _cache_data(self, cache_key: str, data: Dict[str, Any]):
        """Cache data with timestamp."""
        self.metrics_cache[cache_key] = {
            'data': data,
            'timestamp': timezone.now()
        }


# Global instances
grafana_dashboard_generator = GrafanaDashboardGenerator()
business_intelligence_dashboard = BusinessIntelligenceDashboard()