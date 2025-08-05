# Enterprise Authentication - Monitoring and Observability System

This comprehensive monitoring and observability system provides real-time insights into the enterprise authentication backend, including performance metrics, security monitoring, business intelligence, and compliance reporting.

## Features

### 1. Structured Logging with JSON Format

- **Correlation ID Support**: Every request gets a unique correlation ID for tracing
- **Request Context**: Automatic inclusion of user ID, IP address, endpoint, and method
- **Security Logging**: Specialized logging for authentication attempts, MFA usage, and security events
- **Audit Logging**: Comprehensive audit trails for compliance requirements
- **Performance Logging**: Detailed performance metrics and slow query detection

### 2. Prometheus Metrics Collection

- **System Metrics**: Request rates, response times, error rates, database performance
- **Authentication Metrics**: Login success rates, MFA adoption, OAuth provider usage
- **Security Metrics**: Threat detection, failed authentication attempts, risk scores
- **Business Metrics**: User registrations, active users, feature usage, conversion rates
- **Compliance Metrics**: GDPR requests, data retention compliance, audit events

### 3. Health Checks and Status Endpoints

- **System Health**: Overall system health score and component status
- **Database Health**: Connection pool status, query performance, availability
- **Redis Health**: Cache performance, connection status, memory usage
- **Celery Health**: Worker status, queue lengths, task performance
- **External Services**: OAuth providers, SMS services, email services

### 4. Sentry Integration

- **Error Tracking**: Automatic error capture and correlation
- **Performance Monitoring**: Request tracing and performance insights
- **Release Tracking**: Deploy tracking and error attribution
- **User Context**: Enhanced error context with user and session information

### 5. Grafana Dashboards

- **System Overview**: High-level system health and performance
- **Authentication Metrics**: Login patterns, success rates, provider usage
- **Security Monitoring**: Threat detection, attack patterns, risk analysis
- **Business Intelligence**: User growth, engagement, feature adoption
- **Performance Monitoring**: Response times, SLA compliance, resource usage
- **Compliance Reporting**: GDPR compliance, audit trails, data retention

### 6. Real-time Alerting

- **Multi-channel Notifications**: Email, Slack, PagerDuty, webhooks
- **Severity-based Routing**: Different channels for different alert severities
- **Alert Suppression**: Time-based and condition-based alert suppression
- **Escalation Procedures**: Automatic escalation for unacknowledged alerts

### 7. Business Intelligence Dashboards

- **User Analytics**: Registration trends, retention rates, engagement metrics
- **Authentication Analytics**: Success rates, method preferences, geographic distribution
- **Security Analytics**: Threat patterns, risk scores, incident response times
- **Compliance Reports**: GDPR/CCPA compliance, audit readiness, data lifecycle

## API Endpoints

### Health Check Endpoints

```
GET /monitoring/health/                    # Basic health check
GET /monitoring/health/detailed/           # Detailed component health
GET /monitoring/status/                    # Public system status
```

### Metrics Endpoints

```
GET /monitoring/metrics/                   # Prometheus metrics
GET /monitoring/metrics/business/          # Business KPIs and analytics
GET /monitoring/metrics/security/          # Security metrics and alerts
GET /monitoring/metrics/performance/       # Performance and SLA reports
```

### Compliance and Reporting

```
GET /monitoring/compliance/report/         # Compliance reports (GDPR, CCPA)
```

### Dashboard Configuration

```
GET /monitoring/dashboards/                # Grafana dashboard configs
GET /monitoring/dashboards/?dashboard=name # Specific dashboard config
```

### Alert Management

```
POST /monitoring/alerts/create/            # Create manual alert
POST /monitoring/alerts/{id}/acknowledge/  # Acknowledge alert
POST /monitoring/alerts/{id}/resolve/      # Resolve alert
```

## Configuration

### Environment Variables

```bash
# Monitoring Configuration
MONITORING_ENABLED=true
HEALTH_CHECK_ENABLED=true
METRICS_COLLECTION_ENABLED=true
BUSINESS_METRICS_ENABLED=true
SECURITY_MONITORING_ENABLED=true
COMPLIANCE_MONITORING_ENABLED=true

# Alert Configuration
ALERT_EMAIL_RECIPIENTS=admin@company.com,ops@company.com
ALERT_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
ALERT_PAGERDUTY_INTEGRATION_KEY=your-pagerduty-key

# Monitoring Digest
MONITORING_DIGEST_RECIPIENTS=management@company.com

# Health Check Configuration
HEALTH_CHECK_TIMEOUT_SECONDS=5
HEALTH_CHECK_CACHE_TTL_SECONDS=30

# Metrics Retention
METRICS_RETENTION_DAYS=90
ALERT_HISTORY_RETENTION_DAYS=30

# Grafana Integration
GRAFANA_URL=https://grafana.company.com
GRAFANA_API_KEY=your-grafana-api-key

# Sentry Configuration
SENTRY_DSN=https://your-sentry-dsn
SENTRY_TRACES_SAMPLE_RATE=0.1
SENTRY_SEND_DEFAULT_PII=true
ENVIRONMENT=production
```

### Django Settings

The monitoring system is automatically configured through Django settings. Key configurations include:

- **Middleware**: Correlation ID, request context, monitoring, and security middleware
- **Celery Tasks**: Scheduled tasks for metrics updates, health checks, and reporting
- **Logging**: Structured JSON logging with correlation IDs
- **Caching**: Redis-based caching for metrics and health check data

## Usage Examples

### Creating Custom Alerts

```python
from enterprise_auth.core.monitoring.alerting import alert_manager, AlertSeverity

# Create a custom alert
alert = alert_manager.create_alert(
    name="custom_business_metric",
    severity=AlertSeverity.HIGH,
    message="Custom business metric exceeded threshold",
    source="business_logic",
    labels={"metric": "conversion_rate", "threshold": "5%"},
    annotations={"runbook": "Check conversion funnel"}
)
```

### Recording Business Metrics

```python
from enterprise_auth.core.monitoring.metrics import business_metrics_collector

# Record user registration
business_metrics_collector.record_user_registration(
    source="web_app",
    method="email",
    country="US",
    device_type="desktop"
)

# Record feature usage
business_metrics_collector.record_feature_usage(
    feature="mfa_setup",
    action="completed",
    user_type="premium"
)
```

### Custom Health Checks

```python
from enterprise_auth.core.monitoring.health_checks import health_check_registry, HealthCheck

class CustomServiceHealthCheck(HealthCheck):
    def _perform_check(self):
        # Your custom health check logic
        if service_is_healthy():
            return {
                'status': HealthStatus.HEALTHY,
                'message': 'Service is operational',
                'details': {'response_time_ms': 50}
            }
        else:
            return {
                'status': HealthStatus.UNHEALTHY,
                'message': 'Service is down',
                'error': 'Connection timeout'
            }

# Register the custom health check
health_check_registry.register(CustomServiceHealthCheck("custom_service"))
```

### Structured Logging

```python
from enterprise_auth.core.monitoring.logging_config import get_structured_logger

logger = get_structured_logger(__name__)

# Log with structured data
logger.info(
    "User action completed",
    user_id="12345",
    action="password_change",
    success=True,
    duration_ms=150
)

# Security logging
from enterprise_auth.core.monitoring.logging_config import security_logger

security_logger.log_authentication_attempt(
    user_id="12345",
    ip_address="192.168.1.1",
    user_agent="Mozilla/5.0...",
    success=True,
    method="password",
    risk_score=0.2
)
```

## Management Commands

### Update Monitoring Metrics

```bash
# Update daily metrics
python manage.py update_monitoring_metrics --daily

# Update monthly metrics
python manage.py update_monitoring_metrics --monthly

# Run health checks
python manage.py update_monitoring_metrics --health-check

# Perform cleanup
python manage.py update_monitoring_metrics --cleanup

# Run all tasks
python manage.py update_monitoring_metrics
```

### Export Dashboard Configurations

```bash
# Export all dashboards
python manage.py export_dashboards --all --output-dir ./dashboards

# Export specific dashboard
python manage.py export_dashboards --dashboard system_overview

# List available dashboards
python manage.py export_dashboards
```

## Celery Tasks

The monitoring system includes several Celery tasks for automated maintenance:

- **update_daily_business_metrics**: Updates daily business KPIs
- **update_monthly_business_metrics**: Updates monthly aggregated metrics
- **run_system_health_checks**: Performs comprehensive health checks
- **cleanup_monitoring_data**: Cleans up old metrics and alerts
- **generate_compliance_report**: Generates compliance reports
- **analyze_security_metrics**: Analyzes security patterns and threats
- **update_sla_compliance_metrics**: Updates SLA compliance tracking
- **send_monitoring_digest**: Sends daily monitoring digest emails

## Grafana Dashboard Setup

1. **Import Dashboard Configurations**:

   ```bash
   python manage.py export_dashboards --all --output-dir ./grafana-dashboards
   ```

2. **Configure Prometheus Data Source**:

   - URL: `http://your-app:8000/monitoring/metrics/`
   - Access: Server (default)
   - Scrape interval: 15s

3. **Import Dashboards**:
   - Use the exported JSON files from the management command
   - Configure appropriate data source references

## Security Considerations

- **Access Control**: Monitoring endpoints require authentication
- **Data Sanitization**: Sensitive data is automatically filtered from logs
- **Correlation IDs**: Enable request tracing without exposing sensitive information
- **Alert Suppression**: Prevents alert spam and information leakage
- **Audit Trails**: Comprehensive logging for security and compliance

## Performance Impact

The monitoring system is designed for minimal performance impact:

- **Asynchronous Processing**: Heavy operations are handled by Celery tasks
- **Efficient Caching**: Redis caching for frequently accessed data
- **Sampling**: Configurable sampling rates for metrics collection
- **Excluded Paths**: Static files and health checks are excluded from monitoring
- **Buffered Metrics**: In-memory buffering with periodic persistence

## Troubleshooting

### Common Issues

1. **High Memory Usage**: Adjust metrics buffer size and retention periods
2. **Slow Health Checks**: Increase timeout values and optimize check logic
3. **Missing Metrics**: Verify Prometheus client installation and configuration
4. **Alert Spam**: Configure appropriate suppression rules and thresholds
5. **Dashboard Errors**: Check Grafana data source configuration and permissions

### Debug Commands

```bash
# Check health status
curl http://localhost:8000/monitoring/health/detailed/

# View Prometheus metrics
curl http://localhost:8000/monitoring/metrics/

# Test alert creation
curl -X POST http://localhost:8000/monitoring/alerts/create/ \
  -H "Content-Type: application/json" \
  -d '{"name": "test_alert", "severity": "medium", "message": "Test alert", "source": "manual"}'
```

## Contributing

When adding new monitoring features:

1. **Follow Patterns**: Use existing patterns for metrics, health checks, and alerts
2. **Add Tests**: Include comprehensive tests for new monitoring components
3. **Update Documentation**: Update this README and add inline documentation
4. **Consider Performance**: Ensure new features don't impact application performance
5. **Security Review**: Review for potential security implications

## License

This monitoring system is part of the Enterprise Authentication Backend and follows the same licensing terms.
