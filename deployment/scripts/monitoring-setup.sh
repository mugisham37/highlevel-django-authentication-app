#!/bin/bash

# Monitoring Setup Script for Enterprise Auth Backend
# This script sets up comprehensive monitoring with Prometheus, Grafana, and alerting

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-monitoring}"
ENTERPRISE_AUTH_NAMESPACE="${ENTERPRISE_AUTH_NAMESPACE:-enterprise-auth}"
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-admin123}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
EMAIL_SMTP_HOST="${EMAIL_SMTP_HOST:-}"
EMAIL_SMTP_USER="${EMAIL_SMTP_USER:-}"
EMAIL_SMTP_PASSWORD="${EMAIL_SMTP_PASSWORD:-}"

# Functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check required tools
    for tool in kubectl helm; do
        if ! command -v $tool &> /dev/null; then
            echo "Error: $tool is not installed"
            exit 1
        fi
    done
    
    # Check kubectl context
    if ! kubectl cluster-info &> /dev/null; then
        echo "Error: kubectl not configured or cluster not accessible"
        exit 1
    fi
    
    log "Prerequisites check passed"
}

create_monitoring_namespace() {
    log "Creating monitoring namespace..."
    
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Label namespace for monitoring
    kubectl label namespace "$NAMESPACE" name=monitoring --overwrite
}

install_prometheus_operator() {
    log "Installing Prometheus Operator..."
    
    # Add Prometheus community Helm repository
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update
    
    # Install kube-prometheus-stack
    helm upgrade --install prometheus-stack prometheus-community/kube-prometheus-stack \
        --namespace "$NAMESPACE" \
        --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
        --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
        --set prometheus.prometheusSpec.ruleSelectorNilUsesHelmValues=false \
        --set prometheus.prometheusSpec.retention=30d \
        --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=50Gi \
        --set grafana.adminPassword="$GRAFANA_ADMIN_PASSWORD" \
        --set grafana.persistence.enabled=true \
        --set grafana.persistence.size=10Gi \
        --set alertmanager.alertmanagerSpec.storage.volumeClaimTemplate.spec.resources.requests.storage=10Gi
    
    log "Prometheus Operator installed successfully"
}

create_service_monitors() {
    log "Creating ServiceMonitor for Enterprise Auth..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: enterprise-auth-monitor
  namespace: $NAMESPACE
  labels:
    app: enterprise-auth
spec:
  selector:
    matchLabels:
      app: enterprise-auth-web
  namespaceSelector:
    matchNames:
    - $ENTERPRISE_AUTH_NAMESPACE
  endpoints:
  - port: web
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: postgres-monitor
  namespace: $NAMESPACE
  labels:
    app: postgres
spec:
  selector:
    matchLabels:
      app: postgres
  namespaceSelector:
    matchNames:
    - $ENTERPRISE_AUTH_NAMESPACE
  endpoints:
  - port: postgres
    interval: 30s
    scrapeTimeout: 10s
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: redis-monitor
  namespace: $NAMESPACE
  labels:
    app: redis
spec:
  selector:
    matchLabels:
      app: redis
  namespaceSelector:
    matchNames:
    - $ENTERPRISE_AUTH_NAMESPACE
  endpoints:
  - port: redis
    interval: 30s
    scrapeTimeout: 10s
EOF
    
    log "ServiceMonitors created successfully"
}

create_prometheus_rules() {
    log "Creating Prometheus alerting rules..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: enterprise-auth-rules
  namespace: $NAMESPACE
  labels:
    app: enterprise-auth
spec:
  groups:
  - name: enterprise-auth.rules
    rules:
    # Application Health Rules
    - alert: EnterpriseAuthDown
      expr: up{job="enterprise-auth-monitor"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Enterprise Auth service is down"
        description: "Enterprise Auth service has been down for more than 1 minute"
    
    - alert: EnterpriseAuthHighErrorRate
      expr: rate(django_http_responses_total_by_status{status=~"5.."}[5m]) > 0.1
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High error rate in Enterprise Auth"
        description: "Error rate is {{ \$value }} errors per second"
    
    - alert: EnterpriseAuthHighResponseTime
      expr: histogram_quantile(0.95, rate(django_http_request_duration_seconds_bucket[5m])) > 1
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High response time in Enterprise Auth"
        description: "95th percentile response time is {{ \$value }} seconds"
    
    # Database Rules
    - alert: PostgreSQLDown
      expr: up{job="postgres-monitor"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "PostgreSQL is down"
        description: "PostgreSQL database has been down for more than 1 minute"
    
    - alert: PostgreSQLHighConnections
      expr: pg_stat_database_numbackends / pg_settings_max_connections > 0.8
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "PostgreSQL high connection usage"
        description: "PostgreSQL connection usage is {{ \$value | humanizePercentage }}"
    
    - alert: PostgreSQLSlowQueries
      expr: rate(pg_stat_database_tup_returned[5m]) / rate(pg_stat_database_tup_fetched[5m]) < 0.1
      for: 10m
      labels:
        severity: warning
      annotations:
        summary: "PostgreSQL slow queries detected"
        description: "Query efficiency is low: {{ \$value | humanizePercentage }}"
    
    # Redis Rules
    - alert: RedisDown
      expr: up{job="redis-monitor"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Redis is down"
        description: "Redis cache has been down for more than 1 minute"
    
    - alert: RedisHighMemoryUsage
      expr: redis_memory_used_bytes / redis_memory_max_bytes > 0.9
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Redis high memory usage"
        description: "Redis memory usage is {{ \$value | humanizePercentage }}"
    
    # Security Rules
    - alert: HighFailedLoginAttempts
      expr: rate(enterprise_auth_failed_login_attempts_total[5m]) > 10
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High failed login attempts"
        description: "Failed login rate is {{ \$value }} attempts per second"
    
    - alert: SuspiciousSecurityEvents
      expr: rate(enterprise_auth_security_events_total{severity="high"}[5m]) > 1
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "High severity security events detected"
        description: "High severity security events rate: {{ \$value }} events per second"
    
    # Infrastructure Rules
    - alert: HighCPUUsage
      expr: rate(container_cpu_usage_seconds_total{namespace="$ENTERPRISE_AUTH_NAMESPACE"}[5m]) > 0.8
      for: 10m
      labels:
        severity: warning
      annotations:
        summary: "High CPU usage"
        description: "CPU usage is {{ \$value | humanizePercentage }}"
    
    - alert: HighMemoryUsage
      expr: container_memory_usage_bytes{namespace="$ENTERPRISE_AUTH_NAMESPACE"} / container_spec_memory_limit_bytes > 0.9
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High memory usage"
        description: "Memory usage is {{ \$value | humanizePercentage }}"
    
    - alert: PodCrashLooping
      expr: rate(kube_pod_container_status_restarts_total{namespace="$ENTERPRISE_AUTH_NAMESPACE"}[15m]) > 0
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Pod is crash looping"
        description: "Pod {{ \$labels.pod }} is restarting frequently"
EOF
    
    log "Prometheus rules created successfully"
}

configure_alertmanager() {
    log "Configuring Alertmanager..."
    
    # Create Alertmanager configuration
    cat <<EOF > /tmp/alertmanager.yml
global:
  smtp_smarthost: '$EMAIL_SMTP_HOST:587'
  smtp_from: '$EMAIL_SMTP_USER'
  smtp_auth_username: '$EMAIL_SMTP_USER'
  smtp_auth_password: '$EMAIL_SMTP_PASSWORD'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default'
  routes:
  - match:
      severity: critical
    receiver: 'critical-alerts'
  - match:
      severity: warning
    receiver: 'warning-alerts'

receivers:
- name: 'default'
  slack_configs:
  - api_url: '$SLACK_WEBHOOK_URL'
    channel: '#alerts'
    title: 'Enterprise Auth Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}{{ end }}'

- name: 'critical-alerts'
  slack_configs:
  - api_url: '$SLACK_WEBHOOK_URL'
    channel: '#critical-alerts'
    title: 'CRITICAL: Enterprise Auth Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}{{ end }}'
  email_configs:
  - to: 'ops-team@example.com'
    subject: 'CRITICAL: Enterprise Auth Alert'
    body: |
      {{ range .Alerts }}
      Alert: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      {{ end }}

- name: 'warning-alerts'
  slack_configs:
  - api_url: '$SLACK_WEBHOOK_URL'
    channel: '#alerts'
    title: 'WARNING: Enterprise Auth Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}\n{{ .Annotations.description }}{{ end }}'

inhibit_rules:
- source_match:
    severity: 'critical'
  target_match:
    severity: 'warning'
  equal: ['alertname', 'cluster', 'service']
EOF
    
    # Create secret for Alertmanager configuration
    kubectl create secret generic alertmanager-prometheus-stack-kube-prom-alertmanager \
        --from-file=alertmanager.yml=/tmp/alertmanager.yml \
        --namespace="$NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Clean up temporary file
    rm /tmp/alertmanager.yml
    
    log "Alertmanager configured successfully"
}

create_grafana_dashboards() {
    log "Creating Grafana dashboards..."
    
    # Create ConfigMap with dashboard JSON
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: enterprise-auth-dashboard
  namespace: $NAMESPACE
  labels:
    grafana_dashboard: "1"
data:
  enterprise-auth.json: |
    {
      "dashboard": {
        "id": null,
        "title": "Enterprise Auth Backend",
        "tags": ["enterprise-auth"],
        "timezone": "browser",
        "panels": [
          {
            "id": 1,
            "title": "Request Rate",
            "type": "graph",
            "targets": [
              {
                "expr": "rate(django_http_requests_total[5m])",
                "legendFormat": "{{ method }} {{ handler }}"
              }
            ],
            "yAxes": [
              {
                "label": "Requests/sec"
              }
            ]
          },
          {
            "id": 2,
            "title": "Response Time",
            "type": "graph",
            "targets": [
              {
                "expr": "histogram_quantile(0.95, rate(django_http_request_duration_seconds_bucket[5m]))",
                "legendFormat": "95th percentile"
              },
              {
                "expr": "histogram_quantile(0.50, rate(django_http_request_duration_seconds_bucket[5m]))",
                "legendFormat": "50th percentile"
              }
            ],
            "yAxes": [
              {
                "label": "Seconds"
              }
            ]
          },
          {
            "id": 3,
            "title": "Error Rate",
            "type": "graph",
            "targets": [
              {
                "expr": "rate(django_http_responses_total_by_status{status=~\"5..\"}[5m])",
                "legendFormat": "5xx errors"
              },
              {
                "expr": "rate(django_http_responses_total_by_status{status=~\"4..\"}[5m])",
                "legendFormat": "4xx errors"
              }
            ],
            "yAxes": [
              {
                "label": "Errors/sec"
              }
            ]
          },
          {
            "id": 4,
            "title": "Active Sessions",
            "type": "stat",
            "targets": [
              {
                "expr": "enterprise_auth_active_sessions_total",
                "legendFormat": "Active Sessions"
              }
            ]
          },
          {
            "id": 5,
            "title": "Database Connections",
            "type": "graph",
            "targets": [
              {
                "expr": "pg_stat_database_numbackends",
                "legendFormat": "Active Connections"
              }
            ],
            "yAxes": [
              {
                "label": "Connections"
              }
            ]
          },
          {
            "id": 6,
            "title": "Redis Memory Usage",
            "type": "graph",
            "targets": [
              {
                "expr": "redis_memory_used_bytes",
                "legendFormat": "Used Memory"
              }
            ],
            "yAxes": [
              {
                "label": "Bytes"
              }
            ]
          }
        ],
        "time": {
          "from": "now-1h",
          "to": "now"
        },
        "refresh": "30s"
      }
    }
EOF
    
    log "Grafana dashboards created successfully"
}

setup_ingress() {
    log "Setting up ingress for monitoring services..."
    
    cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: monitoring-ingress
  namespace: $NAMESPACE
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: monitoring-auth
spec:
  tls:
  - hosts:
    - grafana.example.com
    - prometheus.example.com
    secretName: monitoring-tls
  rules:
  - host: grafana.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: prometheus-stack-grafana
            port:
              number: 80
  - host: prometheus.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: prometheus-stack-kube-prom-prometheus
            port:
              number: 9090
EOF
    
    # Create basic auth secret
    htpasswd -cb /tmp/auth admin "$GRAFANA_ADMIN_PASSWORD"
    kubectl create secret generic monitoring-auth \
        --from-file=auth=/tmp/auth \
        --namespace="$NAMESPACE" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    rm /tmp/auth
    
    log "Ingress configured successfully"
}

show_monitoring_status() {
    log "Monitoring Setup Status:"
    echo "========================"
    echo "Namespace: $NAMESPACE"
    echo ""
    
    # Show pod status
    echo "Pod Status:"
    kubectl get pods -n "$NAMESPACE"
    echo ""
    
    # Show service status
    echo "Service Status:"
    kubectl get services -n "$NAMESPACE"
    echo ""
    
    # Show ingress status
    echo "Ingress Status:"
    kubectl get ingress -n "$NAMESPACE"
    echo ""
    
    log "Access URLs:"
    echo "Grafana: https://grafana.example.com (admin/$GRAFANA_ADMIN_PASSWORD)"
    echo "Prometheus: https://prometheus.example.com"
    echo ""
    echo "To access locally:"
    echo "kubectl port-forward -n $NAMESPACE svc/prometheus-stack-grafana 3000:80"
    echo "kubectl port-forward -n $NAMESPACE svc/prometheus-stack-kube-prom-prometheus 9090:9090"
}

# Main execution
main() {
    log "Starting monitoring setup..."
    
    check_prerequisites
    create_monitoring_namespace
    install_prometheus_operator
    create_service_monitors
    create_prometheus_rules
    
    if [ -n "$SLACK_WEBHOOK_URL" ] || [ -n "$EMAIL_SMTP_HOST" ]; then
        configure_alertmanager
    else
        log "Skipping Alertmanager configuration (no notification channels configured)"
    fi
    
    create_grafana_dashboards
    setup_ingress
    show_monitoring_status
    
    log "Monitoring setup completed successfully!"
}

# Show usage if help requested
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    echo "Usage: $0"
    echo ""
    echo "Environment Variables:"
    echo "  NAMESPACE                    Monitoring namespace (default: monitoring)"
    echo "  ENTERPRISE_AUTH_NAMESPACE    Enterprise auth namespace (default: enterprise-auth)"
    echo "  GRAFANA_ADMIN_PASSWORD       Grafana admin password (default: admin123)"
    echo "  SLACK_WEBHOOK_URL            Slack webhook URL for alerts"
    echo "  EMAIL_SMTP_HOST              SMTP host for email alerts"
    echo "  EMAIL_SMTP_USER              SMTP username for email alerts"
    echo "  EMAIL_SMTP_PASSWORD          SMTP password for email alerts"
    echo ""
    echo "Example:"
    echo "  SLACK_WEBHOOK_URL=https://hooks.slack.com/... $0"
    exit 0
fi

# Run main function
main