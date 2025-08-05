#!/bin/bash

# Enterprise Auth Deployment Monitoring Script
# Monitors deployment health and provides rollback capabilities

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
NAMESPACE="${NAMESPACE:-enterprise-auth}"
ENVIRONMENT="${ENVIRONMENT:-staging}"
MONITORING_DURATION="${MONITORING_DURATION:-300}"  # 5 minutes
CHECK_INTERVAL="${CHECK_INTERVAL:-30}"              # 30 seconds
HEALTH_THRESHOLD="${HEALTH_THRESHOLD:-3}"           # 3 consecutive failures
ROLLBACK_ON_FAILURE="${ROLLBACK_ON_FAILURE:-true}"

# Logging
LOG_FILE="/tmp/enterprise-auth-monitor-$(date +%Y%m%d-%H%M%S).log"

# Counters
CONSECUTIVE_FAILURES=0
TOTAL_CHECKS=0
SUCCESSFUL_CHECKS=0

# Functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -n, --namespace NAMESPACE       Kubernetes namespace [default: enterprise-auth]
    -e, --environment ENV           Environment (staging|production) [default: staging]
    -d, --duration SECONDS          Monitoring duration in seconds [default: 300]
    -i, --interval SECONDS          Check interval in seconds [default: 30]
    -t, --threshold COUNT           Consecutive failure threshold [default: 3]
    -r, --no-rollback              Disable automatic rollback on failure
    -h, --help                     Show this help message

Examples:
    $0 --environment production --duration 600
    $0 --namespace enterprise-auth --threshold 5
    $0 --no-rollback --duration 120
EOF
}

check_dependencies() {
    local deps=("kubectl" "curl" "jq")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error_exit "Required dependency '$dep' not found"
        fi
    done
}

get_deployment_status() {
    local deployment="$1"
    
    kubectl get deployment "${deployment}" -n "${NAMESPACE}" -o json 2>/dev/null | \
        jq -r '.status | {
            replicas: .replicas,
            readyReplicas: .readyReplicas,
            availableReplicas: .availableReplicas,
            updatedReplicas: .updatedReplicas
        }'
}

check_pod_health() {
    log "Checking pod health..."
    
    local unhealthy_pods=0
    local total_pods=0
    
    # Check web pods
    local web_pods
    web_pods=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/component=web -o json)
    
    if [[ -n "${web_pods}" ]]; then
        local web_pod_count
        web_pod_count=$(echo "${web_pods}" | jq '.items | length')
        total_pods=$((total_pods + web_pod_count))
        
        local web_ready_count
        web_ready_count=$(echo "${web_pods}" | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')
        
        unhealthy_pods=$((unhealthy_pods + web_pod_count - web_ready_count))
        
        log "Web pods: ${web_ready_count}/${web_pod_count} ready"
    fi
    
    # Check Celery worker pods
    local celery_pods
    celery_pods=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/component=celery-worker -o json)
    
    if [[ -n "${celery_pods}" ]]; then
        local celery_pod_count
        celery_pod_count=$(echo "${celery_pods}" | jq '.items | length')
        total_pods=$((total_pods + celery_pod_count))
        
        local celery_ready_count
        celery_ready_count=$(echo "${celery_pods}" | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')
        
        unhealthy_pods=$((unhealthy_pods + celery_pod_count - celery_ready_count))
        
        log "Celery worker pods: ${celery_ready_count}/${celery_pod_count} ready"
    fi
    
    if [[ ${unhealthy_pods} -gt 0 ]]; then
        log "WARNING: ${unhealthy_pods}/${total_pods} pods are not ready"
        return 1
    else
        log "All ${total_pods} pods are healthy"
        return 0
    fi
}

check_service_endpoints() {
    log "Checking service endpoints..."
    
    # Get service IP
    local service_ip
    service_ip=$(kubectl get service nginx -n "${NAMESPACE}" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    
    if [[ -z "${service_ip}" ]]; then
        service_ip=$(kubectl get service nginx -n "${NAMESPACE}" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || echo "")
    fi
    
    if [[ -z "${service_ip}" ]]; then
        log "WARNING: Could not determine service IP"
        return 1
    fi
    
    # Check health endpoint
    local health_url="http://${service_ip}/health/"
    if curl -f -s --max-time 10 "${health_url}" > /dev/null; then
        log "Health endpoint OK: ${health_url}"
    else
        log "ERROR: Health endpoint failed: ${health_url}"
        return 1
    fi
    
    # Check readiness endpoint
    local ready_url="http://${service_ip}/health/ready/"
    if curl -f -s --max-time 10 "${ready_url}" > /dev/null; then
        log "Readiness endpoint OK: ${ready_url}"
    else
        log "ERROR: Readiness endpoint failed: ${ready_url}"
        return 1
    fi
    
    # Check API endpoint
    local api_url="http://${service_ip}/api/v1/auth/providers"
    if curl -f -s --max-time 10 "${api_url}" > /dev/null; then
        log "API endpoint OK: ${api_url}"
    else
        log "ERROR: API endpoint failed: ${api_url}"
        return 1
    fi
    
    return 0
}

check_database_connectivity() {
    log "Checking database connectivity..."
    
    local postgres_pod
    postgres_pod=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -z "${postgres_pod}" ]]; then
        log "WARNING: PostgreSQL pod not found"
        return 1
    fi
    
    # Check database connection
    if kubectl exec -n "${NAMESPACE}" "${postgres_pod}" -- pg_isready -U enterprise_auth_user -d enterprise_auth > /dev/null 2>&1; then
        log "Database connectivity OK"
        return 0
    else
        log "ERROR: Database connectivity failed"
        return 1
    fi
}

check_redis_connectivity() {
    log "Checking Redis connectivity..."
    
    local redis_pod
    redis_pod=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=redis -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -z "${redis_pod}" ]]; then
        log "WARNING: Redis pod not found"
        return 1
    fi
    
    # Check Redis connection
    if kubectl exec -n "${NAMESPACE}" "${redis_pod}" -- redis-cli ping > /dev/null 2>&1; then
        log "Redis connectivity OK"
        return 0
    else
        log "ERROR: Redis connectivity failed"
        return 1
    fi
}

check_resource_usage() {
    log "Checking resource usage..."
    
    # Get pod resource usage
    local resource_usage
    resource_usage=$(kubectl top pods -n "${NAMESPACE}" --no-headers 2>/dev/null || echo "")
    
    if [[ -n "${resource_usage}" ]]; then
        log "Resource usage:"
        echo "${resource_usage}" | while read -r line; do
            log "  ${line}"
        done
        
        # Check for high CPU usage (>80%)
        local high_cpu_pods
        high_cpu_pods=$(echo "${resource_usage}" | awk '$2 ~ /[8-9][0-9]%|[0-9][0-9][0-9]%/ {print $1}' || echo "")
        
        if [[ -n "${high_cpu_pods}" ]]; then
            log "WARNING: High CPU usage detected in pods: ${high_cpu_pods}"
        fi
        
        # Check for high memory usage (>80%)
        local high_mem_pods
        high_mem_pods=$(echo "${resource_usage}" | awk '$3 ~ /[8-9][0-9]%|[0-9][0-9][0-9]%/ {print $1}' || echo "")
        
        if [[ -n "${high_mem_pods}" ]]; then
            log "WARNING: High memory usage detected in pods: ${high_mem_pods}"
        fi
    else
        log "WARNING: Could not retrieve resource usage metrics"
    fi
}

check_deployment_events() {
    log "Checking recent deployment events..."
    
    # Get recent events
    local events
    events=$(kubectl get events -n "${NAMESPACE}" --sort-by='.lastTimestamp' --field-selector type=Warning -o json 2>/dev/null || echo '{"items":[]}')
    
    local warning_count
    warning_count=$(echo "${events}" | jq '.items | length')
    
    if [[ ${warning_count} -gt 0 ]]; then
        log "Found ${warning_count} warning events:"
        echo "${events}" | jq -r '.items[] | "  " + .lastTimestamp + " " + .reason + ": " + .message' | tail -5
    else
        log "No warning events found"
    fi
}

perform_comprehensive_health_check() {
    log "Performing comprehensive health check..."
    
    local checks_passed=0
    local total_checks=6
    
    # Run individual checks
    if check_pod_health; then
        ((checks_passed++))
    fi
    
    if check_service_endpoints; then
        ((checks_passed++))
    fi
    
    if check_database_connectivity; then
        ((checks_passed++))
    fi
    
    if check_redis_connectivity; then
        ((checks_passed++))
    fi
    
    # Non-critical checks
    check_resource_usage
    ((checks_passed++))
    
    check_deployment_events
    ((checks_passed++))
    
    local health_percentage=$((checks_passed * 100 / total_checks))
    log "Health check completed: ${checks_passed}/${total_checks} checks passed (${health_percentage}%)"
    
    # Consider deployment healthy if critical checks pass (first 4 checks)
    if [[ ${checks_passed} -ge 4 ]]; then
        return 0
    else
        return 1
    fi
}

rollback_deployment() {
    log "Initiating deployment rollback..."
    
    # Rollback web deployment
    log "Rolling back web deployment..."
    kubectl rollout undo deployment/enterprise-auth-web -n "${NAMESPACE}"
    
    # Rollback Celery deployment
    log "Rolling back Celery deployment..."
    kubectl rollout undo deployment/enterprise-auth-celery-worker -n "${NAMESPACE}"
    
    # Wait for rollback to complete
    log "Waiting for rollback to complete..."
    kubectl rollout status deployment/enterprise-auth-web -n "${NAMESPACE}" --timeout=600s
    kubectl rollout status deployment/enterprise-auth-celery-worker -n "${NAMESPACE}" --timeout=600s
    
    log "Deployment rollback completed"
}

send_alert() {
    local severity="$1"
    local message="$2"
    
    log "ALERT [${severity}]: ${message}"
    
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        local emoji
        case "${severity}" in
            CRITICAL) emoji="🚨" ;;
            WARNING) emoji="⚠️" ;;
            INFO) emoji="ℹ️" ;;
            *) emoji="📢" ;;
        esac
        
        local notification_message="${emoji} [${severity}] Enterprise Auth ${ENVIRONMENT}: ${message}"
        
        curl -X POST "${WEBHOOK_URL}" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"${notification_message}\"}" \
            || log "WARNING: Failed to send alert notification"
    fi
}

generate_monitoring_report() {
    local report_file="/tmp/enterprise-auth-monitoring-report-$(date +%Y%m%d-%H%M%S).json"
    
    log "Generating monitoring report: ${report_file}"
    
    cat > "${report_file}" << EOF
{
  "monitoring_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": "${ENVIRONMENT}",
  "namespace": "${NAMESPACE}",
  "monitoring_duration": ${MONITORING_DURATION},
  "check_interval": ${CHECK_INTERVAL},
  "total_checks": ${TOTAL_CHECKS},
  "successful_checks": ${SUCCESSFUL_CHECKS},
  "success_rate": $(( SUCCESSFUL_CHECKS * 100 / TOTAL_CHECKS )),
  "consecutive_failures": ${CONSECUTIVE_FAILURES},
  "health_threshold": ${HEALTH_THRESHOLD},
  "rollback_triggered": false,
  "log_file": "${LOG_FILE}"
}
EOF
    
    log "Monitoring report generated: ${report_file}"
}

# Main monitoring loop
monitor_deployment() {
    log "Starting deployment monitoring..."
    log "Duration: ${MONITORING_DURATION} seconds"
    log "Check interval: ${CHECK_INTERVAL} seconds"
    log "Failure threshold: ${HEALTH_THRESHOLD} consecutive failures"
    
    local start_time
    start_time=$(date +%s)
    local end_time=$((start_time + MONITORING_DURATION))
    
    while [[ $(date +%s) -lt ${end_time} ]]; do
        ((TOTAL_CHECKS++))
        
        log "Health check ${TOTAL_CHECKS}..."
        
        if perform_comprehensive_health_check; then
            ((SUCCESSFUL_CHECKS++))
            CONSECUTIVE_FAILURES=0
            log "Health check ${TOTAL_CHECKS} passed"
        else
            ((CONSECUTIVE_FAILURES++))
            log "Health check ${TOTAL_CHECKS} failed (${CONSECUTIVE_FAILURES} consecutive failures)"
            
            if [[ ${CONSECUTIVE_FAILURES} -ge ${HEALTH_THRESHOLD} ]]; then
                send_alert "CRITICAL" "Deployment health check failed ${CONSECUTIVE_FAILURES} times consecutively"
                
                if [[ "${ROLLBACK_ON_FAILURE}" == "true" ]]; then
                    rollback_deployment
                    send_alert "INFO" "Automatic rollback completed"
                    break
                else
                    send_alert "WARNING" "Automatic rollback disabled, manual intervention required"
                fi
            else
                send_alert "WARNING" "Deployment health check failed (${CONSECUTIVE_FAILURES}/${HEALTH_THRESHOLD})"
            fi
        fi
        
        # Sleep until next check
        if [[ $(date +%s) -lt ${end_time} ]]; then
            sleep ${CHECK_INTERVAL}
        fi
    done
    
    # Final summary
    local success_rate
    if [[ ${TOTAL_CHECKS} -gt 0 ]]; then
        success_rate=$((SUCCESSFUL_CHECKS * 100 / TOTAL_CHECKS))
    else
        success_rate=0
    fi
    
    log "Monitoring completed:"
    log "  Total checks: ${TOTAL_CHECKS}"
    log "  Successful checks: ${SUCCESSFUL_CHECKS}"
    log "  Success rate: ${success_rate}%"
    log "  Final consecutive failures: ${CONSECUTIVE_FAILURES}"
    
    if [[ ${success_rate} -ge 90 ]]; then
        send_alert "INFO" "Deployment monitoring completed successfully (${success_rate}% success rate)"
    elif [[ ${success_rate} -ge 70 ]]; then
        send_alert "WARNING" "Deployment monitoring completed with issues (${success_rate}% success rate)"
    else
        send_alert "CRITICAL" "Deployment monitoring completed with significant issues (${success_rate}% success rate)"
    fi
}

# Main execution
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -d|--duration)
                MONITORING_DURATION="$2"
                shift 2
                ;;
            -i|--interval)
                CHECK_INTERVAL="$2"
                shift 2
                ;;
            -t|--threshold)
                HEALTH_THRESHOLD="$2"
                shift 2
                ;;
            -r|--no-rollback)
                ROLLBACK_ON_FAILURE="false"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    # Pre-flight checks
    check_dependencies
    
    # Start monitoring
    monitor_deployment
    
    # Generate report
    generate_monitoring_report
    
    log "Deployment monitoring completed"
}

# Error handling
trap 'log "Monitoring interrupted"; exit 1' INT TERM

# Execute main function
main "$@"