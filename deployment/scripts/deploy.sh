#!/bin/bash

# Enterprise Auth Deployment Script
# Zero-downtime deployment with rollback capabilities

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEPLOYMENT_DIR="${PROJECT_ROOT}/deployment"

# Default values
ENVIRONMENT="${ENVIRONMENT:-staging}"
NAMESPACE="${NAMESPACE:-enterprise-auth}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
DRY_RUN="${DRY_RUN:-false}"
SKIP_BACKUP="${SKIP_BACKUP:-false}"
ROLLBACK_ON_FAILURE="${ROLLBACK_ON_FAILURE:-true}"

# Logging
LOG_FILE="/tmp/enterprise-auth-deploy-$(date +%Y%m%d-%H%M%S).log"
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')

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
    -e, --environment ENV       Target environment (staging|production) [default: staging]
    -t, --tag TAG              Docker image tag [default: latest]
    -n, --namespace NAMESPACE   Kubernetes namespace [default: enterprise-auth]
    -d, --dry-run              Perform dry run without actual deployment
    -s, --skip-backup          Skip database backup before deployment
    -r, --no-rollback          Disable automatic rollback on failure
    -h, --help                 Show this help message

Examples:
    $0 --environment staging --tag v1.2.3
    $0 --environment production --tag v1.2.3 --no-rollback
    $0 --dry-run --environment staging
EOF
}

check_dependencies() {
    local deps=("kubectl" "docker" "curl" "jq")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error_exit "Required dependency '$dep' not found"
        fi
    done
}

validate_environment() {
    case "${ENVIRONMENT}" in
        development|staging|production)
            log "Deploying to environment: ${ENVIRONMENT}"
            ;;
        *)
            error_exit "Invalid environment: ${ENVIRONMENT}. Must be one of: development, staging, production"
            ;;
    esac
}

check_kubernetes_connection() {
    log "Checking Kubernetes connection..."
    
    if ! kubectl cluster-info &> /dev/null; then
        error_exit "Cannot connect to Kubernetes cluster"
    fi
    
    if ! kubectl get namespace "${NAMESPACE}" &> /dev/null; then
        log "Creating namespace: ${NAMESPACE}"
        kubectl create namespace "${NAMESPACE}" || error_exit "Failed to create namespace"
    fi
    
    log "Kubernetes connection verified"
}

validate_image() {
    local image_name="$1"
    local image_tag="$2"
    
    log "Validating Docker image: ${image_name}:${image_tag}"
    
    # Check if image exists in registry
    if ! docker manifest inspect "${image_name}:${image_tag}" &> /dev/null; then
        error_exit "Docker image not found: ${image_name}:${image_tag}"
    fi
    
    log "Docker image validated"
}

create_backup() {
    if [[ "${SKIP_BACKUP}" == "true" ]]; then
        log "Skipping database backup as requested"
        return 0
    fi
    
    log "Creating database backup before deployment..."
    
    local backup_pod
    backup_pod=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=postgres -o jsonpath='{.items[0].metadata.name}')
    
    if [[ -z "${backup_pod}" ]]; then
        log "WARNING: No PostgreSQL pod found, skipping backup"
        return 0
    fi
    
    kubectl exec -n "${NAMESPACE}" "${backup_pod}" -- /deployment/scripts/backup-database.sh \
        || log "WARNING: Database backup failed"
    
    log "Database backup completed"
}

update_manifests() {
    local temp_dir
    temp_dir=$(mktemp -d)
    
    log "Updating Kubernetes manifests with image tag: ${IMAGE_TAG}"
    
    # Copy manifests to temp directory
    cp -r "${DEPLOYMENT_DIR}/kubernetes/"* "${temp_dir}/"
    
    # Update image tags in manifests
    find "${temp_dir}" -name "*.yaml" -type f -exec sed -i "s|enterprise-auth:latest|enterprise-auth:${IMAGE_TAG}|g" {} \;
    find "${temp_dir}" -name "*.yaml" -type f -exec sed -i "s|enterprise-auth-celery:latest|enterprise-auth-celery:${IMAGE_TAG}|g" {} \;
    
    # Update environment-specific configurations
    if [[ -f "${DEPLOYMENT_DIR}/environments/${ENVIRONMENT}.env" ]]; then
        log "Applying environment-specific configuration: ${ENVIRONMENT}"
        
        # Create ConfigMap from environment file
        kubectl create configmap enterprise-auth-env-config \
            --from-env-file="${DEPLOYMENT_DIR}/environments/${ENVIRONMENT}.env" \
            --namespace="${NAMESPACE}" \
            --dry-run=client -o yaml | kubectl apply -f -
    fi
    
    echo "${temp_dir}"
}

deploy_infrastructure() {
    local manifest_dir="$1"
    
    log "Deploying infrastructure components..."
    
    # Deploy in order of dependencies
    local components=(
        "namespace.yaml"
        "secrets.yaml"
        "configmap.yaml"
        "rbac.yaml"
        "postgres.yaml"
        "redis.yaml"
    )
    
    for component in "${components[@]}"; do
        if [[ -f "${manifest_dir}/${component}" ]]; then
            log "Applying ${component}..."
            kubectl apply -f "${manifest_dir}/${component}" --namespace="${NAMESPACE}"
        fi
    done
    
    # Wait for infrastructure to be ready
    log "Waiting for infrastructure components to be ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgres -n "${NAMESPACE}" --timeout=300s || true
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n "${NAMESPACE}" --timeout=300s || true
}

run_migrations() {
    log "Running database migrations..."
    
    # Create a temporary job for migrations
    local migration_job="enterprise-auth-migrate-${TIMESTAMP}"
    
    cat << EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: ${migration_job}
  namespace: ${NAMESPACE}
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: migrate
        image: enterprise-auth:${IMAGE_TAG}
        command: ["python", "manage.py", "migrate"]
        envFrom:
        - configMapRef:
            name: enterprise-auth-config
        - secretRef:
            name: enterprise-auth-secrets
      backoffLimit: 3
EOF
    
    # Wait for migration to complete
    kubectl wait --for=condition=complete job/${migration_job} -n "${NAMESPACE}" --timeout=600s \
        || error_exit "Database migration failed"
    
    # Clean up migration job
    kubectl delete job/${migration_job} -n "${NAMESPACE}"
    
    log "Database migrations completed"
}

deploy_application() {
    local manifest_dir="$1"
    
    log "Deploying application components..."
    
    # Deploy application components
    local components=(
        "web-deployment.yaml"
        "celery-deployment.yaml"
        "nginx-deployment.yaml"
        "hpa.yaml"
    )
    
    for component in "${components[@]}"; do
        if [[ -f "${manifest_dir}/${component}" ]]; then
            log "Applying ${component}..."
            kubectl apply -f "${manifest_dir}/${component}" --namespace="${NAMESPACE}"
        fi
    done
    
    # Wait for deployments to be ready
    log "Waiting for application deployments to be ready..."
    kubectl rollout status deployment/enterprise-auth-web -n "${NAMESPACE}" --timeout=600s
    kubectl rollout status deployment/enterprise-auth-celery-worker -n "${NAMESPACE}" --timeout=600s
    kubectl rollout status deployment/nginx -n "${NAMESPACE}" --timeout=600s
}

run_health_checks() {
    log "Running health checks..."
    
    # Get service endpoint
    local service_ip
    service_ip=$(kubectl get service nginx -n "${NAMESPACE}" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    
    if [[ -z "${service_ip}" ]]; then
        service_ip=$(kubectl get service nginx -n "${NAMESPACE}" -o jsonpath='{.spec.clusterIP}')
    fi
    
    if [[ -z "${service_ip}" ]]; then
        log "WARNING: Could not determine service IP, skipping external health checks"
        return 0
    fi
    
    local health_url="http://${service_ip}/health/"
    local max_attempts=30
    local attempt=1
    
    while [[ ${attempt} -le ${max_attempts} ]]; do
        log "Health check attempt ${attempt}/${max_attempts}..."
        
        if curl -f -s "${health_url}" > /dev/null; then
            log "Health check passed"
            return 0
        fi
        
        sleep 10
        ((attempt++))
    done
    
    error_exit "Health checks failed after ${max_attempts} attempts"
}

run_smoke_tests() {
    log "Running smoke tests..."
    
    # Create a temporary pod for smoke tests
    local test_pod="enterprise-auth-smoke-test-${TIMESTAMP}"
    
    cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${test_pod}
  namespace: ${NAMESPACE}
spec:
  restartPolicy: Never
  containers:
  - name: smoke-test
    image: curlimages/curl:latest
    command: ["sh", "-c"]
    args:
    - |
      set -e
      echo "Running smoke tests..."
      
      # Test health endpoint
      curl -f http://nginx/health/ || exit 1
      echo "✓ Health endpoint OK"
      
      # Test API endpoints
      curl -f http://nginx/api/v1/auth/providers || exit 1
      echo "✓ API endpoints OK"
      
      echo "All smoke tests passed"
EOF
    
    # Wait for smoke tests to complete
    kubectl wait --for=condition=ready pod/${test_pod} -n "${NAMESPACE}" --timeout=300s || true
    kubectl logs ${test_pod} -n "${NAMESPACE}" || true
    
    # Check if smoke tests passed
    local exit_code
    exit_code=$(kubectl get pod ${test_pod} -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}')
    
    # Clean up test pod
    kubectl delete pod/${test_pod} -n "${NAMESPACE}"
    
    if [[ "${exit_code}" != "0" ]]; then
        error_exit "Smoke tests failed"
    fi
    
    log "Smoke tests completed successfully"
}

rollback_deployment() {
    log "Rolling back deployment..."
    
    # Rollback deployments
    kubectl rollout undo deployment/enterprise-auth-web -n "${NAMESPACE}"
    kubectl rollout undo deployment/enterprise-auth-celery-worker -n "${NAMESPACE}"
    kubectl rollout undo deployment/nginx -n "${NAMESPACE}"
    
    # Wait for rollback to complete
    kubectl rollout status deployment/enterprise-auth-web -n "${NAMESPACE}" --timeout=600s
    kubectl rollout status deployment/enterprise-auth-celery-worker -n "${NAMESPACE}" --timeout=600s
    kubectl rollout status deployment/nginx -n "${NAMESPACE}" --timeout=600s
    
    log "Rollback completed"
}

send_notification() {
    local status="$1"
    local message="$2"
    
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        local notification_message
        if [[ "${status}" == "success" ]]; then
            notification_message="✅ Deployment to ${ENVIRONMENT} completed successfully: ${message}"
        else
            notification_message="❌ Deployment to ${ENVIRONMENT} failed: ${message}"
        fi
        
        curl -X POST "${WEBHOOK_URL}" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"${notification_message}\"}" \
            || log "WARNING: Failed to send notification"
    fi
}

cleanup() {
    log "Cleaning up temporary files..."
    rm -rf /tmp/enterprise-auth-deploy-*
}

# Main execution
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -n|--namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN="true"
                shift
                ;;
            -s|--skip-backup)
                SKIP_BACKUP="true"
                shift
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
    
    log "Starting deployment process..."
    log "Environment: ${ENVIRONMENT}"
    log "Image Tag: ${IMAGE_TAG}"
    log "Namespace: ${NAMESPACE}"
    log "Dry Run: ${DRY_RUN}"
    
    # Pre-flight checks
    check_dependencies
    validate_environment
    check_kubernetes_connection
    validate_image "enterprise-auth" "${IMAGE_TAG}"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log "DRY RUN: Would deploy enterprise-auth:${IMAGE_TAG} to ${ENVIRONMENT}"
        exit 0
    fi
    
    # Create backup
    create_backup
    
    # Update manifests
    local manifest_dir
    manifest_dir=$(update_manifests)
    
    # Deploy infrastructure
    deploy_infrastructure "${manifest_dir}"
    
    # Run migrations
    run_migrations
    
    # Deploy application
    deploy_application "${manifest_dir}"
    
    # Run health checks
    run_health_checks
    
    # Run smoke tests
    run_smoke_tests
    
    # Cleanup
    cleanup
    
    # Send success notification
    send_notification "success" "Image: ${IMAGE_TAG}"
    
    log "Deployment completed successfully"
}

# Error handling with rollback
handle_error() {
    local exit_code=$?
    log "Deployment failed with exit code: ${exit_code}"
    
    if [[ "${ROLLBACK_ON_FAILURE}" == "true" && "${DRY_RUN}" != "true" ]]; then
        rollback_deployment
    fi
    
    cleanup
    send_notification "error" "Deployment failed"
    exit ${exit_code}
}

trap handle_error ERR

# Execute main function
main "$@"