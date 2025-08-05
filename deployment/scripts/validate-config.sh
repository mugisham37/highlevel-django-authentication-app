#!/bin/bash

# Enterprise Auth Configuration Validation Script
# Validates configuration files and environment settings

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEPLOYMENT_DIR="${PROJECT_ROOT}/deployment"

# Default values
ENVIRONMENT="${ENVIRONMENT:-staging}"
VERBOSE="${VERBOSE:-false}"

# Logging
LOG_FILE="/tmp/enterprise-auth-config-validation-$(date +%Y%m%d-%H%M%S).log"

# Functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

verbose_log() {
    if [[ "${VERBOSE}" == "true" ]]; then
        log "$1"
    fi
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

warning() {
    log "WARNING: $1"
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
    -e, --environment ENV       Target environment (development|staging|production) [default: staging]
    -v, --verbose              Enable verbose logging
    -h, --help                 Show this help message

Examples:
    $0 --environment production --verbose
    $0 --environment staging
EOF
}

check_dependencies() {
    local deps=("kubectl" "yq" "jq" "openssl")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error_exit "Required dependency '$dep' not found"
        fi
    done
}

validate_environment_file() {
    local env_file="${DEPLOYMENT_DIR}/environments/${ENVIRONMENT}.env"
    
    log "Validating environment file: ${env_file}"
    
    if [[ ! -f "${env_file}" ]]; then
        error_exit "Environment file not found: ${env_file}"
    fi
    
    # Check for required environment variables
    local required_vars=(
        "DJANGO_SETTINGS_MODULE"
        "DATABASE_URL"
        "REDIS_URL"
        "JWT_SECRET_KEY"
        "ENCRYPTION_KEY"
    )
    
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" "${env_file}"; then
            missing_vars+=("${var}")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        error_exit "Missing required environment variables: ${missing_vars[*]}"
    fi
    
    # Validate specific configurations
    validate_database_config "${env_file}"
    validate_redis_config "${env_file}"
    validate_security_config "${env_file}"
    validate_oauth_config "${env_file}"
    validate_external_services_config "${env_file}"
    
    log "Environment file validation passed"
}

validate_database_config() {
    local env_file="$1"
    
    verbose_log "Validating database configuration..."
    
    # Extract database URL
    local db_url
    db_url=$(grep "^DATABASE_URL=" "${env_file}" | cut -d'=' -f2- | tr -d '"')
    
    if [[ ! "${db_url}" =~ ^postgresql:// ]]; then
        error_exit "Invalid database URL format. Must start with postgresql://"
    fi
    
    # Check database connection parameters
    local required_db_vars=("DATABASE_HOST" "DATABASE_PORT" "DATABASE_NAME" "DATABASE_USER")
    
    for var in "${required_db_vars[@]}"; do
        if ! grep -q "^${var}=" "${env_file}"; then
            warning "Database variable ${var} not found in environment file"
        fi
    done
    
    verbose_log "Database configuration validation passed"
}

validate_redis_config() {
    local env_file="$1"
    
    verbose_log "Validating Redis configuration..."
    
    # Extract Redis URL
    local redis_url
    redis_url=$(grep "^REDIS_URL=" "${env_file}" | cut -d'=' -f2- | tr -d '"')
    
    if [[ ! "${redis_url}" =~ ^redis:// ]]; then
        error_exit "Invalid Redis URL format. Must start with redis://"
    fi
    
    # Check Redis connection parameters
    local required_redis_vars=("REDIS_HOST" "REDIS_PORT" "REDIS_DB")
    
    for var in "${required_redis_vars[@]}"; do
        if ! grep -q "^${var}=" "${env_file}"; then
            warning "Redis variable ${var} not found in environment file"
        fi
    done
    
    verbose_log "Redis configuration validation passed"
}

validate_security_config() {
    local env_file="$1"
    
    verbose_log "Validating security configuration..."
    
    # Check JWT secret key strength
    local jwt_secret
    jwt_secret=$(grep "^JWT_SECRET_KEY=" "${env_file}" | cut -d'=' -f2- | tr -d '"')
    
    if [[ ${#jwt_secret} -lt 32 ]]; then
        error_exit "JWT secret key must be at least 32 characters long"
    fi
    
    # Check encryption key
    local encryption_key
    encryption_key=$(grep "^ENCRYPTION_KEY=" "${env_file}" | cut -d'=' -f2- | tr -d '"')
    
    if [[ ${#encryption_key} -ne 32 ]]; then
        error_exit "Encryption key must be exactly 32 characters long"
    fi
    
    # Validate security headers for production
    if [[ "${ENVIRONMENT}" == "production" ]]; then
        local security_vars=(
            "SECURE_SSL_REDIRECT=True"
            "SECURE_HSTS_SECONDS=31536000"
            "SECURE_HSTS_INCLUDE_SUBDOMAINS=True"
            "SECURE_HSTS_PRELOAD=True"
            "X_FRAME_OPTIONS=DENY"
        )
        
        for var in "${security_vars[@]}"; do
            if ! grep -q "^${var}" "${env_file}"; then
                error_exit "Production security setting missing: ${var}"
            fi
        done
    fi
    
    verbose_log "Security configuration validation passed"
}

validate_oauth_config() {
    local env_file="$1"
    
    verbose_log "Validating OAuth configuration..."
    
    # Check OAuth provider configurations
    local oauth_providers=("GOOGLE" "GITHUB" "MICROSOFT")
    
    for provider in "${oauth_providers[@]}"; do
        local client_id_var="${provider}_CLIENT_ID"
        local client_secret_var="${provider}_CLIENT_SECRET"
        
        if grep -q "^${client_id_var}=" "${env_file}"; then
            if ! grep -q "^${client_secret_var}=" "${env_file}"; then
                error_exit "OAuth provider ${provider} has client ID but missing client secret"
            fi
            
            # Check for placeholder values
            local client_id
            client_id=$(grep "^${client_id_var}=" "${env_file}" | cut -d'=' -f2- | tr -d '"')
            
            if [[ "${client_id}" == *"REPLACE_WITH"* || "${client_id}" == *"dev-"* ]]; then
                if [[ "${ENVIRONMENT}" == "production" ]]; then
                    error_exit "Production environment has placeholder OAuth credentials for ${provider}"
                else
                    warning "Development/staging OAuth credentials detected for ${provider}"
                fi
            fi
        fi
    done
    
    verbose_log "OAuth configuration validation passed"
}

validate_external_services_config() {
    local env_file="$1"
    
    verbose_log "Validating external services configuration..."
    
    # Check Twilio configuration
    if grep -q "^TWILIO_ACCOUNT_SID=" "${env_file}"; then
        if ! grep -q "^TWILIO_AUTH_TOKEN=" "${env_file}"; then
            error_exit "Twilio account SID found but auth token missing"
        fi
    fi
    
    # Check AWS configuration
    if grep -q "^AWS_ACCESS_KEY_ID=" "${env_file}"; then
        if ! grep -q "^AWS_SECRET_ACCESS_KEY=" "${env_file}"; then
            error_exit "AWS access key ID found but secret access key missing"
        fi
        
        if ! grep -q "^AWS_REGION=" "${env_file}"; then
            warning "AWS credentials found but region not specified"
        fi
    fi
    
    # Check monitoring configuration
    if [[ "${ENVIRONMENT}" == "production" ]]; then
        if ! grep -q "^SENTRY_DSN=" "${env_file}" || grep -q "^SENTRY_DSN=$" "${env_file}"; then
            warning "Production environment should have Sentry DSN configured"
        fi
    fi
    
    verbose_log "External services configuration validation passed"
}

validate_kubernetes_manifests() {
    log "Validating Kubernetes manifests..."
    
    local manifest_dir="${DEPLOYMENT_DIR}/kubernetes"
    
    if [[ ! -d "${manifest_dir}" ]]; then
        error_exit "Kubernetes manifests directory not found: ${manifest_dir}"
    fi
    
    # Validate YAML syntax
    find "${manifest_dir}" -name "*.yaml" -type f | while read -r manifest; do
        verbose_log "Validating YAML syntax: $(basename "${manifest}")"
        
        if ! yq eval '.' "${manifest}" > /dev/null 2>&1; then
            error_exit "Invalid YAML syntax in: ${manifest}"
        fi
    done
    
    # Validate Kubernetes resource definitions
    validate_resource_limits
    validate_security_contexts
    validate_network_policies
    validate_rbac_configuration
    
    log "Kubernetes manifests validation passed"
}

validate_resource_limits() {
    verbose_log "Validating resource limits..."
    
    local deployment_files=(
        "${DEPLOYMENT_DIR}/kubernetes/web-deployment.yaml"
        "${DEPLOYMENT_DIR}/kubernetes/celery-deployment.yaml"
        "${DEPLOYMENT_DIR}/kubernetes/postgres.yaml"
        "${DEPLOYMENT_DIR}/kubernetes/redis.yaml"
    )
    
    for file in "${deployment_files[@]}"; do
        if [[ -f "${file}" ]]; then
            # Check if resource limits are defined
            if ! yq eval '.spec.template.spec.containers[].resources.limits' "${file}" | grep -q "cpu\|memory"; then
                warning "Resource limits not defined in: $(basename "${file}")"
            fi
            
            # Check if resource requests are defined
            if ! yq eval '.spec.template.spec.containers[].resources.requests' "${file}" | grep -q "cpu\|memory"; then
                warning "Resource requests not defined in: $(basename "${file}")"
            fi
        fi
    done
}

validate_security_contexts() {
    verbose_log "Validating security contexts..."
    
    local deployment_files=(
        "${DEPLOYMENT_DIR}/kubernetes/web-deployment.yaml"
        "${DEPLOYMENT_DIR}/kubernetes/celery-deployment.yaml"
    )
    
    for file in "${deployment_files[@]}"; do
        if [[ -f "${file}" ]]; then
            # Check for non-root user
            if ! yq eval '.spec.template.spec.securityContext.runAsNonRoot' "${file}" | grep -q "true"; then
                error_exit "Security context should specify runAsNonRoot: true in: $(basename "${file}")"
            fi
            
            # Check for read-only root filesystem
            if ! yq eval '.spec.template.spec.containers[].securityContext.readOnlyRootFilesystem' "${file}" | grep -q "true"; then
                warning "Consider setting readOnlyRootFilesystem: true in: $(basename "${file}")"
            fi
        fi
    done
}

validate_network_policies() {
    verbose_log "Validating network policies..."
    
    local network_policy_file="${DEPLOYMENT_DIR}/kubernetes/rbac.yaml"
    
    if [[ -f "${network_policy_file}" ]]; then
        if ! yq eval '.kind' "${network_policy_file}" | grep -q "NetworkPolicy"; then
            warning "Network policy not found in RBAC configuration"
        fi
    else
        warning "RBAC configuration file not found"
    fi
}

validate_rbac_configuration() {
    verbose_log "Validating RBAC configuration..."
    
    local rbac_file="${DEPLOYMENT_DIR}/kubernetes/rbac.yaml"
    
    if [[ -f "${rbac_file}" ]]; then
        # Check for service account
        if ! yq eval '.kind' "${rbac_file}" | grep -q "ServiceAccount"; then
            error_exit "ServiceAccount not found in RBAC configuration"
        fi
        
        # Check for role and role binding
        if ! yq eval '.kind' "${rbac_file}" | grep -q "Role"; then
            error_exit "Role not found in RBAC configuration"
        fi
        
        if ! yq eval '.kind' "${rbac_file}" | grep -q "RoleBinding"; then
            error_exit "RoleBinding not found in RBAC configuration"
        fi
    else
        error_exit "RBAC configuration file not found"
    fi
}

validate_secrets_configuration() {
    log "Validating secrets configuration..."
    
    local secrets_file="${DEPLOYMENT_DIR}/kubernetes/secrets.yaml"
    
    if [[ ! -f "${secrets_file}" ]]; then
        error_exit "Secrets configuration file not found: ${secrets_file}"
    fi
    
    # Check for placeholder values in secrets
    if grep -q "REPLACE_WITH" "${secrets_file}"; then
        if [[ "${ENVIRONMENT}" == "production" ]]; then
            error_exit "Production secrets contain placeholder values"
        else
            warning "Secrets contain placeholder values (acceptable for ${ENVIRONMENT})"
        fi
    fi
    
    # Validate secret structure
    if ! yq eval '.kind' "${secrets_file}" | grep -q "Secret"; then
        error_exit "Invalid secret configuration structure"
    fi
    
    verbose_log "Secrets configuration validation passed"
}

validate_docker_configuration() {
    log "Validating Docker configuration..."
    
    local dockerfile="${PROJECT_ROOT}/Dockerfile"
    local dockerfile_celery="${PROJECT_ROOT}/Dockerfile.celery"
    
    # Validate main Dockerfile
    if [[ ! -f "${dockerfile}" ]]; then
        error_exit "Main Dockerfile not found: ${dockerfile}"
    fi
    
    # Check for security best practices
    if ! grep -q "USER.*[^0]" "${dockerfile}"; then
        error_exit "Dockerfile should specify non-root user"
    fi
    
    if ! grep -q "HEALTHCHECK" "${dockerfile}"; then
        warning "Dockerfile should include health check"
    fi
    
    # Validate Celery Dockerfile
    if [[ ! -f "${dockerfile_celery}" ]]; then
        error_exit "Celery Dockerfile not found: ${dockerfile_celery}"
    fi
    
    verbose_log "Docker configuration validation passed"
}

run_security_checks() {
    log "Running security checks..."
    
    # Check for hardcoded secrets in configuration files
    local config_files=(
        "${DEPLOYMENT_DIR}/environments/${ENVIRONMENT}.env"
        "${DEPLOYMENT_DIR}/kubernetes/configmap.yaml"
    )
    
    for file in "${config_files[@]}"; do
        if [[ -f "${file}" ]]; then
            # Check for common secret patterns
            if grep -i "password\|secret\|key" "${file}" | grep -v "REPLACE_WITH" | grep -E "(=.{1,})" > /dev/null; then
                verbose_log "Found potential secrets in: $(basename "${file}")"
                
                # Check for weak passwords
                if grep -E "(password|secret|key).*=.*(123|admin|test|dev)" "${file}" > /dev/null; then
                    if [[ "${ENVIRONMENT}" == "production" ]]; then
                        error_exit "Weak credentials detected in production configuration"
                    else
                        warning "Weak credentials detected in $(basename "${file}")"
                    fi
                fi
            fi
        fi
    done
    
    verbose_log "Security checks completed"
}

generate_validation_report() {
    local report_file="/tmp/enterprise-auth-validation-report-${ENVIRONMENT}-$(date +%Y%m%d-%H%M%S).json"
    
    log "Generating validation report: ${report_file}"
    
    cat > "${report_file}" << EOF
{
  "validation_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": "${ENVIRONMENT}",
  "validation_status": "passed",
  "checks_performed": [
    "environment_file_validation",
    "kubernetes_manifests_validation",
    "secrets_configuration_validation",
    "docker_configuration_validation",
    "security_checks"
  ],
  "log_file": "${LOG_FILE}",
  "validated_by": "$(whoami)",
  "validation_version": "1.0.0"
}
EOF
    
    log "Validation report generated: ${report_file}"
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
            -v|--verbose)
                VERBOSE="true"
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
    
    log "Starting configuration validation for environment: ${ENVIRONMENT}"
    
    # Pre-flight checks
    check_dependencies
    
    # Run validation checks
    validate_environment_file
    validate_kubernetes_manifests
    validate_secrets_configuration
    validate_docker_configuration
    run_security_checks
    
    # Generate report
    generate_validation_report
    
    log "Configuration validation completed successfully"
}

# Error handling
trap 'log "Configuration validation failed"; exit 1' ERR

# Execute main function
main "$@"