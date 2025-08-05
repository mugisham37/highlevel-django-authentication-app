#!/bin/bash

# Enterprise Auth Security Scanning Script
# Comprehensive security scanning for containers and configurations

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Default values
IMAGE_NAME="${IMAGE_NAME:-enterprise-auth}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
SCAN_TYPE="${SCAN_TYPE:-all}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-json}"
SEVERITY_THRESHOLD="${SEVERITY_THRESHOLD:-HIGH}"

# Logging
LOG_FILE="/tmp/enterprise-auth-security-scan-$(date +%Y%m%d-%H%M%S).log"
REPORT_DIR="/tmp/security-reports-$(date +%Y%m%d-%H%M%S)"

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
    -i, --image IMAGE          Docker image name [default: enterprise-auth]
    -t, --tag TAG             Docker image tag [default: latest]
    -s, --scan-type TYPE      Scan type (container|code|config|all) [default: all]
    -f, --format FORMAT       Output format (json|table|sarif) [default: json]
    -T, --threshold LEVEL     Severity threshold (LOW|MEDIUM|HIGH|CRITICAL) [default: HIGH]
    -o, --output-dir DIR      Output directory for reports [default: /tmp/security-reports-*]
    -h, --help                Show this help message

Examples:
    $0 --image enterprise-auth --tag v1.2.3 --scan-type container
    $0 --scan-type code --format table
    $0 --threshold CRITICAL --output-dir ./security-reports
EOF
}

check_dependencies() {
    local deps=("docker" "trivy" "bandit" "safety" "semgrep")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log "Installing missing dependencies: ${missing_deps[*]}"
        install_dependencies "${missing_deps[@]}"
    fi
}

install_dependencies() {
    local deps=("$@")
    
    for dep in "${deps[@]}"; do
        case "$dep" in
            trivy)
                log "Installing Trivy..."
                curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
                ;;
            bandit)
                log "Installing Bandit..."
                pip install bandit[toml]
                ;;
            safety)
                log "Installing Safety..."
                pip install safety
                ;;
            semgrep)
                log "Installing Semgrep..."
                pip install semgrep
                ;;
            *)
                log "Please install $dep manually"
                ;;
        esac
    done
}

setup_report_directory() {
    mkdir -p "${REPORT_DIR}"
    chmod 700 "${REPORT_DIR}"
    log "Security reports will be saved to: ${REPORT_DIR}"
}

scan_container_vulnerabilities() {
    log "Scanning container vulnerabilities with Trivy..."
    
    local image="${IMAGE_NAME}:${IMAGE_TAG}"
    local report_file="${REPORT_DIR}/trivy-vulnerabilities.${OUTPUT_FORMAT}"
    
    # Scan for vulnerabilities
    trivy image \
        --format "${OUTPUT_FORMAT}" \
        --output "${report_file}" \
        --severity "${SEVERITY_THRESHOLD},CRITICAL" \
        --no-progress \
        "${image}" || error_exit "Trivy vulnerability scan failed"
    
    # Generate summary
    local vuln_count
    if [[ "${OUTPUT_FORMAT}" == "json" ]]; then
        vuln_count=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "${report_file}" 2>/dev/null || echo "0")
    else
        vuln_count=$(grep -c "Total:" "${report_file}" 2>/dev/null || echo "0")
    fi
    
    log "Container vulnerability scan completed. Found ${vuln_count} vulnerabilities."
    
    # Fail if critical vulnerabilities found
    if [[ "${SEVERITY_THRESHOLD}" == "CRITICAL" && "${vuln_count}" -gt 0 ]]; then
        error_exit "Critical vulnerabilities found in container image"
    fi
    
    echo "${report_file}"
}

scan_container_misconfigurations() {
    log "Scanning container misconfigurations with Trivy..."
    
    local image="${IMAGE_NAME}:${IMAGE_TAG}"
    local report_file="${REPORT_DIR}/trivy-misconfig.${OUTPUT_FORMAT}"
    
    # Scan for misconfigurations
    trivy image \
        --format "${OUTPUT_FORMAT}" \
        --output "${report_file}" \
        --scanners misconfig \
        --severity "${SEVERITY_THRESHOLD},CRITICAL" \
        --no-progress \
        "${image}" || error_exit "Trivy misconfiguration scan failed"
    
    log "Container misconfiguration scan completed."
    echo "${report_file}"
}

scan_container_secrets() {
    log "Scanning container for secrets with Trivy..."
    
    local image="${IMAGE_NAME}:${IMAGE_TAG}"
    local report_file="${REPORT_DIR}/trivy-secrets.${OUTPUT_FORMAT}"
    
    # Scan for secrets
    trivy image \
        --format "${OUTPUT_FORMAT}" \
        --output "${report_file}" \
        --scanners secret \
        --no-progress \
        "${image}" || error_exit "Trivy secret scan failed"
    
    # Check for secrets
    local secret_count
    if [[ "${OUTPUT_FORMAT}" == "json" ]]; then
        secret_count=$(jq '[.Results[]?.Secrets[]?] | length' "${report_file}" 2>/dev/null || echo "0")
    else
        secret_count=$(grep -c "SECRET" "${report_file}" 2>/dev/null || echo "0")
    fi
    
    log "Container secret scan completed. Found ${secret_count} potential secrets."
    
    if [[ "${secret_count}" -gt 0 ]]; then
        error_exit "Secrets found in container image"
    fi
    
    echo "${report_file}"
}

scan_code_security() {
    log "Scanning code security with Bandit..."
    
    local report_file="${REPORT_DIR}/bandit-security.${OUTPUT_FORMAT}"
    
    # Run Bandit security scan
    bandit -r "${PROJECT_ROOT}/enterprise_auth/" \
        -f "${OUTPUT_FORMAT}" \
        -o "${report_file}" \
        -ll \
        --exclude "${PROJECT_ROOT}/enterprise_auth/*/migrations/*" \
        || log "Bandit scan completed with issues"
    
    # Generate summary
    local issue_count
    if [[ "${OUTPUT_FORMAT}" == "json" ]]; then
        issue_count=$(jq '.results | length' "${report_file}" 2>/dev/null || echo "0")
    else
        issue_count=$(grep -c "Issue:" "${report_file}" 2>/dev/null || echo "0")
    fi
    
    log "Code security scan completed. Found ${issue_count} security issues."
    echo "${report_file}"
}

scan_dependency_vulnerabilities() {
    log "Scanning dependency vulnerabilities with Safety..."
    
    local report_file="${REPORT_DIR}/safety-vulnerabilities.json"
    
    # Run Safety scan
    safety check \
        --json \
        --output "${report_file}" \
        --file "${PROJECT_ROOT}/requirements.txt" \
        || log "Safety scan completed with vulnerabilities"
    
    # Generate summary
    local vuln_count
    vuln_count=$(jq '.vulnerabilities | length' "${report_file}" 2>/dev/null || echo "0")
    
    log "Dependency vulnerability scan completed. Found ${vuln_count} vulnerabilities."
    
    # Fail if vulnerabilities found and threshold is high
    if [[ "${SEVERITY_THRESHOLD}" == "CRITICAL" && "${vuln_count}" -gt 0 ]]; then
        error_exit "Dependency vulnerabilities found"
    fi
    
    echo "${report_file}"
}

scan_code_patterns() {
    log "Scanning code patterns with Semgrep..."
    
    local report_file="${REPORT_DIR}/semgrep-patterns.${OUTPUT_FORMAT}"
    
    # Run Semgrep scan
    semgrep \
        --config=auto \
        --"${OUTPUT_FORMAT}" \
        --output="${report_file}" \
        --severity=ERROR \
        --severity=WARNING \
        "${PROJECT_ROOT}/enterprise_auth/" \
        || log "Semgrep scan completed with findings"
    
    # Generate summary
    local finding_count
    if [[ "${OUTPUT_FORMAT}" == "json" ]]; then
        finding_count=$(jq '.results | length' "${report_file}" 2>/dev/null || echo "0")
    else
        finding_count=$(grep -c "rule:" "${report_file}" 2>/dev/null || echo "0")
    fi
    
    log "Code pattern scan completed. Found ${finding_count} findings."
    echo "${report_file}"
}

scan_kubernetes_configurations() {
    log "Scanning Kubernetes configurations with Trivy..."
    
    local report_file="${REPORT_DIR}/trivy-k8s-config.${OUTPUT_FORMAT}"
    local k8s_dir="${PROJECT_ROOT}/deployment/kubernetes"
    
    if [[ ! -d "${k8s_dir}" ]]; then
        log "Kubernetes configuration directory not found, skipping scan"
        return 0
    fi
    
    # Scan Kubernetes configurations
    trivy config \
        --format "${OUTPUT_FORMAT}" \
        --output "${report_file}" \
        --severity "${SEVERITY_THRESHOLD},CRITICAL" \
        --no-progress \
        "${k8s_dir}" || error_exit "Kubernetes configuration scan failed"
    
    log "Kubernetes configuration scan completed."
    echo "${report_file}"
}

scan_docker_configurations() {
    log "Scanning Docker configurations with Trivy..."
    
    local report_file="${REPORT_DIR}/trivy-docker-config.${OUTPUT_FORMAT}"
    
    # Scan Dockerfile
    trivy config \
        --format "${OUTPUT_FORMAT}" \
        --output "${report_file}" \
        --severity "${SEVERITY_THRESHOLD},CRITICAL" \
        --no-progress \
        "${PROJECT_ROOT}/Dockerfile" \
        "${PROJECT_ROOT}/Dockerfile.celery" \
        || error_exit "Docker configuration scan failed"
    
    log "Docker configuration scan completed."
    echo "${report_file}"
}

generate_consolidated_report() {
    log "Generating consolidated security report..."
    
    local consolidated_report="${REPORT_DIR}/consolidated-security-report.json"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    # Create consolidated report structure
    cat > "${consolidated_report}" << EOF
{
  "scan_timestamp": "${timestamp}",
  "image": "${IMAGE_NAME}:${IMAGE_TAG}",
  "scan_type": "${SCAN_TYPE}",
  "severity_threshold": "${SEVERITY_THRESHOLD}",
  "scans_performed": [],
  "summary": {
    "total_vulnerabilities": 0,
    "total_misconfigurations": 0,
    "total_secrets": 0,
    "total_code_issues": 0,
    "scan_status": "completed"
  },
  "reports": {}
}
EOF
    
    # Add individual scan results
    for report in "${REPORT_DIR}"/*.json; do
        if [[ -f "${report}" && "${report}" != "${consolidated_report}" ]]; then
            local scan_name
            scan_name=$(basename "${report}" .json)
            
            # Add scan to performed list
            jq --arg scan "${scan_name}" '.scans_performed += [$scan]' "${consolidated_report}" > "${consolidated_report}.tmp"
            mv "${consolidated_report}.tmp" "${consolidated_report}"
            
            # Add report content
            jq --arg scan "${scan_name}" --slurpfile content "${report}" '.reports[$scan] = $content[0]' "${consolidated_report}" > "${consolidated_report}.tmp"
            mv "${consolidated_report}.tmp" "${consolidated_report}"
        fi
    done
    
    log "Consolidated security report generated: ${consolidated_report}"
    echo "${consolidated_report}"
}

upload_reports_to_s3() {
    if [[ -n "${AWS_S3_BUCKET:-}" ]]; then
        log "Uploading security reports to S3..."
        
        local s3_prefix="security-reports/$(date +%Y/%m/%d)/${IMAGE_NAME}-${IMAGE_TAG}"
        
        aws s3 sync "${REPORT_DIR}" "s3://${AWS_S3_BUCKET}/${s3_prefix}/" \
            --exclude "*" \
            --include "*.json" \
            --include "*.sarif" \
            --include "*.html" \
            || log "WARNING: Failed to upload reports to S3"
        
        log "Reports uploaded to: s3://${AWS_S3_BUCKET}/${s3_prefix}/"
    fi
}

send_notification() {
    local status="$1"
    local summary="$2"
    
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        local message
        if [[ "${status}" == "success" ]]; then
            message="✅ Security scan completed for ${IMAGE_NAME}:${IMAGE_TAG} - ${summary}"
        else
            message="❌ Security scan failed for ${IMAGE_NAME}:${IMAGE_TAG} - ${summary}"
        fi
        
        curl -X POST "${WEBHOOK_URL}" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"${message}\"}" \
            || log "WARNING: Failed to send notification"
    fi
}

cleanup() {
    log "Cleaning up temporary files..."
    # Keep reports but clean up any temporary files
    find /tmp -name "trivy-*" -type f -mtime +1 -delete 2>/dev/null || true
}

# Main execution
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--image)
                IMAGE_NAME="$2"
                shift 2
                ;;
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -s|--scan-type)
                SCAN_TYPE="$2"
                shift 2
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -T|--threshold)
                SEVERITY_THRESHOLD="$2"
                shift 2
                ;;
            -o|--output-dir)
                REPORT_DIR="$2"
                shift 2
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
    
    log "Starting security scan..."
    log "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
    log "Scan Type: ${SCAN_TYPE}"
    log "Severity Threshold: ${SEVERITY_THRESHOLD}"
    
    # Pre-flight checks
    check_dependencies
    setup_report_directory
    
    # Run scans based on type
    local reports=()
    
    case "${SCAN_TYPE}" in
        container)
            reports+=($(scan_container_vulnerabilities))
            reports+=($(scan_container_misconfigurations))
            reports+=($(scan_container_secrets))
            ;;
        code)
            reports+=($(scan_code_security))
            reports+=($(scan_dependency_vulnerabilities))
            reports+=($(scan_code_patterns))
            ;;
        config)
            reports+=($(scan_kubernetes_configurations))
            reports+=($(scan_docker_configurations))
            ;;
        all)
            reports+=($(scan_container_vulnerabilities))
            reports+=($(scan_container_misconfigurations))
            reports+=($(scan_container_secrets))
            reports+=($(scan_code_security))
            reports+=($(scan_dependency_vulnerabilities))
            reports+=($(scan_code_patterns))
            reports+=($(scan_kubernetes_configurations))
            reports+=($(scan_docker_configurations))
            ;;
        *)
            error_exit "Invalid scan type: ${SCAN_TYPE}. Must be one of: container, code, config, all"
            ;;
    esac
    
    # Generate consolidated report
    local consolidated_report
    consolidated_report=$(generate_consolidated_report)
    
    # Upload reports
    upload_reports_to_s3
    
    # Send notification
    send_notification "success" "Scan completed successfully"
    
    # Cleanup
    cleanup
    
    log "Security scan completed successfully"
    log "Reports available in: ${REPORT_DIR}"
    log "Consolidated report: ${consolidated_report}"
}

# Error handling
trap 'cleanup; send_notification "error" "Security scan failed"; exit 1' ERR

# Execute main function
main "$@"