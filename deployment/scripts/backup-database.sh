#!/bin/bash

# Enterprise Auth Database Backup Script
# This script creates automated database backups with point-in-time recovery capabilities

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-/backups/database}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
COMPRESSION_LEVEL="${COMPRESSION_LEVEL:-6}"
ENCRYPTION_KEY_FILE="${ENCRYPTION_KEY_FILE:-/secrets/backup-encryption-key}"

# Database connection parameters
DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-enterprise_auth}"
DB_USER="${DB_USER:-enterprise_auth_user}"
PGPASSWORD="${DB_PASSWORD}"

# S3 configuration for cross-region replication
AWS_S3_BUCKET="${AWS_S3_BUCKET:-enterprise-auth-backups}"
AWS_S3_REGION="${AWS_S3_REGION:-us-east-1}"
AWS_S3_STORAGE_CLASS="${AWS_S3_STORAGE_CLASS:-STANDARD_IA}"

# Logging
LOG_FILE="${BACKUP_DIR}/backup.log"
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
BACKUP_NAME="enterprise_auth_${TIMESTAMP}"

# Functions
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

check_dependencies() {
    local deps=("pg_dump" "gzip" "openssl" "aws")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error_exit "Required dependency '$dep' not found"
        fi
    done
}

create_backup_directory() {
    mkdir -p "${BACKUP_DIR}"
    chmod 700 "${BACKUP_DIR}"
}

perform_backup() {
    log "Starting database backup: ${BACKUP_NAME}"
    
    local backup_file="${BACKUP_DIR}/${BACKUP_NAME}.sql"
    local compressed_file="${backup_file}.gz"
    local encrypted_file="${compressed_file}.enc"
    
    # Create database dump
    log "Creating database dump..."
    pg_dump \
        --host="${DB_HOST}" \
        --port="${DB_PORT}" \
        --username="${DB_USER}" \
        --dbname="${DB_NAME}" \
        --verbose \
        --format=custom \
        --no-password \
        --file="${backup_file}" \
        || error_exit "Database dump failed"
    
    # Compress backup
    log "Compressing backup..."
    gzip -"${COMPRESSION_LEVEL}" "${backup_file}" \
        || error_exit "Backup compression failed"
    
    # Encrypt backup
    if [[ -f "${ENCRYPTION_KEY_FILE}" ]]; then
        log "Encrypting backup..."
        openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
            -in "${compressed_file}" \
            -out "${encrypted_file}" \
            -pass file:"${ENCRYPTION_KEY_FILE}" \
            || error_exit "Backup encryption failed"
        
        # Remove unencrypted file
        rm "${compressed_file}"
        backup_file="${encrypted_file}"
    else
        log "WARNING: Encryption key not found, backup not encrypted"
        backup_file="${compressed_file}"
    fi
    
    # Calculate checksum
    local checksum_file="${backup_file}.sha256"
    sha256sum "${backup_file}" > "${checksum_file}"
    
    log "Backup completed: ${backup_file}"
    log "Backup size: $(du -h "${backup_file}" | cut -f1)"
    
    echo "${backup_file}"
}

upload_to_s3() {
    local backup_file="$1"
    local checksum_file="${backup_file}.sha256"
    
    if [[ -n "${AWS_S3_BUCKET}" ]]; then
        log "Uploading backup to S3..."
        
        local s3_key="database-backups/$(basename "${backup_file}")"
        local s3_checksum_key="database-backups/$(basename "${checksum_file}")"
        
        # Upload backup file
        aws s3 cp "${backup_file}" "s3://${AWS_S3_BUCKET}/${s3_key}" \
            --region "${AWS_S3_REGION}" \
            --storage-class "${AWS_S3_STORAGE_CLASS}" \
            --server-side-encryption AES256 \
            || error_exit "S3 upload failed"
        
        # Upload checksum file
        aws s3 cp "${checksum_file}" "s3://${AWS_S3_BUCKET}/${s3_checksum_key}" \
            --region "${AWS_S3_REGION}" \
            --storage-class "${AWS_S3_STORAGE_CLASS}" \
            --server-side-encryption AES256 \
            || error_exit "S3 checksum upload failed"
        
        log "Backup uploaded to S3: s3://${AWS_S3_BUCKET}/${s3_key}"
    fi
}

cleanup_old_backups() {
    log "Cleaning up backups older than ${RETENTION_DAYS} days..."
    
    # Local cleanup
    find "${BACKUP_DIR}" -name "enterprise_auth_*.sql*" -type f -mtime +${RETENTION_DAYS} -delete
    find "${BACKUP_DIR}" -name "enterprise_auth_*.sha256" -type f -mtime +${RETENTION_DAYS} -delete
    
    # S3 cleanup (if configured)
    if [[ -n "${AWS_S3_BUCKET}" ]]; then
        local cutoff_date=$(date -d "${RETENTION_DAYS} days ago" '+%Y-%m-%d')
        aws s3api list-objects-v2 \
            --bucket "${AWS_S3_BUCKET}" \
            --prefix "database-backups/enterprise_auth_" \
            --query "Contents[?LastModified<='${cutoff_date}'].Key" \
            --output text | \
        while read -r key; do
            if [[ -n "${key}" ]]; then
                aws s3 rm "s3://${AWS_S3_BUCKET}/${key}"
                log "Deleted old S3 backup: ${key}"
            fi
        done
    fi
    
    log "Cleanup completed"
}

verify_backup() {
    local backup_file="$1"
    local checksum_file="${backup_file}.sha256"
    
    log "Verifying backup integrity..."
    
    if sha256sum -c "${checksum_file}"; then
        log "Backup verification successful"
        return 0
    else
        error_exit "Backup verification failed"
    fi
}

send_notification() {
    local status="$1"
    local backup_file="$2"
    
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        local message
        if [[ "${status}" == "success" ]]; then
            message="✅ Database backup completed successfully: $(basename "${backup_file}")"
        else
            message="❌ Database backup failed: ${status}"
        fi
        
        curl -X POST "${WEBHOOK_URL}" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"${message}\"}" \
            || log "WARNING: Failed to send notification"
    fi
}

# Main execution
main() {
    log "Starting database backup process..."
    
    # Pre-flight checks
    check_dependencies
    create_backup_directory
    
    # Perform backup
    local backup_file
    backup_file=$(perform_backup)
    
    # Verify backup
    verify_backup "${backup_file}"
    
    # Upload to S3
    upload_to_s3 "${backup_file}"
    
    # Cleanup old backups
    cleanup_old_backups
    
    # Send success notification
    send_notification "success" "${backup_file}"
    
    log "Database backup process completed successfully"
}

# Error handling
trap 'send_notification "error" ""; exit 1' ERR

# Execute main function
main "$@"