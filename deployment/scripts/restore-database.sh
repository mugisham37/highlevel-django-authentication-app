#!/bin/bash

# Enterprise Auth Database Restore Script
# This script restores database backups with point-in-time recovery capabilities

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-/backups/database}"
ENCRYPTION_KEY_FILE="${ENCRYPTION_KEY_FILE:-/secrets/backup-encryption-key}"

# Database connection parameters
DB_HOST="${DB_HOST:-postgres}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-enterprise_auth}"
DB_USER="${DB_USER:-enterprise_auth_user}"
PGPASSWORD="${DB_PASSWORD}"

# S3 configuration
AWS_S3_BUCKET="${AWS_S3_BUCKET:-enterprise-auth-backups}"
AWS_S3_REGION="${AWS_S3_REGION:-us-east-1}"

# Logging
LOG_FILE="${BACKUP_DIR}/restore.log"
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
    -f, --file BACKUP_FILE      Restore from local backup file
    -s, --s3-key S3_KEY        Restore from S3 backup
    -l, --list                 List available backups
    -t, --target-time TIME     Point-in-time recovery target (YYYY-MM-DD HH:MM:SS)
    -d, --dry-run              Perform dry run without actual restore
    -h, --help                 Show this help message

Examples:
    $0 --file /backups/enterprise_auth_2024-01-15_10-30-00.sql.gz.enc
    $0 --s3-key database-backups/enterprise_auth_2024-01-15_10-30-00.sql.gz.enc
    $0 --list
    $0 --target-time "2024-01-15 10:30:00"
EOF
}

check_dependencies() {
    local deps=("pg_restore" "psql" "gunzip" "openssl" "aws")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error_exit "Required dependency '$dep' not found"
        fi
    done
}

list_backups() {
    log "Available local backups:"
    find "${BACKUP_DIR}" -name "enterprise_auth_*.sql*" -type f | sort -r | head -20
    
    if [[ -n "${AWS_S3_BUCKET}" ]]; then
        log "Available S3 backups:"
        aws s3 ls "s3://${AWS_S3_BUCKET}/database-backups/" --recursive | \
            grep "enterprise_auth_" | sort -r | head -20
    fi
}

download_from_s3() {
    local s3_key="$1"
    local local_file="${BACKUP_DIR}/$(basename "${s3_key}")"
    
    log "Downloading backup from S3: ${s3_key}"
    
    aws s3 cp "s3://${AWS_S3_BUCKET}/${s3_key}" "${local_file}" \
        --region "${AWS_S3_REGION}" \
        || error_exit "Failed to download backup from S3"
    
    # Download checksum file
    local checksum_key="${s3_key}.sha256"
    local checksum_file="${local_file}.sha256"
    
    aws s3 cp "s3://${AWS_S3_BUCKET}/${checksum_key}" "${checksum_file}" \
        --region "${AWS_S3_REGION}" \
        || log "WARNING: Checksum file not found"
    
    echo "${local_file}"
}

verify_backup() {
    local backup_file="$1"
    local checksum_file="${backup_file}.sha256"
    
    if [[ -f "${checksum_file}" ]]; then
        log "Verifying backup integrity..."
        if sha256sum -c "${checksum_file}"; then
            log "Backup verification successful"
        else
            error_exit "Backup verification failed"
        fi
    else
        log "WARNING: Checksum file not found, skipping verification"
    fi
}

decrypt_backup() {
    local encrypted_file="$1"
    local decrypted_file="${encrypted_file%.enc}"
    
    if [[ "${encrypted_file}" == *.enc ]]; then
        log "Decrypting backup..."
        
        if [[ ! -f "${ENCRYPTION_KEY_FILE}" ]]; then
            error_exit "Encryption key file not found: ${ENCRYPTION_KEY_FILE}"
        fi
        
        openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
            -in "${encrypted_file}" \
            -out "${decrypted_file}" \
            -pass file:"${ENCRYPTION_KEY_FILE}" \
            || error_exit "Backup decryption failed"
        
        echo "${decrypted_file}"
    else
        echo "${encrypted_file}"
    fi
}

decompress_backup() {
    local compressed_file="$1"
    local decompressed_file="${compressed_file%.gz}"
    
    if [[ "${compressed_file}" == *.gz ]]; then
        log "Decompressing backup..."
        gunzip -c "${compressed_file}" > "${decompressed_file}" \
            || error_exit "Backup decompression failed"
        
        echo "${decompressed_file}"
    else
        echo "${compressed_file}"
    fi
}

create_database_backup() {
    local backup_name="pre_restore_${TIMESTAMP}"
    log "Creating pre-restore backup: ${backup_name}"
    
    "${SCRIPT_DIR}/backup-database.sh" || log "WARNING: Pre-restore backup failed"
}

stop_application_services() {
    log "Stopping application services..."
    
    # Stop Kubernetes deployments
    if command -v kubectl &> /dev/null; then
        kubectl scale deployment enterprise-auth-web --replicas=0 -n enterprise-auth || true
        kubectl scale deployment enterprise-auth-celery-worker --replicas=0 -n enterprise-auth || true
        kubectl scale deployment enterprise-auth-celery-beat --replicas=0 -n enterprise-auth || true
        
        # Wait for pods to terminate
        kubectl wait --for=delete pod -l app.kubernetes.io/name=enterprise-auth -n enterprise-auth --timeout=300s || true
    fi
}

start_application_services() {
    log "Starting application services..."
    
    # Start Kubernetes deployments
    if command -v kubectl &> /dev/null; then
        kubectl scale deployment enterprise-auth-web --replicas=3 -n enterprise-auth || true
        kubectl scale deployment enterprise-auth-celery-worker --replicas=2 -n enterprise-auth || true
        kubectl scale deployment enterprise-auth-celery-beat --replicas=1 -n enterprise-auth || true
        
        # Wait for pods to be ready
        kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=enterprise-auth -n enterprise-auth --timeout=300s || true
    fi
}

restore_database() {
    local backup_file="$1"
    local dry_run="${2:-false}"
    
    log "Restoring database from: ${backup_file}"
    
    if [[ "${dry_run}" == "true" ]]; then
        log "DRY RUN: Would restore database from ${backup_file}"
        return 0
    fi
    
    # Create pre-restore backup
    create_database_backup
    
    # Stop application services
    stop_application_services
    
    # Terminate existing connections
    log "Terminating existing database connections..."
    psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres -c "
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();
    " || log "WARNING: Failed to terminate some connections"
    
    # Drop and recreate database
    log "Dropping and recreating database..."
    psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d postgres -c "
        DROP DATABASE IF EXISTS ${DB_NAME};
        CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};
    " || error_exit "Failed to recreate database"
    
    # Restore database
    log "Restoring database data..."
    pg_restore \
        --host="${DB_HOST}" \
        --port="${DB_PORT}" \
        --username="${DB_USER}" \
        --dbname="${DB_NAME}" \
        --verbose \
        --clean \
        --if-exists \
        --no-owner \
        --no-privileges \
        "${backup_file}" \
        || error_exit "Database restore failed"
    
    # Run post-restore tasks
    log "Running post-restore tasks..."
    psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -c "
        -- Update sequences
        SELECT setval(pg_get_serial_sequence(schemaname||'.'||tablename, columnname), 
                     COALESCE(max_value, 1), max_value IS NOT null) 
        FROM (
            SELECT schemaname, tablename, columnname, 
                   COALESCE(MAX(CAST(column_value AS bigint)), 0) AS max_value
            FROM (
                SELECT schemaname, tablename, columnname,
                       CASE WHEN column_value ~ '^[0-9]+$' THEN column_value ELSE '0' END AS column_value
                FROM (
                    SELECT n.nspname AS schemaname, c.relname AS tablename, a.attname AS columnname,
                           COALESCE(t.column_value, '0') AS column_value
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    JOIN pg_attribute a ON a.attrelid = c.oid
                    LEFT JOIN (
                        SELECT schemaname, tablename, columnname, 
                               COALESCE(MAX(column_value::text), '0') AS column_value
                        FROM information_schema.columns
                        WHERE column_default LIKE 'nextval%'
                        GROUP BY schemaname, tablename, columnname
                    ) t ON t.schemaname = n.nspname AND t.tablename = c.relname AND t.columnname = a.attname
                    WHERE c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
                      AND pg_get_serial_sequence(n.nspname||'.'||c.relname, a.attname) IS NOT NULL
                ) AS subq
            ) AS subq2
            GROUP BY schemaname, tablename, columnname
        ) AS subq3;
        
        -- Analyze tables
        ANALYZE;
    " || log "WARNING: Post-restore tasks failed"
    
    # Start application services
    start_application_services
    
    log "Database restore completed successfully"
}

point_in_time_recovery() {
    local target_time="$1"
    local dry_run="${2:-false}"
    
    log "Performing point-in-time recovery to: ${target_time}"
    
    if [[ "${dry_run}" == "true" ]]; then
        log "DRY RUN: Would perform point-in-time recovery to ${target_time}"
        return 0
    fi
    
    # Find the most recent backup before target time
    local backup_file
    backup_file=$(find "${BACKUP_DIR}" -name "enterprise_auth_*.sql*" -type f | \
        while read -r file; do
            local file_time
            file_time=$(basename "${file}" | sed 's/enterprise_auth_\([0-9-]*_[0-9-]*\).*/\1/' | tr '_' ' ')
            if [[ "${file_time}" < "${target_time}" ]]; then
                echo "${file_time} ${file}"
            fi
        done | sort -r | head -1 | cut -d' ' -f2-)
    
    if [[ -z "${backup_file}" ]]; then
        error_exit "No suitable backup found for point-in-time recovery"
    fi
    
    log "Using backup: ${backup_file}"
    
    # Restore the backup
    restore_database "${backup_file}" "${dry_run}"
    
    # Apply WAL files for point-in-time recovery
    log "Applying WAL files for point-in-time recovery..."
    # Note: This would require WAL archiving to be set up
    log "WARNING: WAL-based point-in-time recovery not implemented"
}

cleanup_temp_files() {
    log "Cleaning up temporary files..."
    find "${BACKUP_DIR}" -name "*.tmp" -type f -delete 2>/dev/null || true
}

send_notification() {
    local status="$1"
    local message="$2"
    
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        local notification_message
        if [[ "${status}" == "success" ]]; then
            notification_message="✅ Database restore completed successfully: ${message}"
        else
            notification_message="❌ Database restore failed: ${message}"
        fi
        
        curl -X POST "${WEBHOOK_URL}" \
            -H "Content-Type: application/json" \
            -d "{\"text\":\"${notification_message}\"}" \
            || log "WARNING: Failed to send notification"
    fi
}

# Main execution
main() {
    local backup_file=""
    local s3_key=""
    local target_time=""
    local dry_run="false"
    local list_only="false"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--file)
                backup_file="$2"
                shift 2
                ;;
            -s|--s3-key)
                s3_key="$2"
                shift 2
                ;;
            -l|--list)
                list_only="true"
                shift
                ;;
            -t|--target-time)
                target_time="$2"
                shift 2
                ;;
            -d|--dry-run)
                dry_run="true"
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
    mkdir -p "${BACKUP_DIR}"
    
    # List backups if requested
    if [[ "${list_only}" == "true" ]]; then
        list_backups
        exit 0
    fi
    
    # Point-in-time recovery
    if [[ -n "${target_time}" ]]; then
        point_in_time_recovery "${target_time}" "${dry_run}"
        send_notification "success" "Point-in-time recovery to ${target_time}"
        exit 0
    fi
    
    # Determine backup file
    if [[ -n "${s3_key}" ]]; then
        backup_file=$(download_from_s3 "${s3_key}")
    elif [[ -z "${backup_file}" ]]; then
        error_exit "No backup file specified. Use --file or --s3-key option."
    fi
    
    if [[ ! -f "${backup_file}" ]]; then
        error_exit "Backup file not found: ${backup_file}"
    fi
    
    # Verify backup
    verify_backup "${backup_file}"
    
    # Process backup file
    local processed_file="${backup_file}"
    processed_file=$(decrypt_backup "${processed_file}")
    processed_file=$(decompress_backup "${processed_file}")
    
    # Restore database
    restore_database "${processed_file}" "${dry_run}"
    
    # Cleanup
    cleanup_temp_files
    
    # Send success notification
    send_notification "success" "$(basename "${backup_file}")"
    
    log "Database restore process completed successfully"
}

# Error handling
trap 'cleanup_temp_files; send_notification "error" "Restore process failed"; exit 1' ERR

# Execute main function
main "$@"