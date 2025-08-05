"""
Audit log integrity verification service for SOC2 compliance.
Provides cryptographic verification of audit trail integrity.
"""

import hashlib
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError

from ..models.compliance import ComplianceAuditLog
from .compliance_service import SOC2AuditService

logger = logging.getLogger(__name__)


class AuditIntegrityService:
    """
    Service for maintaining and verifying audit log integrity.
    Implements cryptographic chaining and integrity verification for SOC2 compliance.
    """
    
    def __init__(self):
        self.audit_service = SOC2AuditService()
    
    def verify_audit_chain_integrity(self, start_date: datetime = None, 
                                   end_date: datetime = None) -> Dict[str, Any]:
        """
        Verify the integrity of the audit log chain using cryptographic checksums.
        
        Args:
            start_date: Start date for verification (optional)
            end_date: End date for verification (optional)
            
        Returns:
            Dictionary containing verification results
        """
        try:
            query = ComplianceAuditLog.objects.order_by('timestamp')
            
            if start_date:
                query = query.filter(timestamp__gte=start_date)
            if end_date:
                query = query.filter(timestamp__lte=end_date)
            
            audit_logs = list(query.all())
            
            verification_results = {
                'verification_timestamp': timezone.now().isoformat(),
                'period_start': start_date.isoformat() if start_date else None,
                'period_end': end_date.isoformat() if end_date else None,
                'total_logs_verified': len(audit_logs),
                'integrity_status': 'valid',
                'chain_breaks': [],
                'checksum_mismatches': [],
                'missing_checksums': 0,
                'verification_details': {
                    'first_log_timestamp': None,
                    'last_log_timestamp': None,
                    'chain_length': len(audit_logs)
                }
            }
            
            if not audit_logs:
                verification_results['integrity_status'] = 'no_logs'
                return verification_results
            
            verification_results['verification_details']['first_log_timestamp'] = audit_logs[0].timestamp.isoformat()
            verification_results['verification_details']['last_log_timestamp'] = audit_logs[-1].timestamp.isoformat()
            
            previous_checksum = ''
            
            for i, log in enumerate(audit_logs):
                # Check if checksum exists
                if not log.checksum:
                    verification_results['missing_checksums'] += 1
                    continue
                
                # Verify checksum integrity
                expected_checksum = self._calculate_log_checksum(log)
                if log.checksum != expected_checksum:
                    verification_results['checksum_mismatches'].append({
                        'audit_id': str(log.audit_id),
                        'timestamp': log.timestamp.isoformat(),
                        'expected_checksum': expected_checksum,
                        'actual_checksum': log.checksum,
                        'position_in_chain': i
                    })
                
                # Verify chain integrity
                if log.previous_log_checksum != previous_checksum:
                    verification_results['chain_breaks'].append({
                        'audit_id': str(log.audit_id),
                        'timestamp': log.timestamp.isoformat(),
                        'expected_previous_checksum': previous_checksum,
                        'actual_previous_checksum': log.previous_log_checksum,
                        'position_in_chain': i
                    })
                
                previous_checksum = log.checksum
            
            # Determine overall integrity status
            if (verification_results['checksum_mismatches'] or 
                verification_results['chain_breaks'] or 
                verification_results['missing_checksums'] > 0):
                verification_results['integrity_status'] = 'compromised'
            
            logger.info(
                f"Audit chain integrity verification completed",
                total_logs=len(audit_logs),
                integrity_status=verification_results['integrity_status'],
                chain_breaks=len(verification_results['chain_breaks']),
                checksum_mismatches=len(verification_results['checksum_mismatches'])
            )
            
            return verification_results
            
        except Exception as e:
            logger.error(f"Failed to verify audit chain integrity: {str(e)}")
            raise
    
    def _calculate_log_checksum(self, audit_log: ComplianceAuditLog) -> str:
        """
        Calculate SHA-256 checksum for an audit log entry.
        
        Args:
            audit_log: Audit log entry to calculate checksum for
            
        Returns:
            SHA-256 checksum as hexadecimal string
        """
        # Create deterministic data structure for checksum calculation
        checksum_data = {
            'audit_id': str(audit_log.audit_id),
            'timestamp': audit_log.timestamp.isoformat(),
            'activity_type': audit_log.activity_type,
            'severity': audit_log.severity,
            'user_id': str(audit_log.user.id) if audit_log.user else '',
            'session_id': audit_log.session_id or '',
            'ip_address': str(audit_log.ip_address) if audit_log.ip_address else '',
            'action': audit_log.action or '',
            'resource': audit_log.resource or '',
            'outcome': audit_log.outcome or '',
            'details': audit_log.details,
            'before_state': audit_log.before_state,
            'after_state': audit_log.after_state,
            'previous_log_checksum': audit_log.previous_log_checksum or ''
        }
        
        # Convert to JSON string with sorted keys for consistency
        data_string = json.dumps(checksum_data, sort_keys=True, default=str)
        
        # Calculate SHA-256 hash
        return hashlib.sha256(data_string.encode('utf-8')).hexdigest()
    
    def repair_audit_chain(self, start_date: datetime = None, 
                          end_date: datetime = None, 
                          dry_run: bool = True) -> Dict[str, Any]:
        """
        Repair audit log chain by recalculating checksums and chain links.
        
        Args:
            start_date: Start date for repair (optional)
            end_date: End date for repair (optional)
            dry_run: If True, only simulate repair without making changes
            
        Returns:
            Dictionary containing repair results
        """
        try:
            query = ComplianceAuditLog.objects.order_by('timestamp')
            
            if start_date:
                query = query.filter(timestamp__gte=start_date)
            if end_date:
                query = query.filter(timestamp__lte=end_date)
            
            audit_logs = list(query.all())
            
            repair_results = {
                'repair_timestamp': timezone.now().isoformat(),
                'dry_run': dry_run,
                'total_logs_processed': len(audit_logs),
                'checksums_updated': 0,
                'chain_links_updated': 0,
                'errors': []
            }
            
            if not audit_logs:
                return repair_results
            
            previous_checksum = ''
            
            with transaction.atomic():
                for i, log in enumerate(audit_logs):
                    try:
                        # Calculate correct checksum
                        expected_checksum = self._calculate_log_checksum(log)
                        checksum_needs_update = log.checksum != expected_checksum
                        
                        # Check chain link
                        chain_needs_update = log.previous_log_checksum != previous_checksum
                        
                        if checksum_needs_update or chain_needs_update:
                            if not dry_run:
                                if chain_needs_update:
                                    log.previous_log_checksum = previous_checksum
                                    repair_results['chain_links_updated'] += 1
                                
                                if checksum_needs_update:
                                    log.checksum = expected_checksum
                                    repair_results['checksums_updated'] += 1
                                
                                log.save(update_fields=['checksum', 'previous_log_checksum'])
                            else:
                                # Dry run - just count what would be updated
                                if chain_needs_update:
                                    repair_results['chain_links_updated'] += 1
                                if checksum_needs_update:
                                    repair_results['checksums_updated'] += 1
                        
                        previous_checksum = expected_checksum
                        
                    except Exception as e:
                        error_info = {
                            'audit_id': str(log.audit_id),
                            'timestamp': log.timestamp.isoformat(),
                            'error': str(e)
                        }
                        repair_results['errors'].append(error_info)
                        logger.error(f"Failed to repair audit log {log.audit_id}: {str(e)}")
            
            action = "simulated" if dry_run else "completed"
            logger.info(
                f"Audit chain repair {action}",
                total_logs=len(audit_logs),
                checksums_updated=repair_results['checksums_updated'],
                chain_links_updated=repair_results['chain_links_updated'],
                errors=len(repair_results['errors'])
            )
            
            return repair_results
            
        except Exception as e:
            logger.error(f"Failed to repair audit chain: {str(e)}")
            raise
    
    def create_integrity_report(self, period_days: int = 30) -> Dict[str, Any]:
        """
        Create comprehensive audit integrity report.
        
        Args:
            period_days: Number of days to include in the report
            
        Returns:
            Dictionary containing integrity report
        """
        try:
            end_date = timezone.now()
            start_date = end_date - timedelta(days=period_days)
            
            # Run integrity verification
            verification_results = self.verify_audit_chain_integrity(start_date, end_date)
            
            # Get audit log statistics
            total_logs = ComplianceAuditLog.objects.filter(
                timestamp__gte=start_date,
                timestamp__lte=end_date
            ).count()
            
            logs_by_severity = {}
            for severity in ['low', 'medium', 'high', 'critical']:
                count = ComplianceAuditLog.objects.filter(
                    timestamp__gte=start_date,
                    timestamp__lte=end_date,
                    severity=severity
                ).count()
                logs_by_severity[severity] = count
            
            logs_by_activity = {}
            activity_types = ComplianceAuditLog.objects.filter(
                timestamp__gte=start_date,
                timestamp__lte=end_date
            ).values_list('activity_type', flat=True).distinct()
            
            for activity_type in activity_types:
                count = ComplianceAuditLog.objects.filter(
                    timestamp__gte=start_date,
                    timestamp__lte=end_date,
                    activity_type=activity_type
                ).count()
                logs_by_activity[activity_type] = count
            
            # Calculate integrity score
            integrity_score = self._calculate_integrity_score(verification_results)
            
            report = {
                'report_metadata': {
                    'report_type': 'audit_integrity_report',
                    'generated_at': timezone.now().isoformat(),
                    'period_start': start_date.isoformat(),
                    'period_end': end_date.isoformat(),
                    'period_days': period_days
                },
                'integrity_verification': verification_results,
                'audit_statistics': {
                    'total_audit_logs': total_logs,
                    'logs_by_severity': logs_by_severity,
                    'logs_by_activity_type': logs_by_activity,
                    'average_logs_per_day': round(total_logs / max(period_days, 1), 2)
                },
                'integrity_score': integrity_score,
                'compliance_status': {
                    'soc2_compliant': integrity_score >= 95,
                    'integrity_level': self._get_integrity_level(integrity_score),
                    'recommendations': self._get_integrity_recommendations(verification_results)
                }
            }
            
            logger.info(
                f"Audit integrity report generated",
                period_days=period_days,
                total_logs=total_logs,
                integrity_score=integrity_score
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to create integrity report: {str(e)}")
            raise
    
    def _calculate_integrity_score(self, verification_results: Dict[str, Any]) -> float:
        """
        Calculate integrity score based on verification results.
        
        Args:
            verification_results: Results from integrity verification
            
        Returns:
            Integrity score as percentage (0-100)
        """
        if verification_results['total_logs_verified'] == 0:
            return 100.0  # No logs to verify
        
        total_issues = (
            len(verification_results['checksum_mismatches']) +
            len(verification_results['chain_breaks']) +
            verification_results['missing_checksums']
        )
        
        if total_issues == 0:
            return 100.0
        
        # Calculate score based on issue severity
        issue_weight = total_issues / verification_results['total_logs_verified']
        integrity_score = max(0, 100 - (issue_weight * 100))
        
        return round(integrity_score, 2)
    
    def _get_integrity_level(self, integrity_score: float) -> str:
        """
        Get integrity level description based on score.
        
        Args:
            integrity_score: Integrity score (0-100)
            
        Returns:
            Integrity level description
        """
        if integrity_score >= 99:
            return 'excellent'
        elif integrity_score >= 95:
            return 'good'
        elif integrity_score >= 85:
            return 'acceptable'
        elif integrity_score >= 70:
            return 'poor'
        else:
            return 'critical'
    
    def _get_integrity_recommendations(self, verification_results: Dict[str, Any]) -> List[str]:
        """
        Get recommendations based on verification results.
        
        Args:
            verification_results: Results from integrity verification
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if verification_results['missing_checksums'] > 0:
            recommendations.append(
                f"Repair {verification_results['missing_checksums']} audit logs with missing checksums"
            )
        
        if verification_results['checksum_mismatches']:
            recommendations.append(
                f"Investigate {len(verification_results['checksum_mismatches'])} checksum mismatches - possible data corruption"
            )
        
        if verification_results['chain_breaks']:
            recommendations.append(
                f"Repair {len(verification_results['chain_breaks'])} chain breaks to restore audit trail continuity"
            )
        
        if verification_results['integrity_status'] == 'compromised':
            recommendations.append(
                "Conduct security investigation to determine cause of audit trail compromise"
            )
        
        if not recommendations:
            recommendations.append("Audit trail integrity is maintained - continue regular monitoring")
        
        return recommendations
    
    def schedule_integrity_verification(self, interval_hours: int = 24) -> None:
        """
        Schedule regular integrity verification (would be implemented with Celery in production).
        
        Args:
            interval_hours: Interval between verifications in hours
        """
        # This would be implemented with Celery periodic tasks in production
        logger.info(f"Integrity verification scheduled every {interval_hours} hours")
        
        # For now, just log the scheduling
        # In production, you would use:
        # from celery import current_app
        # current_app.conf.beat_schedule['audit_integrity_check'] = {
        #     'task': 'enterprise_auth.core.tasks.verify_audit_integrity',
        #     'schedule': interval_hours * 3600.0,
        # }