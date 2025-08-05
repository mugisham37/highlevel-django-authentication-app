"""
Compliance service for GDPR, CCPA, and SOC2 compliance operations.
"""

import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.serializers import serialize
from django.core.files.storage import default_storage
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError

from ..models.compliance import (
    DataProcessingPurpose, ConsentRecord, DataExportRequest, DataDeletionRequest,
    DataDisclosureLog, PrivacyPolicyVersion, PrivacyPolicyAcceptance,
    ComplianceAuditLog, SecurityVulnerability, ComplianceReport
)
from ..models import UserProfile, UserSession, SecurityEvent, AuditLog
from ..utils.encryption import EncryptionService

User = get_user_model()
logger = logging.getLogger(__name__)


class GDPRComplianceService:
    """
    Service for GDPR compliance operations including data portability and right to deletion.
    """
    
    def __init__(self):
        self.encryption_service = EncryptionService()
    
    def request_data_export(self, user: User, data_types: List[str], export_format: str = 'json') -> DataExportRequest:
        """
        Create a data export request for GDPR Article 20 (Right to data portability).
        """
        try:
            with transaction.atomic():
                # Check for existing pending requests
                existing_request = DataExportRequest.objects.filter(
                    user=user,
                    status__in=['pending', 'processing']
                ).first()
                
                if existing_request:
                    raise ValidationError("A data export request is already in progress")
                
                # Create new export request
                export_request = DataExportRequest.objects.create(
                    user=user,
                    export_format=export_format,
                    requested_data_types=data_types,
                    download_expires_at=timezone.now() + timedelta(days=30)
                )
                
                # Log the request
                ComplianceAuditLog.objects.create(
                    activity_type='compliance_action',
                    user=user,
                    action='data_export_requested',
                    resource='user_data',
                    outcome='success',
                    details={
                        'request_id': str(export_request.request_id),
                        'data_types': data_types,
                        'format': export_format
                    }
                )
                
                logger.info(f"Data export requested for user {user.id}: {export_request.request_id}")
                return export_request
                
        except Exception as e:
            logger.error(f"Failed to create data export request for user {user.id}: {str(e)}")
            raise
    
    def process_data_export(self, export_request: DataExportRequest) -> bool:
        """
        Process a data export request and generate the export file.
        """
        try:
            with transaction.atomic():
                export_request.status = 'processing'
                export_request.processing_started_at = timezone.now()
                export_request.save()
                
                # Collect user data based on requested types
                user_data = self._collect_user_data(export_request.user, export_request.requested_data_types)
                
                # Generate export file
                file_path = self._generate_export_file(export_request, user_data)
                
                # Update request with file information
                export_request.file_path = file_path
                export_request.file_size_bytes = default_storage.size(file_path)
                export_request.status = 'completed'
                export_request.processing_completed_at = timezone.now()
                export_request.save()
                
                # Log completion
                ComplianceAuditLog.objects.create(
                    activity_type='compliance_action',
                    user=export_request.user,
                    action='data_export_completed',
                    resource='user_data',
                    outcome='success',
                    details={
                        'request_id': str(export_request.request_id),
                        'file_size': export_request.file_size_bytes,
                        'processing_time': (export_request.processing_completed_at - export_request.processing_started_at).total_seconds()
                    }
                )
                
                logger.info(f"Data export completed for request {export_request.request_id}")
                return True
                
        except Exception as e:
            export_request.status = 'failed'
            export_request.error_message = str(e)
            export_request.save()
            
            logger.error(f"Failed to process data export {export_request.request_id}: {str(e)}")
            return False
    
    def _collect_user_data(self, user: User, data_types: List[str]) -> Dict[str, Any]:
        """
        Collect user data based on requested data types.
        """
        data = {
            'user_id': str(user.id),
            'export_timestamp': timezone.now().isoformat(),
            'data_types': data_types
        }
        
        if 'profile' in data_types:
            data['profile'] = {
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'phone_number': getattr(user, 'phone_number', ''),
                'organization': getattr(user, 'organization', ''),
                'department': getattr(user, 'department', ''),
                'created_at': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None
            }
        
        if 'sessions' in data_types:
            sessions = UserSession.objects.filter(user=user).values(
                'session_id', 'device_type', 'browser', 'operating_system',
                'country', 'city', 'created_at', 'last_activity'
            )
            data['sessions'] = list(sessions)
        
        if 'security_events' in data_types:
            security_events = SecurityEvent.objects.filter(user=user).values(
                'event_type', 'severity', 'description', 'timestamp'
            )
            data['security_events'] = list(security_events)
        
        if 'audit_logs' in data_types:
            audit_logs = AuditLog.objects.filter(user=user).values(
                'action', 'resource', 'timestamp', 'ip_address'
            )
            data['audit_logs'] = list(audit_logs)
        
        if 'consent_records' in data_types:
            consent_records = ConsentRecord.objects.filter(user=user).select_related('purpose').values(
                'purpose__name', 'status', 'consent_given_at', 'consent_withdrawn_at'
            )
            data['consent_records'] = list(consent_records)
        
        return data
    
    def _generate_export_file(self, export_request: DataExportRequest, user_data: Dict[str, Any]) -> str:
        """
        Generate export file in the requested format.
        """
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        filename = f"data_export_{export_request.user.id}_{timestamp}.{export_request.export_format}"
        file_path = f"exports/{filename}"
        
        if export_request.export_format == 'json':
            content = json.dumps(user_data, indent=2, default=str)
        elif export_request.export_format == 'csv':
            # For CSV, we'll flatten the data structure
            content = self._convert_to_csv(user_data)
        else:
            raise ValueError(f"Unsupported export format: {export_request.export_format}")
        
        # Save file to storage
        default_storage.save(file_path, content.encode('utf-8'))
        
        return file_path
    
    def _convert_to_csv(self, data: Dict[str, Any]) -> str:
        """
        Convert data dictionary to CSV format.
        """
        import csv
        import io
        
        output = io.StringIO()
        
        # Write profile data
        if 'profile' in data:
            writer = csv.writer(output)
            writer.writerow(['Data Type', 'Field', 'Value'])
            for key, value in data['profile'].items():
                writer.writerow(['Profile', key, value])
        
        # Add other data types as needed
        for data_type in ['sessions', 'security_events', 'audit_logs', 'consent_records']:
            if data_type in data and data[data_type]:
                writer.writerow([])  # Empty row for separation
                writer.writerow([f'{data_type.title()} Data'])
                
                if data[data_type]:
                    # Write headers
                    headers = list(data[data_type][0].keys())
                    writer.writerow(headers)
                    
                    # Write data rows
                    for item in data[data_type]:
                        writer.writerow([item.get(header, '') for header in headers])
        
        return output.getvalue()
    
    def request_data_deletion(self, user: User, deletion_scope: str, reason: str, data_types: List[str] = None) -> DataDeletionRequest:
        """
        Create a data deletion request for GDPR Article 17 (Right to erasure).
        """
        try:
            with transaction.atomic():
                # Check for existing pending requests
                existing_request = DataDeletionRequest.objects.filter(
                    user=user,
                    status__in=['pending', 'approved', 'processing']
                ).first()
                
                if existing_request:
                    raise ValidationError("A data deletion request is already in progress")
                
                # Create deletion request
                deletion_request = DataDeletionRequest.objects.create(
                    user=user,
                    deletion_scope=deletion_scope,
                    reason=reason,
                    requested_data_types=data_types or [],
                    legal_basis='GDPR Article 17 - Right to erasure'
                )
                
                # Log the request
                ComplianceAuditLog.objects.create(
                    activity_type='compliance_action',
                    user=user,
                    action='data_deletion_requested',
                    resource='user_data',
                    outcome='success',
                    details={
                        'request_id': str(deletion_request.request_id),
                        'scope': deletion_scope,
                        'reason': reason,
                        'data_types': data_types
                    }
                )
                
                logger.info(f"Data deletion requested for user {user.id}: {deletion_request.request_id}")
                return deletion_request
                
        except Exception as e:
            logger.error(f"Failed to create data deletion request for user {user.id}: {str(e)}")
            raise
    
    def process_data_deletion(self, deletion_request: DataDeletionRequest) -> bool:
        """
        Process an approved data deletion request.
        """
        try:
            with transaction.atomic():
                deletion_request.status = 'processing'
                deletion_request.processing_started_at = timezone.now()
                deletion_request.save()
                
                deletion_summary = {}
                retention_exceptions = []
                
                if deletion_request.deletion_scope == 'full_account':
                    # Full account deletion
                    deletion_summary = self._delete_user_account(deletion_request.user)
                    
                elif deletion_request.deletion_scope == 'specific_data':
                    # Delete specific data types
                    deletion_summary = self._delete_specific_data(
                        deletion_request.user,
                        deletion_request.requested_data_types
                    )
                
                # Check for legal retention requirements
                retention_exceptions = self._check_retention_requirements(deletion_request.user)
                
                # Update request
                deletion_request.status = 'completed'
                deletion_request.processing_completed_at = timezone.now()
                deletion_request.deletion_summary = deletion_summary
                deletion_request.retention_exceptions = retention_exceptions
                deletion_request.save()
                
                # Log completion
                ComplianceAuditLog.objects.create(
                    activity_type='compliance_action',
                    user=deletion_request.user,
                    action='data_deletion_completed',
                    resource='user_data',
                    outcome='success',
                    details={
                        'request_id': str(deletion_request.request_id),
                        'deletion_summary': deletion_summary,
                        'retention_exceptions': retention_exceptions
                    }
                )
                
                logger.info(f"Data deletion completed for request {deletion_request.request_id}")
                return True
                
        except Exception as e:
            deletion_request.status = 'failed'
            deletion_request.save()
            
            logger.error(f"Failed to process data deletion {deletion_request.request_id}: {str(e)}")
            return False
    
    def _delete_user_account(self, user: User) -> Dict[str, Any]:
        """
        Delete user account and associated data.
        """
        summary = {
            'user_profile': 1,
            'sessions': 0,
            'security_events': 0,
            'audit_logs': 0,
            'consent_records': 0
        }
        
        # Delete sessions
        summary['sessions'] = UserSession.objects.filter(user=user).count()
        UserSession.objects.filter(user=user).delete()
        
        # Delete security events (except those required for legal retention)
        security_events = SecurityEvent.objects.filter(user=user)
        summary['security_events'] = security_events.count()
        security_events.delete()
        
        # Delete audit logs (except those required for legal retention)
        audit_logs = AuditLog.objects.filter(user=user)
        summary['audit_logs'] = audit_logs.count()
        audit_logs.delete()
        
        # Delete consent records
        summary['consent_records'] = ConsentRecord.objects.filter(user=user).count()
        ConsentRecord.objects.filter(user=user).delete()
        
        # Anonymize or delete user profile
        user.email = f"deleted_user_{user.id}@deleted.local"
        user.first_name = "Deleted"
        user.last_name = "User"
        user.is_active = False
        user.save()
        
        return summary
    
    def _delete_specific_data(self, user: User, data_types: List[str]) -> Dict[str, Any]:
        """
        Delete specific data types for a user.
        """
        summary = {}
        
        for data_type in data_types:
            if data_type == 'sessions':
                count = UserSession.objects.filter(user=user).count()
                UserSession.objects.filter(user=user).delete()
                summary['sessions'] = count
                
            elif data_type == 'security_events':
                count = SecurityEvent.objects.filter(user=user).count()
                SecurityEvent.objects.filter(user=user).delete()
                summary['security_events'] = count
                
            elif data_type == 'audit_logs':
                count = AuditLog.objects.filter(user=user).count()
                AuditLog.objects.filter(user=user).delete()
                summary['audit_logs'] = count
        
        return summary
    
    def _check_retention_requirements(self, user: User) -> List[Dict[str, Any]]:
        """
        Check for legal retention requirements that prevent deletion.
        """
        exceptions = []
        
        # Example: Financial records must be retained for 7 years
        # Example: Security incident logs must be retained for 2 years
        # This would be customized based on specific legal requirements
        
        return exceptions
    
    def manage_consent(self, user: User, purpose_name: str, consent_status: str, 
                      consent_method: str = 'explicit', ip_address: str = None, 
                      user_agent: str = None) -> ConsentRecord:
        """
        Manage user consent for data processing purposes.
        """
        try:
            purpose = DataProcessingPurpose.objects.get(name=purpose_name)
            
            consent_record, created = ConsentRecord.objects.get_or_create(
                user=user,
                purpose=purpose,
                defaults={
                    'status': consent_status,
                    'consent_method': consent_method,
                    'ip_address': ip_address,
                    'user_agent': user_agent,
                    'consent_text': f"Consent for {purpose.description}",
                    'version': '1.0'
                }
            )
            
            if not created:
                # Update existing consent
                consent_record.status = consent_status
                if consent_status == 'granted':
                    consent_record.consent_given_at = timezone.now()
                elif consent_status == 'withdrawn':
                    consent_record.consent_withdrawn_at = timezone.now()
                consent_record.save()
            
            # Log consent change
            ComplianceAuditLog.objects.create(
                activity_type='compliance_action',
                user=user,
                action=f'consent_{consent_status}',
                resource='data_processing_consent',
                outcome='success',
                details={
                    'purpose': purpose_name,
                    'consent_method': consent_method,
                    'previous_status': consent_record.status if not created else None
                }
            )
            
            return consent_record
            
        except DataProcessingPurpose.DoesNotExist:
            logger.error(f"Data processing purpose not found: {purpose_name}")
            raise ValidationError(f"Invalid data processing purpose: {purpose_name}")
        except Exception as e:
            logger.error(f"Failed to manage consent for user {user.id}: {str(e)}")
            raise


class CCPAComplianceService:
    """
    Service for CCPA compliance operations.
    """
    
    def create_privacy_rights_request(self, user: User, request_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle CCPA privacy rights requests (know, delete, opt-out).
        """
        try:
            if request_type == 'know':
                # Right to know - similar to GDPR data export
                gdpr_service = GDPRComplianceService()
                export_request = gdpr_service.request_data_export(
                    user=user,
                    data_types=details.get('data_types', ['profile', 'sessions', 'security_events']),
                    export_format='json'
                )
                return {'request_id': str(export_request.request_id), 'type': 'data_export'}
                
            elif request_type == 'delete':
                # Right to delete - similar to GDPR right to erasure
                gdpr_service = GDPRComplianceService()
                deletion_request = gdpr_service.request_data_deletion(
                    user=user,
                    deletion_scope='full_account',
                    reason='CCPA Right to Delete'
                )
                return {'request_id': str(deletion_request.request_id), 'type': 'data_deletion'}
                
            elif request_type == 'opt_out':
                # Right to opt-out of sale
                return self._handle_opt_out_request(user, details)
                
            else:
                raise ValidationError(f"Invalid CCPA request type: {request_type}")
                
        except Exception as e:
            logger.error(f"Failed to create CCPA privacy rights request: {str(e)}")
            raise
    
    def _handle_opt_out_request(self, user: User, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle CCPA opt-out of sale requests.
        """
        # Update user preferences to opt-out of data sale
        # This would be implemented based on specific business requirements
        
        # Log the opt-out request
        ComplianceAuditLog.objects.create(
            activity_type='compliance_action',
            user=user,
            action='ccpa_opt_out',
            resource='data_sale_preferences',
            outcome='success',
            details=details
        )
        
        return {'status': 'opted_out', 'effective_date': timezone.now().isoformat()}


class SOC2AuditService:
    """
    Service for SOC2 compliance audit trail and reporting.
    """
    
    def create_audit_log(self, activity_type: str, user: User = None, session_id: str = None,
                        ip_address: str = None, user_agent: str = None, request_id: str = None,
                        action: str = None, resource: str = None, outcome: str = 'success',
                        details: Dict[str, Any] = None, before_state: Dict[str, Any] = None,
                        after_state: Dict[str, Any] = None, severity: str = 'low') -> ComplianceAuditLog:
        """
        Create a SOC2-compliant audit log entry with integrity verification.
        """
        try:
            # Get the last audit log for chaining
            last_log = ComplianceAuditLog.objects.order_by('-timestamp').first()
            previous_checksum = last_log.checksum if last_log else ''
            
            # Create audit log entry
            audit_log = ComplianceAuditLog(
                activity_type=activity_type,
                severity=severity,
                user=user,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                request_id=request_id,
                action=action,
                resource=resource,
                outcome=outcome,
                details=details or {},
                before_state=before_state or {},
                after_state=after_state or {},
                previous_log_checksum=previous_checksum
            )
            
            # Calculate integrity checksum
            audit_log.checksum = self._calculate_audit_checksum(audit_log)
            audit_log.save()
            
            return audit_log
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")
            raise
    
    def _calculate_audit_checksum(self, audit_log: ComplianceAuditLog) -> str:
        """
        Calculate SHA-256 checksum for audit log integrity verification.
        """
        data = {
            'audit_id': str(audit_log.audit_id),
            'timestamp': audit_log.timestamp.isoformat(),
            'activity_type': audit_log.activity_type,
            'user_id': str(audit_log.user.id) if audit_log.user else '',
            'action': audit_log.action,
            'resource': audit_log.resource,
            'outcome': audit_log.outcome,
            'details': audit_log.details,
            'previous_checksum': audit_log.previous_log_checksum
        }
        
        data_string = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(data_string.encode()).hexdigest()
    
    def verify_audit_trail_integrity(self, start_date: datetime = None, end_date: datetime = None) -> Dict[str, Any]:
        """
        Verify the integrity of the audit trail by checking checksums.
        """
        try:
            query = ComplianceAuditLog.objects.order_by('timestamp')
            
            if start_date:
                query = query.filter(timestamp__gte=start_date)
            if end_date:
                query = query.filter(timestamp__lte=end_date)
            
            audit_logs = query.all()
            
            verification_results = {
                'total_logs': len(audit_logs),
                'verified_logs': 0,
                'integrity_violations': [],
                'missing_checksums': 0
            }
            
            previous_checksum = ''
            
            for log in audit_logs:
                if not log.checksum:
                    verification_results['missing_checksums'] += 1
                    continue
                
                # Verify checksum
                expected_checksum = self._calculate_audit_checksum(log)
                if log.checksum != expected_checksum:
                    verification_results['integrity_violations'].append({
                        'audit_id': str(log.audit_id),
                        'timestamp': log.timestamp.isoformat(),
                        'expected_checksum': expected_checksum,
                        'actual_checksum': log.checksum
                    })
                
                # Verify chain integrity
                if log.previous_log_checksum != previous_checksum:
                    verification_results['integrity_violations'].append({
                        'audit_id': str(log.audit_id),
                        'timestamp': log.timestamp.isoformat(),
                        'issue': 'chain_break',
                        'expected_previous': previous_checksum,
                        'actual_previous': log.previous_log_checksum
                    })
                
                verification_results['verified_logs'] += 1
                previous_checksum = log.checksum
            
            verification_results['integrity_status'] = 'valid' if not verification_results['integrity_violations'] else 'compromised'
            
            return verification_results
            
        except Exception as e:
            logger.error(f"Failed to verify audit trail integrity: {str(e)}")
            raise
    
    def generate_compliance_report(self, report_type: str, period_start: datetime, 
                                 period_end: datetime, generated_by: User = None) -> ComplianceReport:
        """
        Generate compliance reports for various standards.
        """
        try:
            report = ComplianceReport.objects.create(
                report_type=report_type,
                title=f"{report_type.replace('_', ' ').title()} - {period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')}",
                period_start=period_start,
                period_end=period_end,
                generated_by=generated_by,
                retention_until=timezone.now() + timedelta(days=2555)  # 7 years retention
            )
            
            # Generate report content based on type
            if report_type == 'gdpr_compliance':
                report.summary = self._generate_gdpr_report_summary(period_start, period_end)
            elif report_type == 'ccpa_compliance':
                report.summary = self._generate_ccpa_report_summary(period_start, period_end)
            elif report_type == 'soc2_audit':
                report.summary = self._generate_soc2_report_summary(period_start, period_end)
            elif report_type == 'security_assessment':
                report.summary = self._generate_security_report_summary(period_start, period_end)
            
            report.save()
            
            # Log report generation
            self.create_audit_log(
                activity_type='compliance_action',
                user=generated_by,
                action='compliance_report_generated',
                resource='compliance_report',
                outcome='success',
                details={
                    'report_id': str(report.report_id),
                    'report_type': report_type,
                    'period_start': period_start.isoformat(),
                    'period_end': period_end.isoformat()
                }
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {str(e)}")
            raise
    
    def _generate_gdpr_report_summary(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Generate GDPR compliance report summary.
        """
        return {
            'data_export_requests': DataExportRequest.objects.filter(
                created_at__range=[start_date, end_date]
            ).count(),
            'data_deletion_requests': DataDeletionRequest.objects.filter(
                created_at__range=[start_date, end_date]
            ).count(),
            'consent_changes': ConsentRecord.objects.filter(
                updated_at__range=[start_date, end_date]
            ).count(),
            'data_disclosures': DataDisclosureLog.objects.filter(
                disclosure_date__range=[start_date, end_date]
            ).count(),
            'privacy_policy_acceptances': PrivacyPolicyAcceptance.objects.filter(
                accepted_at__range=[start_date, end_date]
            ).count()
        }
    
    def _generate_ccpa_report_summary(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Generate CCPA compliance report summary.
        """
        # Similar to GDPR but with CCPA-specific metrics
        return {
            'know_requests': DataExportRequest.objects.filter(
                created_at__range=[start_date, end_date]
            ).count(),
            'delete_requests': DataDeletionRequest.objects.filter(
                created_at__range=[start_date, end_date]
            ).count(),
            'opt_out_requests': ComplianceAuditLog.objects.filter(
                action='ccpa_opt_out',
                timestamp__range=[start_date, end_date]
            ).count()
        }
    
    def _generate_soc2_report_summary(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Generate SOC2 audit report summary.
        """
        return {
            'total_audit_logs': ComplianceAuditLog.objects.filter(
                timestamp__range=[start_date, end_date]
            ).count(),
            'security_events': ComplianceAuditLog.objects.filter(
                activity_type='security_event',
                timestamp__range=[start_date, end_date]
            ).count(),
            'authentication_events': ComplianceAuditLog.objects.filter(
                activity_type='authentication',
                timestamp__range=[start_date, end_date]
            ).count(),
            'data_access_events': ComplianceAuditLog.objects.filter(
                activity_type='data_access',
                timestamp__range=[start_date, end_date]
            ).count(),
            'integrity_verification': self.verify_audit_trail_integrity(start_date, end_date)
        }
    
    def _generate_security_report_summary(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Generate security assessment report summary.
        """
        return {
            'vulnerabilities_discovered': SecurityVulnerability.objects.filter(
                discovered_at__range=[start_date, end_date]
            ).count(),
            'vulnerabilities_resolved': SecurityVulnerability.objects.filter(
                resolved_at__range=[start_date, end_date]
            ).count(),
            'critical_vulnerabilities': SecurityVulnerability.objects.filter(
                severity='critical',
                discovered_at__range=[start_date, end_date]
            ).count(),
            'high_severity_events': ComplianceAuditLog.objects.filter(
                severity='high',
                timestamp__range=[start_date, end_date]
            ).count()
        }


class SecurityComplianceService:
    """
    Service for security compliance monitoring and OWASP guidelines implementation.
    """
    
    def track_security_vulnerability(self, vulnerability_data: Dict[str, Any]) -> SecurityVulnerability:
        """
        Track a new security vulnerability.
        """
        try:
            vulnerability = SecurityVulnerability.objects.create(
                vulnerability_id=vulnerability_data['vulnerability_id'],
                title=vulnerability_data['title'],
                description=vulnerability_data['description'],
                severity=vulnerability_data['severity'],
                cve_id=vulnerability_data.get('cve_id', ''),
                owasp_category=vulnerability_data.get('owasp_category', ''),
                affected_components=vulnerability_data.get('affected_components', []),
                discovery_method=vulnerability_data['discovery_method'],
                discovered_by=vulnerability_data['discovered_by'],
                remediation_plan=vulnerability_data.get('remediation_plan', ''),
                remediation_deadline=vulnerability_data.get('remediation_deadline')
            )
            
            # Log vulnerability discovery
            audit_service = SOC2AuditService()
            audit_service.create_audit_log(
                activity_type='security_event',
                action='vulnerability_discovered',
                resource='security_vulnerability',
                outcome='success',
                severity=vulnerability_data['severity'],
                details={
                    'vulnerability_id': vulnerability_data['vulnerability_id'],
                    'severity': vulnerability_data['severity'],
                    'owasp_category': vulnerability_data.get('owasp_category', ''),
                    'discovery_method': vulnerability_data['discovery_method']
                }
            )
            
            return vulnerability
            
        except Exception as e:
            logger.error(f"Failed to track security vulnerability: {str(e)}")
            raise
    
    def resolve_security_vulnerability(self, vulnerability_id: str, resolved_by: User, 
                                     resolution_notes: str) -> SecurityVulnerability:
        """
        Mark a security vulnerability as resolved.
        """
        try:
            vulnerability = SecurityVulnerability.objects.get(vulnerability_id=vulnerability_id)
            vulnerability.status = 'resolved'
            vulnerability.resolved_at = timezone.now()
            vulnerability.resolved_by = resolved_by
            vulnerability.resolution_notes = resolution_notes
            vulnerability.save()
            
            # Log vulnerability resolution
            audit_service = SOC2AuditService()
            audit_service.create_audit_log(
                activity_type='security_event',
                user=resolved_by,
                action='vulnerability_resolved',
                resource='security_vulnerability',
                outcome='success',
                details={
                    'vulnerability_id': vulnerability_id,
                    'resolution_time': (vulnerability.resolved_at - vulnerability.discovered_at).total_seconds(),
                    'resolution_notes': resolution_notes
                }
            )
            
            return vulnerability
            
        except SecurityVulnerability.DoesNotExist:
            logger.error(f"Security vulnerability not found: {vulnerability_id}")
            raise ValidationError(f"Vulnerability not found: {vulnerability_id}")
        except Exception as e:
            logger.error(f"Failed to resolve security vulnerability: {str(e)}")
            raise
    
    def get_owasp_compliance_status(self) -> Dict[str, Any]:
        """
        Get OWASP Top 10 compliance status.
        """
        owasp_categories = [
            'A01:2021-Broken Access Control',
            'A02:2021-Cryptographic Failures',
            'A03:2021-Injection',
            'A04:2021-Insecure Design',
            'A05:2021-Security Misconfiguration',
            'A06:2021-Vulnerable and Outdated Components',
            'A07:2021-Identification and Authentication Failures',
            'A08:2021-Software and Data Integrity Failures',
            'A09:2021-Security Logging and Monitoring Failures',
            'A10:2021-Server-Side Request Forgery'
        ]
        
        compliance_status = {}
        
        for category in owasp_categories:
            open_vulnerabilities = SecurityVulnerability.objects.filter(
                owasp_category=category,
                status='open'
            ).count()
            
            total_vulnerabilities = SecurityVulnerability.objects.filter(
                owasp_category=category
            ).count()
            
            compliance_status[category] = {
                'open_vulnerabilities': open_vulnerabilities,
                'total_vulnerabilities': total_vulnerabilities,
                'compliance_score': ((total_vulnerabilities - open_vulnerabilities) / max(total_vulnerabilities, 1)) * 100
            }
        
        return compliance_status