"""
Compliance dashboard service for generating compliance metrics and dashboards.
Provides real-time compliance monitoring and reporting capabilities.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from django.db.models import Count, Q
from django.utils import timezone
from django.contrib.auth import get_user_model

from ..models.compliance import (
    ComplianceAuditLog, SecurityVulnerability, ComplianceReport,
    DataExportRequest, DataDeletionRequest, ConsentRecord
)
from ..models import SecurityEvent, UserSession
from .audit_integrity_service import AuditIntegrityService
from .security_compliance_service import SecurityComplianceService

User = get_user_model()
logger = logging.getLogger(__name__)


class ComplianceDashboardService:
    """
    Service for generating compliance dashboards and metrics.
    Provides comprehensive compliance monitoring and reporting.
    """
    
    def __init__(self):
        self.integrity_service = AuditIntegrityService()
        self.security_service = SecurityComplianceService()
    
    def get_compliance_overview(self, period_days: int = 30) -> Dict[str, Any]:
        """
        Get comprehensive compliance overview dashboard.
        
        Args:
            period_days: Number of days to include in metrics
            
        Returns:
            Dictionary containing compliance overview metrics
        """
        try:
            end_date = timezone.now()
            start_date = end_date - timedelta(days=period_days)
            
            overview = {
                'dashboard_metadata': {
                    'generated_at': timezone.now().isoformat(),
                    'period_start': start_date.isoformat(),
                    'period_end': end_date.isoformat(),
                    'period_days': period_days
                },
                'gdpr_compliance': self._get_gdpr_metrics(start_date, end_date),
                'ccpa_compliance': self._get_ccpa_metrics(start_date, end_date),
                'soc2_compliance': self._get_soc2_metrics(start_date, end_date),
                'security_compliance': self._get_security_metrics(start_date, end_date),
                'audit_integrity': self._get_audit_integrity_metrics(start_date, end_date),
                'overall_compliance_score': 0.0,
                'compliance_trends': self._get_compliance_trends(period_days),
                'action_items': []
            }
            
            # Calculate overall compliance score
            overview['overall_compliance_score'] = self._calculate_overall_compliance_score(overview)
            
            # Generate action items
            overview['action_items'] = self._generate_action_items(overview)
            
            logger.info(
                f"Compliance overview generated",
                period_days=period_days,
                overall_score=overview['overall_compliance_score']
            )
            
            return overview
            
        except Exception as e:
            logger.error(f"Failed to generate compliance overview: {str(e)}")
            raise
    
    def _get_gdpr_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get GDPR compliance metrics."""
        try:
            # Data export requests
            export_requests = DataExportRequest.objects.filter(
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            export_metrics = {
                'total_requests': export_requests.count(),
                'completed_requests': export_requests.filter(status='completed').count(),
                'pending_requests': export_requests.filter(status__in=['pending', 'processing']).count(),
                'failed_requests': export_requests.filter(status='failed').count(),
                'average_processing_time_hours': self._calculate_average_processing_time(export_requests)
            }
            
            # Data deletion requests
            deletion_requests = DataDeletionRequest.objects.filter(
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            deletion_metrics = {
                'total_requests': deletion_requests.count(),
                'completed_requests': deletion_requests.filter(status='completed').count(),
                'pending_requests': deletion_requests.filter(status__in=['pending', 'approved', 'processing']).count(),
                'rejected_requests': deletion_requests.filter(status='rejected').count()
            }
            
            # Consent management
            consent_metrics = self._get_consent_metrics(start_date, end_date)
            
            # Calculate GDPR compliance score
            gdpr_score = self._calculate_gdpr_score(export_metrics, deletion_metrics, consent_metrics)
            
            return {
                'compliance_score': gdpr_score,
                'data_portability': export_metrics,
                'right_to_erasure': deletion_metrics,
                'consent_management': consent_metrics,
                'status': 'compliant' if gdpr_score >= 90 else 'non_compliant'
            }
            
        except Exception as e:
            logger.error(f"Failed to get GDPR metrics: {str(e)}")
            return {'compliance_score': 0, 'status': 'error'}
    
    def _get_ccpa_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get CCPA compliance metrics."""
        try:
            # CCPA requests are handled through the same data export/deletion system
            # but with different legal basis
            
            ccpa_export_requests = DataExportRequest.objects.filter(
                created_at__gte=start_date,
                created_at__lte=end_date
            ).count()
            
            ccpa_deletion_requests = DataDeletionRequest.objects.filter(
                created_at__gte=start_date,
                created_at__lte=end_date,
                legal_basis__icontains='CCPA'
            ).count()
            
            # Calculate CCPA compliance score
            ccpa_score = 95.0  # Base score, would be calculated based on actual metrics
            
            return {
                'compliance_score': ccpa_score,
                'right_to_know_requests': ccpa_export_requests,
                'right_to_delete_requests': ccpa_deletion_requests,
                'opt_out_requests': 0,  # Would be tracked separately
                'status': 'compliant' if ccpa_score >= 90 else 'non_compliant'
            }
            
        except Exception as e:
            logger.error(f"Failed to get CCPA metrics: {str(e)}")
            return {'compliance_score': 0, 'status': 'error'}
    
    def _get_soc2_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get SOC2 compliance metrics."""
        try:
            # Audit log metrics
            total_audit_logs = ComplianceAuditLog.objects.filter(
                timestamp__gte=start_date,
                timestamp__lte=end_date
            ).count()
            
            audit_logs_by_severity = {}
            for severity in ['low', 'medium', 'high', 'critical']:
                count = ComplianceAuditLog.objects.filter(
                    timestamp__gte=start_date,
                    timestamp__lte=end_date,
                    severity=severity
                ).count()
                audit_logs_by_severity[severity] = count
            
            # Get audit integrity metrics
            integrity_results = self.integrity_service.verify_audit_chain_integrity(start_date, end_date)
            integrity_score = self._calculate_integrity_score_from_results(integrity_results)
            
            # Security events
            security_events = SecurityEvent.objects.filter(
                timestamp__gte=start_date,
                timestamp__lte=end_date
            ).count()
            
            # Calculate SOC2 compliance score
            soc2_score = min(100, integrity_score + 5)  # Bonus for good integrity
            
            return {
                'compliance_score': soc2_score,
                'audit_trail': {
                    'total_logs': total_audit_logs,
                    'logs_by_severity': audit_logs_by_severity,
                    'integrity_score': integrity_score,
                    'integrity_status': integrity_results.get('integrity_status', 'unknown')
                },
                'security_monitoring': {
                    'total_security_events': security_events,
                    'monitoring_coverage': 95.0  # Would be calculated based on actual coverage
                },
                'status': 'compliant' if soc2_score >= 95 else 'non_compliant'
            }
            
        except Exception as e:
            logger.error(f"Failed to get SOC2 metrics: {str(e)}")
            return {'compliance_score': 0, 'status': 'error'}
    
    def _get_security_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get security compliance metrics."""
        try:
            # Get OWASP compliance status
            owasp_status = self.security_service.get_owasp_compliance_status()
            
            # Vulnerability metrics
            vulnerabilities = SecurityVulnerability.objects.filter(
                discovered_at__gte=start_date,
                discovered_at__lte=end_date
            )
            
            vuln_metrics = {
                'total_vulnerabilities': vulnerabilities.count(),
                'open_vulnerabilities': vulnerabilities.filter(status='open').count(),
                'resolved_vulnerabilities': vulnerabilities.filter(status='resolved').count(),
                'critical_vulnerabilities': vulnerabilities.filter(severity='critical', status='open').count(),
                'high_vulnerabilities': vulnerabilities.filter(severity='high', status='open').count()
            }
            
            # Security events
            security_events = SecurityEvent.objects.filter(
                timestamp__gte=start_date,
                timestamp__lte=end_date
            )
            
            event_metrics = {
                'total_events': security_events.count(),
                'high_severity_events': security_events.filter(severity__in=['high', 'critical']).count(),
                'resolved_events': security_events.filter(status='resolved').count()
            }
            
            return {
                'compliance_score': owasp_status.get('overall_compliance_score', 0),
                'owasp_compliance': owasp_status,
                'vulnerability_management': vuln_metrics,
                'security_monitoring': event_metrics,
                'status': owasp_status.get('overall_status', 'non_compliant')
            }
            
        except Exception as e:
            logger.error(f"Failed to get security metrics: {str(e)}")
            return {'compliance_score': 0, 'status': 'error'}
    
    def _get_audit_integrity_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get audit integrity metrics."""
        try:
            integrity_results = self.integrity_service.verify_audit_chain_integrity(start_date, end_date)
            integrity_score = self._calculate_integrity_score_from_results(integrity_results)
            
            return {
                'integrity_score': integrity_score,
                'verification_results': integrity_results,
                'status': 'compliant' if integrity_score >= 95 else 'non_compliant'
            }
            
        except Exception as e:
            logger.error(f"Failed to get audit integrity metrics: {str(e)}")
            return {'integrity_score': 0, 'status': 'error'}
    
    def _get_consent_metrics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get consent management metrics."""
        try:
            # Consent records created in period
            consent_records = ConsentRecord.objects.filter(
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
            # Current consent status
            active_consents = ConsentRecord.objects.filter(status='granted').count()
            withdrawn_consents = ConsentRecord.objects.filter(status='withdrawn').count()
            expired_consents = ConsentRecord.objects.filter(status='expired').count()
            
            return {
                'new_consents': consent_records.filter(status='granted').count(),
                'withdrawn_consents_period': consent_records.filter(status='withdrawn').count(),
                'active_consents': active_consents,
                'withdrawn_consents_total': withdrawn_consents,
                'expired_consents': expired_consents,
                'consent_rate': self._calculate_consent_rate()
            }
            
        except Exception as e:
            logger.error(f"Failed to get consent metrics: {str(e)}")
            return {}
    
    def _get_compliance_trends(self, period_days: int) -> Dict[str, Any]:
        """Get compliance trends over time."""
        try:
            # Calculate trends for the last few periods
            trends = {
                'gdpr_trend': self._calculate_trend('gdpr', period_days),
                'soc2_trend': self._calculate_trend('soc2', period_days),
                'security_trend': self._calculate_trend('security', period_days),
                'overall_trend': 'stable'  # Would be calculated based on historical data
            }
            
            return trends
            
        except Exception as e:
            logger.error(f"Failed to get compliance trends: {str(e)}")
            return {}
    
    def _calculate_overall_compliance_score(self, overview: Dict[str, Any]) -> float:
        """Calculate overall compliance score."""
        try:
            scores = []
            
            # Weight different compliance areas
            weights = {
                'gdpr_compliance': 0.3,
                'soc2_compliance': 0.3,
                'security_compliance': 0.25,
                'audit_integrity': 0.15
            }
            
            weighted_score = 0.0
            total_weight = 0.0
            
            for area, weight in weights.items():
                if area in overview and 'compliance_score' in overview[area]:
                    score = overview[area]['compliance_score']
                    weighted_score += score * weight
                    total_weight += weight
            
            if total_weight > 0:
                return round(weighted_score / total_weight, 2)
            else:
                return 0.0
                
        except Exception as e:
            logger.error(f"Failed to calculate overall compliance score: {str(e)}")
            return 0.0
    
    def _generate_action_items(self, overview: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate action items based on compliance status."""
        action_items = []
        
        try:
            # Check GDPR compliance
            if overview.get('gdpr_compliance', {}).get('status') == 'non_compliant':
                action_items.append({
                    'priority': 'high',
                    'category': 'gdpr',
                    'title': 'GDPR Compliance Issues',
                    'description': 'Address GDPR compliance gaps',
                    'due_date': (timezone.now() + timedelta(days=7)).isoformat()
                })
            
            # Check pending data requests
            gdpr_data = overview.get('gdpr_compliance', {})
            if gdpr_data.get('data_portability', {}).get('pending_requests', 0) > 0:
                action_items.append({
                    'priority': 'medium',
                    'category': 'gdpr',
                    'title': 'Process Pending Data Export Requests',
                    'description': f"Process {gdpr_data['data_portability']['pending_requests']} pending data export requests",
                    'due_date': (timezone.now() + timedelta(days=3)).isoformat()
                })
            
            # Check security vulnerabilities
            security_data = overview.get('security_compliance', {})
            critical_vulns = security_data.get('vulnerability_management', {}).get('critical_vulnerabilities', 0)
            if critical_vulns > 0:
                action_items.append({
                    'priority': 'critical',
                    'category': 'security',
                    'title': 'Critical Security Vulnerabilities',
                    'description': f"Address {critical_vulns} critical security vulnerabilities",
                    'due_date': (timezone.now() + timedelta(days=1)).isoformat()
                })
            
            # Check audit integrity
            integrity_data = overview.get('audit_integrity', {})
            if integrity_data.get('status') == 'non_compliant':
                action_items.append({
                    'priority': 'high',
                    'category': 'soc2',
                    'title': 'Audit Trail Integrity Issues',
                    'description': 'Investigate and repair audit trail integrity issues',
                    'due_date': (timezone.now() + timedelta(days=2)).isoformat()
                })
            
            return action_items
            
        except Exception as e:
            logger.error(f"Failed to generate action items: {str(e)}")
            return []
    
    def _calculate_average_processing_time(self, requests) -> float:
        """Calculate average processing time for requests."""
        try:
            completed_requests = requests.filter(
                status='completed',
                processing_started_at__isnull=False,
                processing_completed_at__isnull=False
            )
            
            if not completed_requests.exists():
                return 0.0
            
            total_time = 0
            count = 0
            
            for request in completed_requests:
                if request.processing_started_at and request.processing_completed_at:
                    processing_time = request.processing_completed_at - request.processing_started_at
                    total_time += processing_time.total_seconds()
                    count += 1
            
            if count > 0:
                return round(total_time / count / 3600, 2)  # Convert to hours
            else:
                return 0.0
                
        except Exception as e:
            logger.error(f"Failed to calculate average processing time: {str(e)}")
            return 0.0
    
    def _calculate_gdpr_score(self, export_metrics: Dict, deletion_metrics: Dict, consent_metrics: Dict) -> float:
        """Calculate GDPR compliance score."""
        try:
            score = 100.0
            
            # Deduct points for failed requests
            if export_metrics['total_requests'] > 0:
                failure_rate = export_metrics['failed_requests'] / export_metrics['total_requests']
                score -= failure_rate * 20
            
            if deletion_metrics['total_requests'] > 0:
                rejection_rate = deletion_metrics['rejected_requests'] / deletion_metrics['total_requests']
                score -= rejection_rate * 15
            
            # Deduct points for slow processing
            if export_metrics['average_processing_time_hours'] > 72:  # More than 3 days
                score -= 10
            
            # Bonus for good consent management
            consent_rate = consent_metrics.get('consent_rate', 0)
            if consent_rate > 80:
                score += 5
            
            return max(0, min(100, round(score, 2)))
            
        except Exception as e:
            logger.error(f"Failed to calculate GDPR score: {str(e)}")
            return 0.0
    
    def _calculate_integrity_score_from_results(self, integrity_results: Dict[str, Any]) -> float:
        """Calculate integrity score from verification results."""
        try:
            if integrity_results.get('total_logs_verified', 0) == 0:
                return 100.0
            
            total_issues = (
                len(integrity_results.get('checksum_mismatches', [])) +
                len(integrity_results.get('chain_breaks', [])) +
                integrity_results.get('missing_checksums', 0)
            )
            
            if total_issues == 0:
                return 100.0
            
            issue_rate = total_issues / integrity_results['total_logs_verified']
            score = max(0, 100 - (issue_rate * 100))
            
            return round(score, 2)
            
        except Exception as e:
            logger.error(f"Failed to calculate integrity score: {str(e)}")
            return 0.0
    
    def _calculate_consent_rate(self) -> float:
        """Calculate overall consent rate."""
        try:
            total_users = User.objects.filter(is_active=True).count()
            if total_users == 0:
                return 0.0
            
            users_with_consent = ConsentRecord.objects.filter(
                status='granted'
            ).values('user').distinct().count()
            
            return round((users_with_consent / total_users) * 100, 2)
            
        except Exception as e:
            logger.error(f"Failed to calculate consent rate: {str(e)}")
            return 0.0
    
    def _calculate_trend(self, compliance_area: str, period_days: int) -> str:
        """Calculate trend for a compliance area."""
        try:
            # This would compare current period with previous period
            # For now, return a placeholder
            return 'stable'
            
        except Exception as e:
            logger.error(f"Failed to calculate trend for {compliance_area}: {str(e)}")
            return 'unknown'
    
    def get_compliance_alerts(self) -> List[Dict[str, Any]]:
        """Get active compliance alerts."""
        try:
            alerts = []
            
            # Check for overdue data requests
            overdue_exports = DataExportRequest.objects.filter(
                status='pending',
                created_at__lt=timezone.now() - timedelta(days=30)
            ).count()
            
            if overdue_exports > 0:
                alerts.append({
                    'severity': 'high',
                    'category': 'gdpr',
                    'title': 'Overdue Data Export Requests',
                    'message': f'{overdue_exports} data export requests are overdue (>30 days)',
                    'action_required': True
                })
            
            # Check for critical vulnerabilities
            critical_vulns = SecurityVulnerability.objects.filter(
                status='open',
                severity='critical'
            ).count()
            
            if critical_vulns > 0:
                alerts.append({
                    'severity': 'critical',
                    'category': 'security',
                    'title': 'Critical Security Vulnerabilities',
                    'message': f'{critical_vulns} critical vulnerabilities require immediate attention',
                    'action_required': True
                })
            
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to get compliance alerts: {str(e)}")
            return []