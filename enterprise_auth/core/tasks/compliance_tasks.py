"""
Celery tasks for compliance monitoring and maintenance.
"""

import logging
from datetime import datetime, timedelta
from celery import shared_task
from django.utils import timezone
from django.contrib.auth import get_user_model

from ..services.compliance_dashboard_service import ComplianceDashboardService
from ..services.audit_integrity_service import AuditIntegrityService
from ..services.security_compliance_service import SecurityComplianceService
from ..services.privacy_rights_service import PrivacyRightsService
from ..services.compliance_service import GDPRComplianceService, SOC2AuditService
from ..models.compliance import DataExportRequest, ComplianceReport
from ..monitoring.alerting import alert_manager, AlertSeverity

User = get_user_model()
logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def verify_audit_integrity_task(self, period_days=7):
    """
    Periodic task to verify audit log integrity.
    
    Args:
        period_days: Number of days to verify
    """
    try:
        logger.info(f"Starting audit integrity verification for {period_days} days")
        
        integrity_service = AuditIntegrityService()
        
        # Calculate date range
        end_date = timezone.now()
        start_date = end_date - timedelta(days=period_days)
        
        # Run integrity verification
        verification_results = integrity_service.verify_audit_chain_integrity(
            start_date=start_date,
            end_date=end_date
        )
        
        # Check for integrity issues and create alerts
        if verification_results['integrity_status'] == 'compromised':
            total_issues = (
                len(verification_results.get('checksum_mismatches', [])) +
                len(verification_results.get('chain_breaks', [])) +
                verification_results.get('missing_checksums', 0)
            )
            
            alert_manager.create_alert(
                name='audit_integrity_compromised',
                severity=AlertSeverity.HIGH,
                message=f'Audit trail integrity compromised: {total_issues} issues found in {period_days} days',
                source='compliance_monitoring',
                labels={
                    'compliance_area': 'soc2',
                    'issue_type': 'audit_integrity'
                },
                annotations={
                    'total_issues': str(total_issues),
                    'checksum_mismatches': str(len(verification_results.get('checksum_mismatches', []))),
                    'chain_breaks': str(len(verification_results.get('chain_breaks', []))),
                    'missing_checksums': str(verification_results.get('missing_checksums', 0)),
                    'runbook': 'Investigate audit log integrity issues and run repair if necessary'
                }
            )
        
        logger.info(
            f"Audit integrity verification completed",
            integrity_status=verification_results['integrity_status'],
            total_logs=verification_results['total_logs_verified']
        )
        
        return {
            'status': 'completed',
            'integrity_status': verification_results['integrity_status'],
            'total_logs_verified': verification_results['total_logs_verified']
        }
        
    except Exception as e:
        logger.error(f"Audit integrity verification failed: {str(e)}")
        
        # Create alert for task failure
        alert_manager.create_alert(
            name='audit_integrity_verification_failed',
            severity=AlertSeverity.MEDIUM,
            message=f'Audit integrity verification task failed: {str(e)}',
            source='compliance_monitoring',
            labels={'task': 'audit_integrity_verification'}
        )
        
        # Retry the task
        raise self.retry(exc=e, countdown=300)  # Retry after 5 minutes


@shared_task(bind=True, max_retries=3)
def process_pending_data_exports_task(self):
    """
    Process pending data export requests.
    """
    try:
        logger.info("Processing pending data export requests")
        
        gdpr_service = GDPRComplianceService()
        
        # Get pending export requests
        pending_requests = DataExportRequest.objects.filter(
            status='pending'
        ).order_by('created_at')
        
        processed_count = 0
        failed_count = 0
        
        for export_request in pending_requests[:10]:  # Process up to 10 at a time
            try:
                success = gdpr_service.process_data_export(export_request)
                if success:
                    processed_count += 1
                    logger.info(f"Processed data export request: {export_request.request_id}")
                else:
                    failed_count += 1
                    logger.error(f"Failed to process data export request: {export_request.request_id}")
                    
            except Exception as e:
                failed_count += 1
                logger.error(f"Error processing export request {export_request.request_id}: {str(e)}")
        
        # Check for overdue requests and create alerts
        overdue_requests = DataExportRequest.objects.filter(
            status='pending',
            created_at__lt=timezone.now() - timedelta(days=30)
        ).count()
        
        if overdue_requests > 0:
            alert_manager.create_alert(
                name='overdue_data_export_requests',
                severity=AlertSeverity.HIGH,
                message=f'{overdue_requests} data export requests are overdue (>30 days)',
                source='compliance_monitoring',
                labels={
                    'compliance_area': 'gdpr',
                    'issue_type': 'overdue_requests'
                },
                annotations={
                    'overdue_count': str(overdue_requests),
                    'runbook': 'Review and process overdue data export requests immediately'
                }
            )
        
        logger.info(
            f"Data export processing completed",
            processed=processed_count,
            failed=failed_count,
            overdue=overdue_requests
        )
        
        return {
            'status': 'completed',
            'processed_count': processed_count,
            'failed_count': failed_count,
            'overdue_requests': overdue_requests
        }
        
    except Exception as e:
        logger.error(f"Data export processing failed: {str(e)}")
        raise self.retry(exc=e, countdown=600)  # Retry after 10 minutes


@shared_task(bind=True, max_retries=3)
def check_consent_expiration_task(self):
    """
    Check for expired consents and update their status.
    """
    try:
        logger.info("Checking consent expiration")
        
        privacy_service = PrivacyRightsService()
        result = privacy_service.check_consent_expiration()
        
        expired_count = result.get('expired_consents', 0)
        
        if expired_count > 0:
            logger.info(f"Updated {expired_count} expired consents")
            
            # Create informational alert
            alert_manager.create_alert(
                name='consent_expiration_processed',
                severity=AlertSeverity.LOW,
                message=f'{expired_count} consents expired and were updated',
                source='compliance_monitoring',
                labels={
                    'compliance_area': 'gdpr',
                    'issue_type': 'consent_expiration'
                },
                annotations={
                    'expired_count': str(expired_count)
                }
            )
        
        return {
            'status': 'completed',
            'expired_consents': expired_count
        }
        
    except Exception as e:
        logger.error(f"Consent expiration check failed: {str(e)}")
        raise self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=3)
def run_security_compliance_scan_task(self, scan_type='comprehensive'):
    """
    Run security compliance scan.
    
    Args:
        scan_type: Type of scan to run
    """
    try:
        logger.info(f"Starting {scan_type} security compliance scan")
        
        security_service = SecurityComplianceService()
        scan_results = security_service.run_security_scan(scan_type)
        
        # Check for critical vulnerabilities
        summary = scan_results.get('scan_summary', {})
        critical_vulns = summary.get('critical_vulnerabilities', 0)
        high_vulns = summary.get('high_vulnerabilities', 0)
        
        if critical_vulns > 0:
            alert_manager.create_alert(
                name='critical_security_vulnerabilities',
                severity=AlertSeverity.CRITICAL,
                message=f'{critical_vulns} critical security vulnerabilities found',
                source='security_scan',
                labels={
                    'compliance_area': 'security',
                    'issue_type': 'critical_vulnerabilities'
                },
                annotations={
                    'critical_count': str(critical_vulns),
                    'high_count': str(high_vulns),
                    'scan_id': scan_results.get('scan_id', ''),
                    'runbook': 'Address critical vulnerabilities immediately'
                }
            )
        elif high_vulns > 5:  # Alert if more than 5 high severity vulnerabilities
            alert_manager.create_alert(
                name='high_security_vulnerabilities',
                severity=AlertSeverity.HIGH,
                message=f'{high_vulns} high severity security vulnerabilities found',
                source='security_scan',
                labels={
                    'compliance_area': 'security',
                    'issue_type': 'high_vulnerabilities'
                },
                annotations={
                    'high_count': str(high_vulns),
                    'scan_id': scan_results.get('scan_id', ''),
                    'runbook': 'Review and address high severity vulnerabilities'
                }
            )
        
        logger.info(
            f"Security compliance scan completed",
            scan_id=scan_results.get('scan_id'),
            total_vulnerabilities=summary.get('total_vulnerabilities', 0),
            critical_vulnerabilities=critical_vulns
        )
        
        return {
            'status': 'completed',
            'scan_id': scan_results.get('scan_id'),
            'scan_summary': summary
        }
        
    except Exception as e:
        logger.error(f"Security compliance scan failed: {str(e)}")
        raise self.retry(exc=e, countdown=900)  # Retry after 15 minutes


@shared_task(bind=True, max_retries=3)
def generate_compliance_reports_task(self, report_types=None):
    """
    Generate compliance reports.
    
    Args:
        report_types: List of report types to generate
    """
    try:
        if report_types is None:
            report_types = ['gdpr_compliance', 'soc2_audit', 'security_assessment']
        
        logger.info(f"Generating compliance reports: {report_types}")
        
        audit_service = SOC2AuditService()
        generated_reports = []
        
        # Calculate report period (last 30 days)
        end_date = timezone.now()
        start_date = end_date - timedelta(days=30)
        
        for report_type in report_types:
            try:
                report = audit_service.generate_compliance_report(
                    report_type=report_type,
                    period_start=start_date,
                    period_end=end_date
                )
                
                generated_reports.append({
                    'report_id': str(report.report_id),
                    'report_type': report_type,
                    'generated_at': report.generated_at.isoformat()
                })
                
                logger.info(f"Generated {report_type} report: {report.report_id}")
                
            except Exception as e:
                logger.error(f"Failed to generate {report_type} report: {str(e)}")
        
        return {
            'status': 'completed',
            'generated_reports': generated_reports,
            'total_reports': len(generated_reports)
        }
        
    except Exception as e:
        logger.error(f"Compliance report generation failed: {str(e)}")
        raise self.retry(exc=e, countdown=600)


@shared_task(bind=True, max_retries=3)
def compliance_monitoring_health_check_task(self):
    """
    Comprehensive compliance monitoring health check.
    """
    try:
        logger.info("Running compliance monitoring health check")
        
        dashboard_service = ComplianceDashboardService()
        
        # Get compliance overview for last 7 days
        overview = dashboard_service.get_compliance_overview(period_days=7)
        
        health_status = {
            'overall_score': overview.get('overall_compliance_score', 0),
            'gdpr_status': overview.get('gdpr_compliance', {}).get('status', 'unknown'),
            'soc2_status': overview.get('soc2_compliance', {}).get('status', 'unknown'),
            'security_status': overview.get('security_compliance', {}).get('status', 'unknown'),
            'audit_integrity_status': overview.get('audit_integrity', {}).get('status', 'unknown'),
            'action_items_count': len(overview.get('action_items', []))
        }
        
        # Check overall compliance score
        overall_score = health_status['overall_score']
        if overall_score < 70:
            alert_manager.create_alert(
                name='low_compliance_score',
                severity=AlertSeverity.HIGH,
                message=f'Overall compliance score is low: {overall_score}%',
                source='compliance_monitoring',
                labels={
                    'compliance_area': 'overall',
                    'issue_type': 'low_score'
                },
                annotations={
                    'overall_score': str(overall_score),
                    'action_items': str(health_status['action_items_count']),
                    'runbook': 'Review compliance dashboard and address action items'
                }
            )
        
        # Check for non-compliant areas
        non_compliant_areas = []
        for area in ['gdpr_status', 'soc2_status', 'security_status', 'audit_integrity_status']:
            if health_status[area] == 'non_compliant':
                non_compliant_areas.append(area.replace('_status', ''))
        
        if non_compliant_areas:
            alert_manager.create_alert(
                name='compliance_areas_non_compliant',
                severity=AlertSeverity.MEDIUM,
                message=f'Non-compliant areas detected: {", ".join(non_compliant_areas)}',
                source='compliance_monitoring',
                labels={
                    'compliance_area': 'multiple',
                    'issue_type': 'non_compliant'
                },
                annotations={
                    'non_compliant_areas': ', '.join(non_compliant_areas),
                    'runbook': 'Review specific compliance areas and address issues'
                }
            )
        
        logger.info(
            f"Compliance health check completed",
            overall_score=overall_score,
            non_compliant_areas=len(non_compliant_areas),
            action_items=health_status['action_items_count']
        )
        
        return {
            'status': 'completed',
            'health_status': health_status,
            'non_compliant_areas': non_compliant_areas
        }
        
    except Exception as e:
        logger.error(f"Compliance health check failed: {str(e)}")
        raise self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=3)
def cleanup_old_compliance_data_task(self, retention_days=2555):
    """
    Clean up old compliance data based on retention policies.
    
    Args:
        retention_days: Number of days to retain data (default: 7 years)
    """
    try:
        logger.info(f"Cleaning up compliance data older than {retention_days} days")
        
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        # Clean up old compliance reports
        old_reports = ComplianceReport.objects.filter(
            generated_at__lt=cutoff_date,
            retention_until__lt=timezone.now()
        )
        
        reports_count = old_reports.count()
        old_reports.delete()
        
        # Clean up old export files (but keep the request records)
        old_exports = DataExportRequest.objects.filter(
            created_at__lt=cutoff_date,
            status='completed'
        )
        
        exports_cleaned = 0
        for export_request in old_exports:
            if export_request.file_path:
                try:
                    from django.core.files.storage import default_storage
                    if default_storage.exists(export_request.file_path):
                        default_storage.delete(export_request.file_path)
                        export_request.file_path = ''
                        export_request.save(update_fields=['file_path'])
                        exports_cleaned += 1
                except Exception as e:
                    logger.warning(f"Failed to delete export file {export_request.file_path}: {str(e)}")
        
        logger.info(
            f"Compliance data cleanup completed",
            reports_deleted=reports_count,
            export_files_cleaned=exports_cleaned
        )
        
        return {
            'status': 'completed',
            'reports_deleted': reports_count,
            'export_files_cleaned': exports_cleaned
        }
        
    except Exception as e:
        logger.error(f"Compliance data cleanup failed: {str(e)}")
        raise self.retry(exc=e, countdown=600)