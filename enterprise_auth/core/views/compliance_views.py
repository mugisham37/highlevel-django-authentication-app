"""
API views for compliance and privacy rights management.
"""

import logging
from typing import Dict, Any
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.http import HttpResponse, Http404
from django.core.files.storage import default_storage

from ..models.compliance import (
    DataExportRequest, DataDeletionRequest, ConsentRecord,
    PrivacyPolicyVersion, SecurityVulnerability, ComplianceReport
)
from ..services.compliance_service import GDPRComplianceService, CCPAComplianceService, SOC2AuditService
from ..services.data_portability_service import DataPortabilityService
from ..services.privacy_rights_service import PrivacyRightsService
from ..services.security_compliance_service import SecurityComplianceService
from ..services.compliance_dashboard_service import ComplianceDashboardService
from ..services.audit_integrity_service import AuditIntegrityService
from ..serializers import ComplianceSerializer

User = get_user_model()
logger = logging.getLogger(__name__)


class DataExportView(APIView):
    """
    Handle GDPR Article 20 data portability requests.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """
        Create a new data export request.
        """
        try:
            data_types = request.data.get('data_types', ['profile', 'sessions', 'security_events'])
            export_format = request.data.get('format', 'json')
            
            # Validate request
            portability_service = DataPortabilityService()
            validation_result = portability_service.validate_export_request(request.user, data_types)
            
            if not validation_result['valid']:
                return Response({
                    'error': 'Invalid export request',
                    'details': validation_result['errors']
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create export request
            gdpr_service = GDPRComplianceService()
            export_request = gdpr_service.request_data_export(
                user=request.user,
                data_types=data_types,
                export_format=export_format
            )
            
            return Response({
                'request_id': str(export_request.request_id),
                'status': export_request.status,
                'data_types': export_request.requested_data_types,
                'format': export_request.export_format,
                'created_at': export_request.created_at.isoformat(),
                'download_expires_at': export_request.download_expires_at.isoformat(),
                'data_availability': validation_result['data_availability']
            }, status=status.HTTP_201_CREATED)
            
        except ValidationError as e:
            return Response({
                'error': 'Validation error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Failed to create data export request: {str(e)}")
            return Response({
                'error': 'Internal server error',
                'message': 'Failed to create export request'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get(self, request):
        """
        Get user's data export requests.
        """
        try:
            export_requests = DataExportRequest.objects.filter(
                user=request.user
            ).order_by('-created_at')
            
            requests_data = []
            for export_request in export_requests:
                request_data = {
                    'request_id': str(export_request.request_id),
                    'status': export_request.status,
                    'data_types': export_request.requested_data_types,
                    'format': export_request.export_format,
                    'created_at': export_request.created_at.isoformat(),
                    'download_expires_at': export_request.download_expires_at.isoformat() if export_request.download_expires_at else None,
                    'file_size_bytes': export_request.file_size_bytes,
                    'download_count': export_request.download_count,
                    'can_download': (export_request.status == 'completed' and 
                                   export_request.download_expires_at and 
                                   export_request.download_expires_at > timezone.now())
                }
                requests_data.append(request_data)
            
            return Response({
                'export_requests': requests_data
            })
            
        except Exception as e:
            logger.error(f"Failed to get export requests: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DataExportDownloadView(APIView):
    """
    Handle data export file downloads.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, request_id):
        """
        Download data export file.
        """
        try:
            export_request = DataExportRequest.objects.get(
                request_id=request_id,
                user=request.user,
                status='completed'
            )
            
            # Check if download is still valid
            if (export_request.download_expires_at and 
                export_request.download_expires_at < timezone.now()):
                return Response({
                    'error': 'Download expired',
                    'message': 'The download link has expired'
                }, status=status.HTTP_410_GONE)
            
            # Check if file exists
            if not export_request.file_path or not default_storage.exists(export_request.file_path):
                return Response({
                    'error': 'File not found',
                    'message': 'Export file is no longer available'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Update download count
            export_request.download_count += 1
            export_request.downloaded_at = timezone.now()
            export_request.save()
            
            # Serve file
            file_content = default_storage.open(export_request.file_path).read()
            
            response = HttpResponse(
                file_content,
                content_type='application/octet-stream'
            )
            response['Content-Disposition'] = f'attachment; filename="data_export_{request_id}.{export_request.export_format}"'
            
            return response
            
        except DataExportRequest.DoesNotExist:
            raise Http404("Export request not found")
        except Exception as e:
            logger.error(f"Failed to download export file: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DataDeletionView(APIView):
    """
    Handle GDPR Article 17 right to erasure requests.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """
        Create a new data deletion request.
        """
        try:
            deletion_scope = request.data.get('scope', 'full_account')
            reason = request.data.get('reason', 'User requested deletion')
            data_types = request.data.get('data_types', [])
            
            gdpr_service = GDPRComplianceService()
            deletion_request = gdpr_service.request_data_deletion(
                user=request.user,
                deletion_scope=deletion_scope,
                reason=reason,
                data_types=data_types
            )
            
            return Response({
                'request_id': str(deletion_request.request_id),
                'status': deletion_request.status,
                'scope': deletion_request.deletion_scope,
                'reason': deletion_request.reason,
                'created_at': deletion_request.created_at.isoformat(),
                'legal_basis': deletion_request.legal_basis
            }, status=status.HTTP_201_CREATED)
            
        except ValidationError as e:
            return Response({
                'error': 'Validation error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Failed to create data deletion request: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get(self, request):
        """
        Get user's data deletion requests.
        """
        try:
            deletion_requests = DataDeletionRequest.objects.filter(
                user=request.user
            ).order_by('-created_at')
            
            requests_data = []
            for deletion_request in deletion_requests:
                request_data = {
                    'request_id': str(deletion_request.request_id),
                    'status': deletion_request.status,
                    'scope': deletion_request.deletion_scope,
                    'reason': deletion_request.reason,
                    'created_at': deletion_request.created_at.isoformat(),
                    'approved_at': deletion_request.approved_at.isoformat() if deletion_request.approved_at else None,
                    'processing_completed_at': deletion_request.processing_completed_at.isoformat() if deletion_request.processing_completed_at else None,
                    'rejection_reason': deletion_request.rejection_reason
                }
                requests_data.append(request_data)
            
            return Response({
                'deletion_requests': requests_data
            })
            
        except Exception as e:
            logger.error(f"Failed to get deletion requests: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ConsentManagementView(APIView):
    """
    Handle user consent management for data processing.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """
        Get user's consent status for all data processing purposes.
        """
        try:
            privacy_service = PrivacyRightsService()
            consent_status = privacy_service.get_user_consent_status(request.user)
            
            return Response(consent_status)
            
        except Exception as e:
            logger.error(f"Failed to get consent status: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        """
        Grant consent for a data processing purpose.
        """
        try:
            purpose_name = request.data.get('purpose')
            consent_method = request.data.get('consent_method', 'explicit')
            
            if not purpose_name:
                return Response({
                    'error': 'Missing purpose',
                    'message': 'Data processing purpose is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            privacy_service = PrivacyRightsService()
            consent_record = privacy_service.grant_consent(
                user=request.user,
                purpose_name=purpose_name,
                consent_method=consent_method,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT')
            )
            
            return Response({
                'purpose': purpose_name,
                'status': consent_record.status,
                'consent_given_at': consent_record.consent_given_at.isoformat(),
                'expires_at': consent_record.expires_at.isoformat() if consent_record.expires_at else None
            })
            
        except ValidationError as e:
            return Response({
                'error': 'Validation error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Failed to grant consent: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def delete(self, request):
        """
        Withdraw consent for a data processing purpose.
        """
        try:
            purpose_name = request.data.get('purpose')
            
            if not purpose_name:
                return Response({
                    'error': 'Missing purpose',
                    'message': 'Data processing purpose is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            privacy_service = PrivacyRightsService()
            consent_record = privacy_service.withdraw_consent(
                user=request.user,
                purpose_name=purpose_name,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT')
            )
            
            return Response({
                'purpose': purpose_name,
                'status': consent_record.status,
                'consent_withdrawn_at': consent_record.consent_withdrawn_at.isoformat()
            })
            
        except ValidationError as e:
            return Response({
                'error': 'Validation error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Failed to withdraw consent: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PrivacyPolicyView(APIView):
    """
    Handle privacy policy acceptance and status.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """
        Get current privacy policy and user's acceptance status.
        """
        try:
            privacy_service = PrivacyRightsService()
            policy_status = privacy_service.get_user_privacy_policy_status(request.user)
            
            return Response(policy_status)
            
        except Exception as e:
            logger.error(f"Failed to get privacy policy status: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        """
        Accept the current privacy policy.
        """
        try:
            acceptance_method = request.data.get('acceptance_method', 'explicit')
            
            current_policy = PrivacyPolicyVersion.objects.filter(is_current=True).first()
            if not current_policy:
                return Response({
                    'error': 'No current policy',
                    'message': 'No current privacy policy found'
                }, status=status.HTTP_404_NOT_FOUND)
            
            privacy_service = PrivacyRightsService()
            acceptance = privacy_service.record_privacy_policy_acceptance(
                user=request.user,
                policy_version=current_policy,
                acceptance_method=acceptance_method,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT')
            )
            
            return Response({
                'policy_version': current_policy.version,
                'accepted_at': acceptance.accepted_at.isoformat(),
                'acceptance_method': acceptance.acceptance_method
            })
            
        except Exception as e:
            logger.error(f"Failed to accept privacy policy: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CCPAPrivacyRightsView(APIView):
    """
    Handle CCPA privacy rights requests.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """
        Create a CCPA privacy rights request.
        """
        try:
            request_type = request.data.get('type')  # 'know', 'delete', 'opt_out'
            details = request.data.get('details', {})
            
            if request_type not in ['know', 'delete', 'opt_out']:
                return Response({
                    'error': 'Invalid request type',
                    'message': 'Request type must be one of: know, delete, opt_out'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            ccpa_service = CCPAComplianceService()
            result = ccpa_service.create_privacy_rights_request(
                user=request.user,
                request_type=request_type,
                details=details
            )
            
            return Response({
                'request_type': request_type,
                'result': result,
                'created_at': timezone.now().isoformat()
            })
            
        except ValidationError as e:
            return Response({
                'error': 'Validation error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Failed to create CCPA request: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SecurityComplianceView(APIView):
    """
    Handle security compliance monitoring and reporting.
    """
    permission_classes = [permissions.IsAdminUser]
    
    def get(self, request):
        """
        Get security compliance status.
        """
        try:
            security_service = SecurityComplianceService()
            
            # Get OWASP compliance status
            owasp_status = security_service.get_owasp_compliance_status()
            
            # Get vulnerability summary
            vulnerabilities = SecurityVulnerability.objects.all()
            vulnerability_summary = {
                'total': vulnerabilities.count(),
                'open': vulnerabilities.filter(status='open').count(),
                'resolved': vulnerabilities.filter(status='resolved').count(),
                'critical': vulnerabilities.filter(severity='critical', status='open').count(),
                'high': vulnerabilities.filter(severity='high', status='open').count()
            }
            
            return Response({
                'owasp_compliance': owasp_status,
                'vulnerability_summary': vulnerability_summary,
                'last_updated': timezone.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Failed to get security compliance status: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        """
        Run security scan.
        """
        try:
            scan_type = request.data.get('scan_type', 'comprehensive')
            
            security_service = SecurityComplianceService()
            scan_results = security_service.run_security_scan(scan_type)
            
            return Response(scan_results)
            
        except Exception as e:
            logger.error(f"Failed to run security scan: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ComplianceReportView(APIView):
    """
    Handle compliance report generation and retrieval.
    """
    permission_classes = [permissions.IsAdminUser]
    
    def get(self, request):
        """
        Get list of compliance reports.
        """
        try:
            reports = ComplianceReport.objects.all().order_by('-generated_at')[:50]
            
            reports_data = []
            for report in reports:
                report_data = {
                    'report_id': str(report.report_id),
                    'report_type': report.report_type,
                    'title': report.title,
                    'period_start': report.period_start.isoformat(),
                    'period_end': report.period_end.isoformat(),
                    'generated_at': report.generated_at.isoformat(),
                    'generated_by': report.generated_by.email if report.generated_by else None,
                    'summary': report.summary
                }
                reports_data.append(report_data)
            
            return Response({
                'reports': reports_data
            })
            
        except Exception as e:
            logger.error(f"Failed to get compliance reports: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        """
        Generate a new compliance report.
        """
        try:
            report_type = request.data.get('report_type')
            period_days = request.data.get('period_days', 30)
            
            if not report_type:
                return Response({
                    'error': 'Missing report type',
                    'message': 'Report type is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            end_date = timezone.now()
            start_date = end_date - timezone.timedelta(days=period_days)
            
            audit_service = SOC2AuditService()
            report = audit_service.generate_compliance_report(
                report_type=report_type,
                period_start=start_date,
                period_end=end_date,
                generated_by=request.user
            )
            
            return Response({
                'report_id': str(report.report_id),
                'report_type': report.report_type,
                'title': report.title,
                'generated_at': report.generated_at.isoformat(),
                'summary': report.summary
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def available_data_types(request):
    """
    Get available data types for export.
    """
    try:
        portability_service = DataPortabilityService()
        data_types = portability_service.get_available_data_types()
        
        return Response({
            'data_types': data_types
        })
        
    except Exception as e:
        logger.error(f"Failed to get available data types: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ComplianceDashboardView(APIView):
    """
    Handle compliance dashboard data and metrics.
    """
    permission_classes = [permissions.IsAdminUser]
    
    def get(self, request):
        """
        Get compliance dashboard overview.
        """
        try:
            period_days = int(request.query_params.get('period_days', 30))
            
            dashboard_service = ComplianceDashboardService()
            overview = dashboard_service.get_compliance_overview(period_days)
            
            return Response(overview)
            
        except Exception as e:
            logger.error(f"Failed to get compliance dashboard: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AuditIntegrityView(APIView):
    """
    Handle audit integrity verification and reporting.
    """
    permission_classes = [permissions.IsAdminUser]
    
    def get(self, request):
        """
        Get audit integrity status.
        """
        try:
            period_days = int(request.query_params.get('period_days', 30))
            
            integrity_service = AuditIntegrityService()
            
            # Calculate date range
            end_date = timezone.now()
            start_date = end_date - timezone.timedelta(days=period_days)
            
            # Run integrity verification
            verification_results = integrity_service.verify_audit_chain_integrity(
                start_date=start_date,
                end_date=end_date
            )
            
            return Response({
                'verification_results': verification_results,
                'period_days': period_days
            })
            
        except Exception as e:
            logger.error(f"Failed to get audit integrity status: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self, request):
        """
        Run audit integrity repair.
        """
        try:
            period_days = int(request.data.get('period_days', 30))
            dry_run = request.data.get('dry_run', True)
            
            integrity_service = AuditIntegrityService()
            
            # Calculate date range
            end_date = timezone.now()
            start_date = end_date - timezone.timedelta(days=period_days)
            
            # Run repair
            repair_results = integrity_service.repair_audit_chain(
                start_date=start_date,
                end_date=end_date,
                dry_run=dry_run
            )
            
            return Response({
                'repair_results': repair_results,
                'period_days': period_days
            })
            
        except Exception as e:
            logger.error(f"Failed to repair audit integrity: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ComplianceAlertsView(APIView):
    """
    Handle compliance alerts and notifications.
    """
    permission_classes = [permissions.IsAdminUser]
    
    def get(self, request):
        """
        Get active compliance alerts.
        """
        try:
            dashboard_service = ComplianceDashboardService()
            alerts = dashboard_service.get_compliance_alerts()
            
            return Response({
                'alerts': alerts,
                'total_alerts': len(alerts),
                'critical_alerts': len([a for a in alerts if a.get('severity') == 'critical']),
                'high_alerts': len([a for a in alerts if a.get('severity') == 'high'])
            })
            
        except Exception as e:
            logger.error(f"Failed to get compliance alerts: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def withdrawable_consents(request):
    """
    Get list of consents that can be withdrawn.
    """
    try:
        privacy_service = PrivacyRightsService()
        withdrawable_consents = privacy_service.get_withdrawable_consents(request.user)
        
        return Response({
            'withdrawable_consents': withdrawable_consents
        })
        
    except Exception as e:
        logger.error(f"Failed to get withdrawable consents: {str(e)}")
        return Response({
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)