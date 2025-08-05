"""
URL patterns for compliance and privacy rights management.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from ..views.compliance_views import (
    DataExportView, DataExportDownloadView, DataDeletionView,
    ConsentManagementView, PrivacyPolicyView, CCPAPrivacyRightsView,
    SecurityComplianceView, ComplianceReportView, ComplianceDashboardView,
    AuditIntegrityView, ComplianceAlertsView,
    available_data_types, withdrawable_consents
)

app_name = 'compliance'

# API endpoints
urlpatterns = [
    # GDPR Data Portability (Article 20)
    path('data-export/', DataExportView.as_view(), name='data_export'),
    path('data-export/<uuid:request_id>/download/', DataExportDownloadView.as_view(), name='data_export_download'),
    path('data-export/available-types/', available_data_types, name='available_data_types'),
    
    # GDPR Right to Erasure (Article 17)
    path('data-deletion/', DataDeletionView.as_view(), name='data_deletion'),
    
    # Consent Management
    path('consent/', ConsentManagementView.as_view(), name='consent_management'),
    path('consent/withdrawable/', withdrawable_consents, name='withdrawable_consents'),
    
    # Privacy Policy Management
    path('privacy-policy/', PrivacyPolicyView.as_view(), name='privacy_policy'),
    
    # CCPA Privacy Rights
    path('ccpa/privacy-rights/', CCPAPrivacyRightsView.as_view(), name='ccpa_privacy_rights'),
    
    # Security Compliance
    path('security/', SecurityComplianceView.as_view(), name='security_compliance'),
    
    # Compliance Reports
    path('reports/', ComplianceReportView.as_view(), name='compliance_reports'),
    
    # Compliance Dashboard
    path('dashboard/', ComplianceDashboardView.as_view(), name='compliance_dashboard'),
    
    # Audit Integrity
    path('audit-integrity/', AuditIntegrityView.as_view(), name='audit_integrity'),
    
    # Compliance Alerts
    path('alerts/', ComplianceAlertsView.as_view(), name='compliance_alerts'),
]