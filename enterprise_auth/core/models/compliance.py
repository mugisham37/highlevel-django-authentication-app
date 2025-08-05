"""
Compliance and privacy models for GDPR, CCPA, and SOC2 compliance.
"""

import uuid
from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.utils import timezone
from django.core.serializers.json import DjangoJSONEncoder
import json

from .base import BaseModel, AuditableModel, TimestampedModel

User = get_user_model()


class DataProcessingPurpose(BaseModel):
    """
    Defines purposes for data processing under GDPR/CCPA.
    """
    PURPOSES = [
        ('authentication', 'User Authentication'),
        ('authorization', 'Access Control'),
        ('security', 'Security Monitoring'),
        ('analytics', 'Usage Analytics'),
        ('communication', 'User Communication'),
        ('legal_compliance', 'Legal Compliance'),
        ('service_improvement', 'Service Improvement'),
    ]
    
    name = models.CharField(max_length=100, unique=True)
    purpose_type = models.CharField(max_length=50, choices=PURPOSES)
    description = models.TextField()
    legal_basis = models.CharField(max_length=200)  # GDPR legal basis
    retention_period_days = models.IntegerField()
    is_essential = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'compliance_data_processing_purpose'
        verbose_name = 'Data Processing Purpose'
        verbose_name_plural = 'Data Processing Purposes'


class ConsentRecord(AuditableModel):
    """
    Tracks user consent for data processing activities.
    """
    CONSENT_STATUS = [
        ('granted', 'Granted'),
        ('withdrawn', 'Withdrawn'),
        ('expired', 'Expired'),
        ('pending', 'Pending'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='consent_records')
    purpose = models.ForeignKey(DataProcessingPurpose, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=CONSENT_STATUS, default='pending')
    consent_given_at = models.DateTimeField(null=True, blank=True)
    consent_withdrawn_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    consent_method = models.CharField(max_length=50)  # 'explicit', 'implicit', 'opt_in', etc.
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    consent_text = models.TextField()  # The actual consent text shown to user
    version = models.CharField(max_length=20)  # Version of consent text
    
    class Meta:
        db_table = 'compliance_consent_record'
        unique_together = ['user', 'purpose']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['purpose', 'status']),
            models.Index(fields=['consent_given_at']),
        ]


class DataExportRequest(AuditableModel):
    """
    Tracks data portability requests under GDPR Article 20.
    """
    REQUEST_STATUS = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    EXPORT_FORMAT = [
        ('json', 'JSON'),
        ('csv', 'CSV'),
        ('xml', 'XML'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='data_export_requests')
    request_id = models.UUIDField(default=uuid.uuid4, unique=True)
    status = models.CharField(max_length=20, choices=REQUEST_STATUS, default='pending')
    export_format = models.CharField(max_length=10, choices=EXPORT_FORMAT, default='json')
    requested_data_types = models.JSONField(default=list)  # List of data types to export
    file_path = models.CharField(max_length=500, blank=True)  # Path to generated export file
    file_size_bytes = models.BigIntegerField(null=True, blank=True)
    download_expires_at = models.DateTimeField(null=True, blank=True)
    downloaded_at = models.DateTimeField(null=True, blank=True)
    download_count = models.IntegerField(default=0)
    processing_started_at = models.DateTimeField(null=True, blank=True)
    processing_completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        db_table = 'compliance_data_export_request'
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['request_id']),
            models.Index(fields=['created_at']),
        ]


class DataDeletionRequest(AuditableModel):
    """
    Tracks right to deletion requests under GDPR Article 17.
    """
    REQUEST_STATUS = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    DELETION_SCOPE = [
        ('full_account', 'Full Account Deletion'),
        ('specific_data', 'Specific Data Types'),
        ('inactive_data', 'Inactive Data Only'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='data_deletion_requests')
    request_id = models.UUIDField(default=uuid.uuid4, unique=True)
    status = models.CharField(max_length=20, choices=REQUEST_STATUS, default='pending')
    deletion_scope = models.CharField(max_length=20, choices=DELETION_SCOPE, default='full_account')
    requested_data_types = models.JSONField(default=list)
    reason = models.TextField()  # User's reason for deletion
    legal_basis = models.CharField(max_length=200)  # Legal basis for deletion
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_deletions')
    approved_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)
    processing_started_at = models.DateTimeField(null=True, blank=True)
    processing_completed_at = models.DateTimeField(null=True, blank=True)
    deletion_summary = models.JSONField(default=dict)  # Summary of what was deleted
    retention_exceptions = models.JSONField(default=list)  # Data retained for legal reasons
    
    class Meta:
        db_table = 'compliance_data_deletion_request'
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['request_id']),
            models.Index(fields=['created_at']),
        ]


class DataDisclosureLog(AuditableModel):
    """
    Logs data disclosures to third parties for compliance tracking.
    """
    DISCLOSURE_TYPE = [
        ('legal_request', 'Legal Request'),
        ('law_enforcement', 'Law Enforcement'),
        ('regulatory', 'Regulatory Authority'),
        ('service_provider', 'Service Provider'),
        ('business_transfer', 'Business Transfer'),
        ('user_consent', 'User Consent'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='data_disclosures')
    disclosure_id = models.UUIDField(default=uuid.uuid4, unique=True)
    disclosure_type = models.CharField(max_length=30, choices=DISCLOSURE_TYPE)
    recipient_name = models.CharField(max_length=200)
    recipient_contact = models.CharField(max_length=200)
    legal_basis = models.CharField(max_length=200)
    data_categories = models.JSONField(default=list)  # Categories of data disclosed
    purpose = models.TextField()
    disclosure_date = models.DateTimeField(default=timezone.now)
    retention_period = models.CharField(max_length=100)
    user_notified = models.BooleanField(default=False)
    user_notification_date = models.DateTimeField(null=True, blank=True)
    supporting_documents = models.JSONField(default=list)  # References to supporting docs
    
    class Meta:
        db_table = 'compliance_data_disclosure_log'
        indexes = [
            models.Index(fields=['user', 'disclosure_type']),
            models.Index(fields=['disclosure_date']),
            models.Index(fields=['recipient_name']),
        ]


class PrivacyPolicyVersion(BaseModel):
    """
    Tracks privacy policy versions and user acceptance.
    """
    version = models.CharField(max_length=20, unique=True)
    title = models.CharField(max_length=200)
    content = models.TextField()
    effective_date = models.DateTimeField()
    expiry_date = models.DateTimeField(null=True, blank=True)
    is_current = models.BooleanField(default=False)
    requires_explicit_consent = models.BooleanField(default=True)
    changes_summary = models.TextField(blank=True)
    
    class Meta:
        db_table = 'compliance_privacy_policy_version'
        ordering = ['-effective_date']


class PrivacyPolicyAcceptance(AuditableModel):
    """
    Tracks user acceptance of privacy policy versions.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='privacy_acceptances')
    policy_version = models.ForeignKey(PrivacyPolicyVersion, on_delete=models.CASCADE)
    accepted_at = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    acceptance_method = models.CharField(max_length=50)  # 'explicit', 'implicit', 'registration'
    
    class Meta:
        db_table = 'compliance_privacy_policy_acceptance'
        unique_together = ['user', 'policy_version']
        indexes = [
            models.Index(fields=['user', 'accepted_at']),
            models.Index(fields=['policy_version', 'accepted_at']),
        ]


class ComplianceAuditLog(BaseModel):
    """
    SOC2-compliant audit trail for all system activities.
    """
    ACTIVITY_TYPES = [
        ('authentication', 'Authentication'),
        ('authorization', 'Authorization'),
        ('data_access', 'Data Access'),
        ('data_modification', 'Data Modification'),
        ('system_configuration', 'System Configuration'),
        ('security_event', 'Security Event'),
        ('compliance_action', 'Compliance Action'),
        ('admin_action', 'Administrative Action'),
    ]
    
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    audit_id = models.UUIDField(default=uuid.uuid4, unique=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    activity_type = models.CharField(max_length=30, choices=ACTIVITY_TYPES, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='low')
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    session_id = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    request_id = models.CharField(max_length=255, blank=True)
    
    # Generic foreign key for linking to any model
    content_type = models.ForeignKey(ContentType, on_delete=models.SET_NULL, null=True, blank=True)
    object_id = models.CharField(max_length=255, blank=True)
    content_object = GenericForeignKey('content_type', 'object_id')
    
    action = models.CharField(max_length=100)  # Specific action taken
    resource = models.CharField(max_length=100)  # Resource affected
    outcome = models.CharField(max_length=20)  # 'success', 'failure', 'error'
    details = models.JSONField(default=dict, encoder=DjangoJSONEncoder)
    before_state = models.JSONField(default=dict, encoder=DjangoJSONEncoder)
    after_state = models.JSONField(default=dict, encoder=DjangoJSONEncoder)
    
    # Integrity verification
    checksum = models.CharField(max_length=64, blank=True)  # SHA-256 hash for integrity
    previous_log_checksum = models.CharField(max_length=64, blank=True)
    
    class Meta:
        db_table = 'compliance_audit_log'
        indexes = [
            models.Index(fields=['timestamp', 'activity_type']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['session_id']),
            models.Index(fields=['audit_id']),
            models.Index(fields=['severity', 'timestamp']),
        ]


class SecurityVulnerability(AuditableModel):
    """
    Tracks security vulnerabilities and remediation efforts.
    """
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
        ('accepted_risk', 'Accepted Risk'),
    ]
    
    vulnerability_id = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=200)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    cve_id = models.CharField(max_length=20, blank=True)  # CVE identifier if applicable
    owasp_category = models.CharField(max_length=50, blank=True)  # OWASP Top 10 category
    affected_components = models.JSONField(default=list)
    discovery_method = models.CharField(max_length=100)  # How it was discovered
    discovered_by = models.CharField(max_length=100)
    discovered_at = models.DateTimeField(default=timezone.now)
    remediation_plan = models.TextField(blank=True)
    remediation_deadline = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    resolution_notes = models.TextField(blank=True)
    
    class Meta:
        db_table = 'compliance_security_vulnerability'
        indexes = [
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['discovered_at']),
            models.Index(fields=['status']),
        ]


class ComplianceReport(AuditableModel):
    """
    Generated compliance reports for various standards.
    """
    REPORT_TYPES = [
        ('gdpr_compliance', 'GDPR Compliance Report'),
        ('ccpa_compliance', 'CCPA Compliance Report'),
        ('soc2_audit', 'SOC2 Audit Report'),
        ('security_assessment', 'Security Assessment Report'),
        ('data_processing', 'Data Processing Report'),
        ('breach_notification', 'Breach Notification Report'),
    ]
    
    report_id = models.UUIDField(default=uuid.uuid4, unique=True)
    report_type = models.CharField(max_length=30, choices=REPORT_TYPES)
    title = models.CharField(max_length=200)
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    generated_at = models.DateTimeField(default=timezone.now)
    file_path = models.CharField(max_length=500, blank=True)
    file_size_bytes = models.BigIntegerField(null=True, blank=True)
    summary = models.JSONField(default=dict)  # Key metrics and findings
    recommendations = models.JSONField(default=list)
    is_confidential = models.BooleanField(default=True)
    retention_until = models.DateTimeField()
    
    class Meta:
        db_table = 'compliance_report'
        indexes = [
            models.Index(fields=['report_type', 'generated_at']),
            models.Index(fields=['period_start', 'period_end']),
        ]