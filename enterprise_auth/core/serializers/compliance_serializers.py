"""
Serializers for compliance and privacy rights management.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model

from ..models.compliance import (
    DataProcessingPurpose, ConsentRecord, DataExportRequest, DataDeletionRequest,
    DataDisclosureLog, PrivacyPolicyVersion, PrivacyPolicyAcceptance,
    ComplianceAuditLog, SecurityVulnerability, ComplianceReport
)

User = get_user_model()


class DataProcessingPurposeSerializer(serializers.ModelSerializer):
    """
    Serializer for data processing purposes.
    """
    class Meta:
        model = DataProcessingPurpose
        fields = [
            'id', 'name', 'purpose_type', 'description', 'legal_basis',
            'retention_period_days', 'is_essential', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ConsentRecordSerializer(serializers.ModelSerializer):
    """
    Serializer for consent records.
    """
    purpose = DataProcessingPurposeSerializer(read_only=True)
    purpose_name = serializers.CharField(write_only=True)
    
    class Meta:
        model = ConsentRecord
        fields = [
            'id', 'purpose', 'purpose_name', 'status', 'consent_given_at',
            'consent_withdrawn_at', 'expires_at', 'consent_method',
            'consent_text', 'version', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'purpose', 'consent_given_at', 'consent_withdrawn_at',
            'created_at', 'updated_at'
        ]
    
    def validate_purpose_name(self, value):
        """
        Validate that the purpose exists and is active.
        """
        try:
            purpose = DataProcessingPurpose.objects.get(name=value, is_active=True)
            return value
        except DataProcessingPurpose.DoesNotExist:
            raise serializers.ValidationError(f"Invalid or inactive purpose: {value}")


class DataExportRequestSerializer(serializers.ModelSerializer):
    """
    Serializer for data export requests.
    """
    user_email = serializers.EmailField(source='user.email', read_only=True)
    can_download = serializers.SerializerMethodField()
    
    class Meta:
        model = DataExportRequest
        fields = [
            'id', 'request_id', 'user_email', 'status', 'export_format',
            'requested_data_types', 'file_size_bytes', 'download_expires_at',
            'downloaded_at', 'download_count', 'processing_started_at',
            'processing_completed_at', 'error_message', 'can_download',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'request_id', 'user_email', 'status', 'file_size_bytes',
            'downloaded_at', 'download_count', 'processing_started_at',
            'processing_completed_at', 'error_message', 'can_download',
            'created_at', 'updated_at'
        ]
    
    def get_can_download(self, obj):
        """
        Check if the export can be downloaded.
        """
        from django.utils import timezone
        return (obj.status == 'completed' and 
                obj.download_expires_at and 
                obj.download_expires_at > timezone.now())
    
    def validate_export_format(self, value):
        """
        Validate export format.
        """
        valid_formats = ['json', 'csv', 'xml']
        if value not in valid_formats:
            raise serializers.ValidationError(f"Invalid format. Must be one of: {valid_formats}")
        return value
    
    def validate_requested_data_types(self, value):
        """
        Validate requested data types.
        """
        from ..services.data_portability_service import DataPortabilityService
        
        portability_service = DataPortabilityService()
        available_types = set(portability_service.get_available_data_types().keys())
        requested_types = set(value)
        
        invalid_types = requested_types - available_types
        if invalid_types:
            raise serializers.ValidationError(f"Invalid data types: {list(invalid_types)}")
        
        return value


class DataDeletionRequestSerializer(serializers.ModelSerializer):
    """
    Serializer for data deletion requests.
    """
    user_email = serializers.EmailField(source='user.email', read_only=True)
    approved_by_email = serializers.EmailField(source='approved_by.email', read_only=True)
    
    class Meta:
        model = DataDeletionRequest
        fields = [
            'id', 'request_id', 'user_email', 'status', 'deletion_scope',
            'requested_data_types', 'reason', 'legal_basis', 'approved_by_email',
            'approved_at', 'rejection_reason', 'processing_started_at',
            'processing_completed_at', 'deletion_summary', 'retention_exceptions',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'request_id', 'user_email', 'status', 'legal_basis',
            'approved_by_email', 'approved_at', 'processing_started_at',
            'processing_completed_at', 'deletion_summary', 'retention_exceptions',
            'created_at', 'updated_at'
        ]
    
    def validate_deletion_scope(self, value):
        """
        Validate deletion scope.
        """
        valid_scopes = ['full_account', 'specific_data', 'inactive_data']
        if value not in valid_scopes:
            raise serializers.ValidationError(f"Invalid scope. Must be one of: {valid_scopes}")
        return value


class DataDisclosureLogSerializer(serializers.ModelSerializer):
    """
    Serializer for data disclosure logs.
    """
    user_email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = DataDisclosureLog
        fields = [
            'id', 'disclosure_id', 'user_email', 'disclosure_type',
            'recipient_name', 'recipient_contact', 'legal_basis',
            'data_categories', 'purpose', 'disclosure_date',
            'retention_period', 'user_notified', 'user_notification_date',
            'supporting_documents', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'disclosure_id', 'user_email', 'created_at', 'updated_at'
        ]
    
    def validate_disclosure_type(self, value):
        """
        Validate disclosure type.
        """
        valid_types = [
            'legal_request', 'law_enforcement', 'regulatory',
            'service_provider', 'business_transfer', 'user_consent'
        ]
        if value not in valid_types:
            raise serializers.ValidationError(f"Invalid type. Must be one of: {valid_types}")
        return value


class PrivacyPolicyVersionSerializer(serializers.ModelSerializer):
    """
    Serializer for privacy policy versions.
    """
    class Meta:
        model = PrivacyPolicyVersion
        fields = [
            'id', 'version', 'title', 'content', 'effective_date',
            'expiry_date', 'is_current', 'requires_explicit_consent',
            'changes_summary', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class PrivacyPolicyAcceptanceSerializer(serializers.ModelSerializer):
    """
    Serializer for privacy policy acceptances.
    """
    user_email = serializers.EmailField(source='user.email', read_only=True)
    policy_version = PrivacyPolicyVersionSerializer(read_only=True)
    
    class Meta:
        model = PrivacyPolicyAcceptance
        fields = [
            'id', 'user_email', 'policy_version', 'accepted_at',
            'acceptance_method', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'user_email', 'policy_version', 'accepted_at',
            'created_at', 'updated_at'
        ]


class ComplianceAuditLogSerializer(serializers.ModelSerializer):
    """
    Serializer for compliance audit logs.
    """
    user_email = serializers.EmailField(source='user.email', read_only=True)
    
    class Meta:
        model = ComplianceAuditLog
        fields = [
            'id', 'audit_id', 'timestamp', 'activity_type', 'severity',
            'user_email', 'session_id', 'ip_address', 'user_agent',
            'request_id', 'action', 'resource', 'outcome', 'details',
            'before_state', 'after_state', 'checksum'
        ]
        read_only_fields = [
            'id', 'audit_id', 'timestamp', 'user_email', 'checksum'
        ]


class SecurityVulnerabilitySerializer(serializers.ModelSerializer):
    """
    Serializer for security vulnerabilities.
    """
    resolved_by_email = serializers.EmailField(source='resolved_by.email', read_only=True)
    days_open = serializers.SerializerMethodField()
    
    class Meta:
        model = SecurityVulnerability
        fields = [
            'id', 'vulnerability_id', 'title', 'description', 'severity',
            'status', 'cve_id', 'owasp_category', 'affected_components',
            'discovery_method', 'discovered_by', 'discovered_at',
            'remediation_plan', 'remediation_deadline', 'resolved_at',
            'resolved_by_email', 'resolution_notes', 'days_open',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'discovered_at', 'resolved_at', 'resolved_by_email',
            'days_open', 'created_at', 'updated_at'
        ]
    
    def get_days_open(self, obj):
        """
        Calculate days the vulnerability has been open.
        """
        from django.utils import timezone
        
        if obj.status == 'resolved' and obj.resolved_at:
            return (obj.resolved_at - obj.discovered_at).days
        else:
            return (timezone.now() - obj.discovered_at).days
    
    def validate_severity(self, value):
        """
        Validate severity level.
        """
        valid_severities = ['low', 'medium', 'high', 'critical']
        if value not in valid_severities:
            raise serializers.ValidationError(f"Invalid severity. Must be one of: {valid_severities}")
        return value
    
    def validate_status(self, value):
        """
        Validate status.
        """
        valid_statuses = ['open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk']
        if value not in valid_statuses:
            raise serializers.ValidationError(f"Invalid status. Must be one of: {valid_statuses}")
        return value


class ComplianceReportSerializer(serializers.ModelSerializer):
    """
    Serializer for compliance reports.
    """
    generated_by_email = serializers.EmailField(source='generated_by.email', read_only=True)
    
    class Meta:
        model = ComplianceReport
        fields = [
            'id', 'report_id', 'report_type', 'title', 'period_start',
            'period_end', 'generated_by_email', 'generated_at',
            'file_size_bytes', 'summary', 'recommendations',
            'is_confidential', 'retention_until', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'report_id', 'generated_by_email', 'generated_at',
            'file_size_bytes', 'created_at', 'updated_at'
        ]
    
    def validate_report_type(self, value):
        """
        Validate report type.
        """
        valid_types = [
            'gdpr_compliance', 'ccpa_compliance', 'soc2_audit',
            'security_assessment', 'data_processing', 'breach_notification'
        ]
        if value not in valid_types:
            raise serializers.ValidationError(f"Invalid type. Must be one of: {valid_types}")
        return value


class ConsentStatusSerializer(serializers.Serializer):
    """
    Serializer for user consent status response.
    """
    user_id = serializers.UUIDField(read_only=True)
    last_updated = serializers.DateTimeField(read_only=True)
    consent_records = serializers.ListField(read_only=True)
    summary = serializers.DictField(read_only=True)


class DataExportValidationSerializer(serializers.Serializer):
    """
    Serializer for data export validation response.
    """
    valid = serializers.BooleanField(read_only=True)
    errors = serializers.ListField(read_only=True)
    warnings = serializers.ListField(read_only=True)
    data_availability = serializers.DictField(read_only=True)


class SecurityScanResultSerializer(serializers.Serializer):
    """
    Serializer for security scan results.
    """
    scan_id = serializers.CharField(read_only=True)
    scan_type = serializers.CharField(read_only=True)
    started_at = serializers.DateTimeField(read_only=True)
    vulnerabilities_found = serializers.ListField(read_only=True)
    owasp_compliance = serializers.DictField(read_only=True)
    recommendations = serializers.ListField(read_only=True)
    scan_summary = serializers.DictField(read_only=True)


class OWASPComplianceSerializer(serializers.Serializer):
    """
    Serializer for OWASP compliance status.
    """
    overall_compliance_score = serializers.FloatField(read_only=True)
    overall_status = serializers.CharField(read_only=True)
    categories = serializers.DictField(read_only=True)
    last_updated = serializers.DateTimeField(read_only=True)


# Convenience serializer for common compliance operations
class ComplianceSerializer:
    """
    Container class for all compliance serializers.
    """
    DataProcessingPurpose = DataProcessingPurposeSerializer
    ConsentRecord = ConsentRecordSerializer
    DataExportRequest = DataExportRequestSerializer
    DataDeletionRequest = DataDeletionRequestSerializer
    DataDisclosureLog = DataDisclosureLogSerializer
    PrivacyPolicyVersion = PrivacyPolicyVersionSerializer
    PrivacyPolicyAcceptance = PrivacyPolicyAcceptanceSerializer
    ComplianceAuditLog = ComplianceAuditLogSerializer
    SecurityVulnerability = SecurityVulnerabilitySerializer
    ComplianceReport = ComplianceReportSerializer
    ConsentStatus = ConsentStatusSerializer
    DataExportValidation = DataExportValidationSerializer
    SecurityScanResult = SecurityScanResultSerializer
    OWASPCompliance = OWASPComplianceSerializer