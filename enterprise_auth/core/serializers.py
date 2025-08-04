"""
Serializers for enterprise authentication system.

This module contains DRF serializers for user registration, authentication,
and profile management with comprehensive validation.
"""

import re
from typing import Dict, Any

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import UserProfile, UserIdentity, AuditLog, ProfileChangeHistory


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration with comprehensive validation.
    
    Handles user creation with email verification workflow and
    enterprise profile information.
    """
    
    password = serializers.CharField(
        write_only=True,
        min_length=12,
        help_text="Password must be at least 12 characters long"
    )
    password_confirm = serializers.CharField(
        write_only=True,
        help_text="Confirm password"
    )
    terms_accepted = serializers.BooleanField(
        write_only=True,
        help_text="Must accept terms of service"
    )
    privacy_policy_accepted = serializers.BooleanField(
        write_only=True,
        help_text="Must accept privacy policy"
    )
    
    class Meta:
        model = UserProfile
        fields = [
            'email',
            'first_name',
            'last_name',
            'phone_number',
            'organization',
            'department',
            'employee_id',
            'job_title',
            'timezone',
            'language',
            'marketing_consent',
            'password',
            'password_confirm',
            'terms_accepted',
            'privacy_policy_accepted',
        ]
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
            'phone_number': {'required': False},
            'organization': {'required': False},
            'department': {'required': False},
            'employee_id': {'required': False},
            'job_title': {'required': False},
            'timezone': {'required': False},
            'language': {'required': False},
            'marketing_consent': {'required': False, 'default': False},
        }
    
    def validate_email(self, value: str) -> str:
        """
        Validate email address format and uniqueness.
        
        Args:
            value: Email address to validate
            
        Returns:
            Validated email address
            
        Raises:
            ValidationError: If email is invalid or already exists
        """
        # Normalize email
        value = value.lower().strip()
        
        # Check for basic email format
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, value):
            raise ValidationError(_('Invalid email address format.'))
        
        # Check for disposable email domains (basic list)
        disposable_domains = [
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org'
        ]
        domain = value.split('@')[1].lower()
        if domain in disposable_domains:
            raise ValidationError(_('Disposable email addresses are not allowed.'))
        
        # Check uniqueness
        if UserProfile.objects.filter(email=value).exists():
            raise ValidationError(_('A user with this email address already exists.'))
        
        return value
    
    def validate_first_name(self, value: str) -> str:
        """
        Validate first name.
        
        Args:
            value: First name to validate
            
        Returns:
            Validated first name
            
        Raises:
            ValidationError: If first name is invalid
        """
        value = value.strip()
        
        if len(value) < 2:
            raise ValidationError(_('First name must be at least 2 characters long.'))
        
        if len(value) > 150:
            raise ValidationError(_('First name must be less than 150 characters.'))
        
        # Check for valid characters (letters, spaces, hyphens, apostrophes)
        if not re.match(r"^[a-zA-Z\s\-']+$", value):
            raise ValidationError(_('First name can only contain letters, spaces, hyphens, and apostrophes.'))
        
        return value
    
    def validate_last_name(self, value: str) -> str:
        """
        Validate last name.
        
        Args:
            value: Last name to validate
            
        Returns:
            Validated last name
            
        Raises:
            ValidationError: If last name is invalid
        """
        value = value.strip()
        
        if len(value) < 2:
            raise ValidationError(_('Last name must be at least 2 characters long.'))
        
        if len(value) > 150:
            raise ValidationError(_('Last name must be less than 150 characters.'))
        
        # Check for valid characters (letters, spaces, hyphens, apostrophes)
        if not re.match(r"^[a-zA-Z\s\-']+$", value):
            raise ValidationError(_('Last name can only contain letters, spaces, hyphens, and apostrophes.'))
        
        return value
    
    def validate_phone_number(self, value: str) -> str:
        """
        Validate phone number format.
        
        Args:
            value: Phone number to validate
            
        Returns:
            Validated phone number
            
        Raises:
            ValidationError: If phone number is invalid
        """
        if not value:
            return value
        
        # Remove all non-digit characters except +
        cleaned = re.sub(r'[^\d+]', '', value)
        
        # Check format
        if not re.match(r'^\+?1?\d{9,15}$', cleaned):
            raise ValidationError(
                _('Phone number must be in international format (e.g., +1234567890) and contain 9-15 digits.')
            )
        
        return cleaned
    
    def validate_employee_id(self, value: str) -> str:
        """
        Validate employee ID format.
        
        Args:
            value: Employee ID to validate
            
        Returns:
            Validated employee ID
            
        Raises:
            ValidationError: If employee ID is invalid
        """
        if not value:
            return value
        
        value = value.strip()
        
        # Check length
        if len(value) < 2 or len(value) > 100:
            raise ValidationError(_('Employee ID must be between 2 and 100 characters.'))
        
        # Check for valid characters (alphanumeric, hyphens, underscores)
        if not re.match(r'^[a-zA-Z0-9\-_]+$', value):
            raise ValidationError(_('Employee ID can only contain letters, numbers, hyphens, and underscores.'))
        
        return value
    
    def validate_organization(self, value: str) -> str:
        """
        Validate organization name.
        
        Args:
            value: Organization name to validate
            
        Returns:
            Validated organization name
            
        Raises:
            ValidationError: If organization name is invalid
        """
        if not value:
            return value
        
        value = value.strip()
        
        if len(value) < 2:
            raise ValidationError(_('Organization name must be at least 2 characters long.'))
        
        if len(value) > 255:
            raise ValidationError(_('Organization name must be less than 255 characters.'))
        
        return value
    
    def validate_password(self, value: str) -> str:
        """
        Validate password strength.
        
        Args:
            value: Password to validate
            
        Returns:
            Validated password
            
        Raises:
            ValidationError: If password is invalid
        """
        # Use Django's built-in password validators
        try:
            validate_password(value)
        except DjangoValidationError as e:
            raise ValidationError(list(e.messages))
        
        # Additional custom validation
        if len(value) < 12:
            raise ValidationError(_('Password must be at least 12 characters long.'))
        
        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', value):
            raise ValidationError(_('Password must contain at least one uppercase letter.'))
        
        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', value):
            raise ValidationError(_('Password must contain at least one lowercase letter.'))
        
        # Check for at least one digit
        if not re.search(r'\d', value):
            raise ValidationError(_('Password must contain at least one digit.'))
        
        # Check for at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise ValidationError(_('Password must contain at least one special character.'))
        
        return value
    
    def validate_terms_accepted(self, value: bool) -> bool:
        """
        Validate that terms of service are accepted.
        
        Args:
            value: Terms acceptance status
            
        Returns:
            Validated terms acceptance
            
        Raises:
            ValidationError: If terms are not accepted
        """
        if not value:
            raise ValidationError(_('You must accept the terms of service to register.'))
        return value
    
    def validate_privacy_policy_accepted(self, value: bool) -> bool:
        """
        Validate that privacy policy is accepted.
        
        Args:
            value: Privacy policy acceptance status
            
        Returns:
            Validated privacy policy acceptance
            
        Raises:
            ValidationError: If privacy policy is not accepted
        """
        if not value:
            raise ValidationError(_('You must accept the privacy policy to register.'))
        return value
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate the entire registration data.
        
        Args:
            attrs: Registration data
            
        Returns:
            Validated data
            
        Raises:
            ValidationError: If validation fails
        """
        # Check password confirmation
        password = attrs.get('password')
        password_confirm = attrs.get('password_confirm')
        
        if password != password_confirm:
            raise ValidationError({
                'password_confirm': _('Password confirmation does not match.')
            })
        
        # Validate employee ID uniqueness within organization
        employee_id = attrs.get('employee_id')
        organization = attrs.get('organization')
        
        if employee_id and organization:
            if UserProfile.objects.filter(
                employee_id=employee_id,
                organization=organization
            ).exists():
                raise ValidationError({
                    'employee_id': _('This employee ID already exists in the organization.')
                })
        
        # Remove password_confirm from validated data
        attrs.pop('password_confirm', None)
        
        return attrs
    
    def create(self, validated_data: Dict[str, Any]) -> UserProfile:
        """
        Create a new user with email verification workflow.
        
        Args:
            validated_data: Validated registration data
            
        Returns:
            Created UserProfile instance
        """
        # Remove non-model fields
        terms_accepted = validated_data.pop('terms_accepted')
        privacy_policy_accepted = validated_data.pop('privacy_policy_accepted')
        password = validated_data.pop('password')
        
        # Set acceptance timestamps
        from django.utils import timezone
        validated_data['terms_accepted_at'] = timezone.now()
        validated_data['privacy_policy_accepted_at'] = timezone.now()
        
        # Create user
        user = UserProfile.objects.create_user(
            password=password,
            **validated_data
        )
        
        # Send verification email using the service
        from .services.email_verification_service import EmailVerificationService
        email_service = EmailVerificationService()
        email_service.send_verification_email(user, resend=False)
        
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile information.
    
    Used for retrieving and updating user profile data.
    """
    
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    is_fully_verified = serializers.BooleanField(read_only=True)
    has_enterprise_profile = serializers.BooleanField(read_only=True)
    is_account_locked = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'id',
            'email',
            'first_name',
            'last_name',
            'full_name',
            'phone_number',
            'is_email_verified',
            'is_phone_verified',
            'is_fully_verified',
            'organization',
            'department',
            'employee_id',
            'job_title',
            'profile_picture_url',
            'timezone',
            'language',
            'marketing_consent',
            'has_enterprise_profile',
            'is_account_locked',
            'last_login',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'email',
            'is_email_verified',
            'is_phone_verified',
            'is_fully_verified',
            'has_enterprise_profile',
            'is_account_locked',
            'last_login',
            'created_at',
            'updated_at',
        ]
    
    def validate_first_name(self, value: str) -> str:
        """Validate first name."""
        return UserRegistrationSerializer().validate_first_name(value)
    
    def validate_last_name(self, value: str) -> str:
        """Validate last name."""
        return UserRegistrationSerializer().validate_last_name(value)
    
    def validate_phone_number(self, value: str) -> str:
        """Validate phone number."""
        return UserRegistrationSerializer().validate_phone_number(value)
    
    def validate_employee_id(self, value: str) -> str:
        """Validate employee ID."""
        return UserRegistrationSerializer().validate_employee_id(value)
    
    def validate_organization(self, value: str) -> str:
        """Validate organization name."""
        return UserRegistrationSerializer().validate_organization(value)


class UserIdentitySerializer(serializers.ModelSerializer):
    """
    Serializer for user identity (OAuth provider) information.
    
    Used for displaying linked social accounts.
    """
    
    provider_display_name = serializers.SerializerMethodField()
    is_token_expired = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = UserIdentity
        fields = [
            'id',
            'provider',
            'provider_display_name',
            'provider_username',
            'provider_email',
            'is_primary',
            'is_verified',
            'is_token_expired',
            'linked_at',
            'last_used',
        ]
        read_only_fields = [
            'id',
            'provider',
            'provider_username',
            'provider_email',
            'is_verified',
            'is_token_expired',
            'linked_at',
            'last_used',
        ]
    
    def get_provider_display_name(self, obj: UserIdentity) -> str:
        """
        Get the display name for the OAuth provider.
        
        Args:
            obj: UserIdentity instance
            
        Returns:
            Human-readable provider name
        """
        provider_names = {
            'google': 'Google',
            'github': 'GitHub',
            'microsoft': 'Microsoft',
            'apple': 'Apple',
            'linkedin': 'LinkedIn',
            'facebook': 'Facebook',
            'twitter': 'Twitter',
            'custom': 'Custom Provider',
        }
        return provider_names.get(obj.provider, obj.provider.title())


class EmailVerificationSerializer(serializers.Serializer):
    """
    Serializer for email verification.
    
    Handles email verification token validation.
    """
    
    user_id = serializers.UUIDField(
        help_text="User ID for verification"
    )
    token = serializers.CharField(
        max_length=255,
        help_text="Email verification token"
    )
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate the verification data.
        
        Args:
            attrs: Verification data
            
        Returns:
            Validated data
            
        Raises:
            ValidationError: If verification fails
        """
        user_id = attrs.get('user_id')
        token = attrs.get('token')
        
        # Basic validation - actual verification is done in the service
        if not user_id or not token:
            raise ValidationError(_('User ID and token are required.'))
        
        return attrs


class ResendVerificationSerializer(serializers.Serializer):
    """
    Serializer for resending email verification.
    
    Handles resending verification emails with rate limiting.
    """
    
    email = serializers.EmailField(
        help_text="Email address to resend verification to"
    )
    
    def validate_email(self, value: str) -> str:
        """
        Validate email address and check if resend is allowed.
        
        Args:
            value: Email address
            
        Returns:
            Validated email address
            
        Raises:
            ValidationError: If email is invalid or resend not allowed
        """
        value = value.lower().strip()
        
        # Check if user exists and is not verified
        try:
            user = UserProfile.objects.get(email=value, is_email_verified=False)
        except UserProfile.DoesNotExist:
            raise ValidationError(_('No unverified user found with this email address.'))
        
        # Check rate limiting
        if user.email_verification_sent_at:
            from django.utils import timezone
            time_since_last = timezone.now() - user.email_verification_sent_at
            if time_since_last.total_seconds() < 300:  # 5 minutes
                raise ValidationError(_('Please wait before requesting another verification email.'))
        
        return value


class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for password change.
    
    Handles password change with current password verification.
    """
    
    current_password = serializers.CharField(
        write_only=True,
        help_text="Current password for verification"
    )
    new_password = serializers.CharField(
        write_only=True,
        min_length=12,
        help_text="New password"
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        help_text="Confirm new password"
    )
    
    def validate_current_password(self, value: str) -> str:
        """
        Validate current password.
        
        Args:
            value: Current password
            
        Returns:
            Validated current password
            
        Raises:
            ValidationError: If current password is incorrect
        """
        user = self.context['request'].user
        if not user.check_password(value):
            raise ValidationError(_('Current password is incorrect.'))
        return value
    
    def validate_new_password(self, value: str) -> str:
        """
        Validate new password strength.
        
        Args:
            value: New password to validate
            
        Returns:
            Validated new password
            
        Raises:
            ValidationError: If new password is invalid
        """
        return UserRegistrationSerializer().validate_password(value)
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate the password change data.
        
        Args:
            attrs: Password change data
            
        Returns:
            Validated data
            
        Raises:
            ValidationError: If validation fails
        """
        current_password = attrs.get('current_password')
        new_password = attrs.get('new_password')
        new_password_confirm = attrs.get('new_password_confirm')
        
        # Check if new password is different from current
        if current_password == new_password:
            raise ValidationError({
                'new_password': _('New password must be different from current password.')
            })
        
        # Check password confirmation
        if new_password != new_password_confirm:
            raise ValidationError({
                'new_password_confirm': _('New password confirmation does not match.')
            })
        
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for password reset request.
    
    Handles password reset initiation with email validation.
    """
    
    email = serializers.EmailField(
        help_text="Email address for password reset"
    )
    
    def validate_email(self, value: str) -> str:
        """
        Validate email format.
        
        Args:
            value: Email address
            
        Returns:
            Validated email address
        """
        return value.lower().strip()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for password reset confirmation.
    
    Handles password reset completion with token validation.
    """
    
    token = serializers.CharField(
        help_text="Password reset token"
    )
    new_password = serializers.CharField(
        write_only=True,
        min_length=12,
        help_text="New password"
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        help_text="Confirm new password"
    )
    
    def validate_new_password(self, value: str) -> str:
        """
        Validate new password strength.
        
        Args:
            value: New password to validate
            
        Returns:
            Validated new password
            
        Raises:
            ValidationError: If new password is invalid
        """
        from .utils.password import password_policy
        
        # Get basic validation without user context
        validation_result = password_policy.validate_password(value)
        
        if not validation_result['is_valid']:
            raise ValidationError(validation_result['errors'])
        
        return value
    
    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate the password reset data.
        
        Args:
            attrs: Password reset data
            
        Returns:
            Validated data
            
        Raises:
            ValidationError: If validation fails
        """
        new_password = attrs.get('new_password')
        new_password_confirm = attrs.get('new_password_confirm')
        
        # Check password confirmation
        if new_password != new_password_confirm:
            raise ValidationError({
                'new_password_confirm': _('New password confirmation does not match.')
            })
        
        return attrs


class PasswordStrengthCheckSerializer(serializers.Serializer):
    """
    Serializer for password strength checking.
    
    Provides real-time password strength feedback.
    """
    
    password = serializers.CharField(
        write_only=True,
        help_text="Password to check strength"
    )
    
    def validate_password(self, value: str) -> str:
        """
        Basic password validation.
        
        Args:
            value: Password to validate
            
        Returns:
            Password value
        """
        return value


class AuditLogSerializer(serializers.ModelSerializer):
    """
    Serializer for audit log entries.
    
    Used for displaying audit logs to users for transparency
    and compliance purposes.
    """
    
    user_email = serializers.CharField(read_only=True)
    changes_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = AuditLog
        fields = [
            'id',
            'event_type',
            'event_description',
            'severity',
            'user_email',
            'ip_address',
            'user_agent',
            'request_id',
            'session_id',
            'old_values',
            'new_values',
            'changes_summary',
            'metadata',
            'created_at',
        ]
        read_only_fields = [
            'id',
            'event_type',
            'event_description',
            'severity',
            'user_email',
            'ip_address',
            'user_agent',
            'request_id',
            'session_id',
            'old_values',
            'new_values',
            'metadata',
            'created_at',
        ]
    
    def get_changes_summary(self, obj: AuditLog) -> Dict[str, Any]:
        """
        Get a summary of changes made in this audit log.
        
        Args:
            obj: AuditLog instance
            
        Returns:
            Dictionary with change summary
        """
        return obj.get_changes_summary()


class ProfileChangeHistorySerializer(serializers.ModelSerializer):
    """
    Serializer for profile change history entries.
    
    Used for displaying detailed profile change history
    to users for transparency.
    """
    
    user_email = serializers.CharField(source='user.email', read_only=True)
    changed_by_email = serializers.CharField(source='changed_by.email', read_only=True)
    
    class Meta:
        model = ProfileChangeHistory
        fields = [
            'id',
            'user_email',
            'changed_by_email',
            'field_name',
            'old_value',
            'new_value',
            'ip_address',
            'user_agent',
            'request_id',
            'created_at',
        ]
        read_only_fields = [
            'id',
            'user_email',
            'changed_by_email',
            'field_name',
            'old_value',
            'new_value',
            'ip_address',
            'user_agent',
            'request_id',
            'created_at',
        ]


class DataExportSerializer(serializers.Serializer):
    """
    Serializer for data export requests (GDPR compliance).
    
    Handles requests for user data export.
    """
    
    include_sensitive = serializers.BooleanField(
        default=False,
        help_text="Whether to include sensitive audit logs in export"
    )
    export_format = serializers.ChoiceField(
        choices=[('json', 'JSON'), ('csv', 'CSV')],
        default='json',
        help_text="Format for data export"
    )
    
    def validate_include_sensitive(self, value: bool) -> bool:
        """
        Validate sensitive data inclusion request.
        
        Args:
            value: Whether to include sensitive data
            
        Returns:
            Validated value
        """
        # Only allow sensitive data export for the user themselves
        request = self.context.get('request')
        if value and request and not request.user.is_staff:
            # Regular users can only export their own non-sensitive data
            return False
        return value


class ProfileUpdateAuditSerializer(serializers.Serializer):
    """
    Serializer for profile update audit information.
    
    Used internally for audit logging of profile changes.
    """
    
    old_values = serializers.JSONField(
        help_text="Previous values before update"
    )
    new_values = serializers.JSONField(
        help_text="New values after update"
    )
    changed_fields = serializers.ListField(
        child=serializers.CharField(),
        help_text="List of fields that were changed"
    )
    request_info = serializers.JSONField(
        help_text="Request metadata for audit trail"
    )
    
    def validate_old_values(self, value: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate old values data.
        
        Args:
            value: Old values dictionary
            
        Returns:
            Validated old values
        """
        # Filter out sensitive fields
        sensitive_fields = {'password', 'password_reset_token', 'email_verification_token'}
        return {k: v for k, v in value.items() if k not in sensitive_fields}
    
    def validate_new_values(self, value: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate new values data.
        
        Args:
            value: New values dictionary
            
        Returns:
            Validated new values
        """
        # Filter out sensitive fields
        sensitive_fields = {'password', 'password_reset_token', 'email_verification_token'}
        return {k: v for k, v in value.items() if k not in sensitive_fields}


class ComplianceReportSerializer(serializers.Serializer):
    """
    Serializer for compliance reporting data.
    
    Used for generating compliance reports for audits.
    """
    
    user_id = serializers.UUIDField(read_only=True)
    user_email = serializers.EmailField(read_only=True)
    report_type = serializers.CharField(read_only=True)
    generated_at = serializers.DateTimeField(read_only=True)
    
    # Profile data
    profile_created_at = serializers.DateTimeField(read_only=True)
    profile_updated_at = serializers.DateTimeField(read_only=True)
    email_verified = serializers.BooleanField(read_only=True)
    phone_verified = serializers.BooleanField(read_only=True)
    
    # Audit statistics
    total_audit_logs = serializers.IntegerField(read_only=True)
    total_profile_changes = serializers.IntegerField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)
    last_profile_update = serializers.DateTimeField(read_only=True)
    
    # Compliance flags
    gdpr_compliant = serializers.BooleanField(read_only=True)
    data_retention_compliant = serializers.BooleanField(read_only=True)
    audit_trail_complete = serializers.BooleanField(read_only=True)