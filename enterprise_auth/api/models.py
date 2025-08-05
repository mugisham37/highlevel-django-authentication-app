"""
API Integration Models

This module contains models for API key management, webhook endpoints,
and delivery tracking.
"""
import uuid
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import URLValidator
from django.utils import timezone
from django.db import models

from enterprise_auth.core.models.base import BaseModel
from enterprise_auth.core.utils.encryption import encrypt_data, decrypt_data


User = get_user_model()


class APIKeyScope(models.TextChoices):
    """Available API key scopes."""
    READ_ONLY = 'read_only', 'Read Only'
    READ_WRITE = 'read_write', 'Read Write'
    ADMIN = 'admin', 'Admin'
    WEBHOOK_ONLY = 'webhook_only', 'Webhook Only'


class APIKeyTier(models.TextChoices):
    """API key tiers for rate limiting."""
    BASIC = 'basic', 'Basic'
    PREMIUM = 'premium', 'Premium'
    ENTERPRISE = 'enterprise', 'Enterprise'


class APIKey(BaseModel):
    """
    API Key model for external system authentication.
    
    Supports scoped access, rate limiting tiers, and comprehensive tracking.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, help_text="Human-readable name for the API key")
    description = models.TextField(blank=True, help_text="Description of the API key purpose")
    
    # Key management
    key_id = models.CharField(max_length=32, unique=True, editable=False)
    key_hash = models.CharField(max_length=128, editable=False)
    key_prefix = models.CharField(max_length=8, editable=False)
    
    # Ownership and organization
    created_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='created_api_keys'
    )
    organization = models.CharField(max_length=255, blank=True)
    
    # Access control
    scopes = models.JSONField(default=list, help_text="List of allowed scopes")
    tier = models.CharField(
        max_length=20, 
        choices=APIKeyTier.choices, 
        default=APIKeyTier.BASIC
    )
    allowed_ips = models.JSONField(
        default=list, 
        blank=True,
        help_text="List of allowed IP addresses (empty = all IPs allowed)"
    )
    
    # Status and lifecycle
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    usage_count = models.PositiveIntegerField(default=0)
    
    # Rate limiting
    rate_limit_per_minute = models.PositiveIntegerField(default=60)
    rate_limit_per_hour = models.PositiveIntegerField(default=1000)
    rate_limit_per_day = models.PositiveIntegerField(default=10000)

    class Meta:
        db_table = 'api_keys'
        indexes = [
            models.Index(fields=['key_id']),
            models.Index(fields=['created_by', 'is_active']),
            models.Index(fields=['tier', 'is_active']),
        ]

    def __str__(self):
        return f"{self.name} ({self.key_prefix}...)"

    def save(self, *args, **kwargs):
        """Generate API key on creation."""
        if not self.key_id:
            self.generate_key()
        super().save(*args, **kwargs)

    def generate_key(self) -> str:
        """Generate a new API key."""
        # Generate a secure random key
        raw_key = secrets.token_urlsafe(32)
        
        # Create key ID and prefix
        self.key_id = secrets.token_hex(16)
        self.key_prefix = raw_key[:8]
        
        # Hash the key for storage
        self.key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        # Return the raw key (only time it's available in plain text)
        return f"ea_{self.key_id}_{raw_key}"

    def verify_key(self, provided_key: str) -> bool:
        """Verify a provided API key against the stored hash."""
        if not provided_key.startswith(f"ea_{self.key_id}_"):
            return False
        
        # Extract the raw key part
        raw_key = provided_key[len(f"ea_{self.key_id}_"):]
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        
        return key_hash == self.key_hash

    def is_expired(self) -> bool:
        """Check if the API key is expired."""
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at

    def can_access_scope(self, scope: str) -> bool:
        """Check if the API key has access to a specific scope."""
        return scope in self.scopes

    def is_ip_allowed(self, ip_address: str) -> bool:
        """Check if an IP address is allowed to use this API key."""
        if not self.allowed_ips:
            return True
        return ip_address in self.allowed_ips

    def record_usage(self):
        """Record API key usage."""
        self.last_used_at = timezone.now()
        self.usage_count += 1
        self.save(update_fields=['last_used_at', 'usage_count'])


class WebhookEndpoint(BaseModel):
    """
    Webhook endpoint registration and configuration.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, help_text="Human-readable name for the webhook")
    description = models.TextField(blank=True)
    
    # Endpoint configuration
    url = models.URLField(validators=[URLValidator()])
    secret_key = models.CharField(max_length=64, editable=False)
    
    # Ownership
    created_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='webhook_endpoints'
    )
    organization = models.CharField(max_length=255, blank=True)
    
    # Event subscriptions
    subscribed_events = models.JSONField(
        default=list,
        help_text="List of event types this endpoint subscribes to"
    )
    
    # Configuration
    headers = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional headers to send with webhook requests"
    )
    timeout_seconds = models.PositiveIntegerField(default=30)
    max_retries = models.PositiveIntegerField(default=3)
    
    # Status
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(max_length=64, blank=True)
    
    # Statistics
    total_deliveries = models.PositiveIntegerField(default=0)
    successful_deliveries = models.PositiveIntegerField(default=0)
    failed_deliveries = models.PositiveIntegerField(default=0)
    last_delivery_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'webhook_endpoints'
        indexes = [
            models.Index(fields=['created_by', 'is_active']),
            models.Index(fields=['organization', 'is_active']),
        ]

    def __str__(self):
        return f"{self.name} - {self.url}"

    def save(self, *args, **kwargs):
        """Generate secret key on creation."""
        if not self.secret_key:
            self.secret_key = secrets.token_urlsafe(32)
        if not self.verification_token:
            self.verification_token = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)

    def is_subscribed_to_event(self, event_type: str) -> bool:
        """Check if endpoint is subscribed to a specific event type."""
        return event_type in self.subscribed_events

    def generate_signature(self, payload: bytes, timestamp: str) -> str:
        """Generate webhook signature for payload verification."""
        import hmac
        
        message = f"{timestamp}.{payload.decode()}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"t={timestamp},v1={signature}"

    def verify_signature(self, payload: bytes, signature: str, timestamp: str) -> bool:
        """Verify webhook signature."""
        expected_signature = self.generate_signature(payload, timestamp)
        return hmac.compare_digest(signature, expected_signature)


class WebhookEventType(models.TextChoices):
    """Available webhook event types."""
    USER_CREATED = 'user.created', 'User Created'
    USER_UPDATED = 'user.updated', 'User Updated'
    USER_DELETED = 'user.deleted', 'User Deleted'
    USER_LOGIN = 'user.login', 'User Login'
    USER_LOGOUT = 'user.logout', 'User Logout'
    USER_PASSWORD_CHANGED = 'user.password_changed', 'User Password Changed'
    USER_EMAIL_VERIFIED = 'user.email_verified', 'User Email Verified'
    USER_MFA_ENABLED = 'user.mfa_enabled', 'User MFA Enabled'
    USER_MFA_DISABLED = 'user.mfa_disabled', 'User MFA Disabled'
    SESSION_CREATED = 'session.created', 'Session Created'
    SESSION_TERMINATED = 'session.terminated', 'Session Terminated'
    SECURITY_ALERT = 'security.alert', 'Security Alert'
    ROLE_ASSIGNED = 'role.assigned', 'Role Assigned'
    ROLE_REVOKED = 'role.revoked', 'Role Revoked'


class WebhookDeliveryStatus(models.TextChoices):
    """Webhook delivery status options."""
    PENDING = 'pending', 'Pending'
    DELIVERED = 'delivered', 'Delivered'
    FAILED = 'failed', 'Failed'
    RETRYING = 'retrying', 'Retrying'
    ABANDONED = 'abandoned', 'Abandoned'


class WebhookDelivery(BaseModel):
    """
    Webhook delivery tracking and status.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Relationship
    endpoint = models.ForeignKey(
        WebhookEndpoint,
        on_delete=models.CASCADE,
        related_name='deliveries'
    )
    
    # Event details
    event_type = models.CharField(
        max_length=50,
        choices=WebhookEventType.choices
    )
    event_id = models.UUIDField(help_text="Unique identifier for the event")
    payload = models.JSONField(help_text="Event payload data")
    
    # Delivery tracking
    status = models.CharField(
        max_length=20,
        choices=WebhookDeliveryStatus.choices,
        default=WebhookDeliveryStatus.PENDING
    )
    attempt_count = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=3)
    
    # Response tracking
    response_status_code = models.PositiveIntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    
    # Timing
    scheduled_at = models.DateTimeField(default=timezone.now)
    first_attempted_at = models.DateTimeField(null=True, blank=True)
    last_attempted_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    next_retry_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'webhook_deliveries'
        indexes = [
            models.Index(fields=['endpoint', 'status']),
            models.Index(fields=['event_type', 'created_at']),
            models.Index(fields=['status', 'scheduled_at']),
            models.Index(fields=['next_retry_at']),
        ]

    def __str__(self):
        return f"{self.event_type} -> {self.endpoint.name} ({self.status})"

    def should_retry(self) -> bool:
        """Check if delivery should be retried."""
        return (
            self.status in [WebhookDeliveryStatus.FAILED, WebhookDeliveryStatus.RETRYING] and
            self.attempt_count < self.max_attempts and
            self.next_retry_at and
            timezone.now() >= self.next_retry_at
        )

    def calculate_next_retry(self) -> Optional[datetime]:
        """Calculate next retry time using exponential backoff."""
        if self.attempt_count >= self.max_attempts:
            return None
        
        # Exponential backoff: 2^attempt_count minutes
        delay_minutes = 2 ** self.attempt_count
        return timezone.now() + timedelta(minutes=delay_minutes)

    def mark_delivered(self, status_code: int, headers: Dict, body: str):
        """Mark delivery as successful."""
        self.status = WebhookDeliveryStatus.DELIVERED
        self.response_status_code = status_code
        self.response_headers = headers
        self.response_body = body
        self.delivered_at = timezone.now()
        self.save()

    def mark_failed(self, error_message: str, status_code: int = None, 
                   headers: Dict = None, body: str = ""):
        """Mark delivery as failed and schedule retry if applicable."""
        self.attempt_count += 1
        self.last_attempted_at = timezone.now()
        self.error_message = error_message
        
        if status_code:
            self.response_status_code = status_code
        if headers:
            self.response_headers = headers
        if body:
            self.response_body = body
        
        if self.attempt_count >= self.max_attempts:
            self.status = WebhookDeliveryStatus.ABANDONED
            self.next_retry_at = None
        else:
            self.status = WebhookDeliveryStatus.RETRYING
            self.next_retry_at = self.calculate_next_retry()
        
        self.save()


class APIRequestLog(BaseModel):
    """
    API request and response logging for monitoring and analytics.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Request identification
    request_id = models.CharField(max_length=64, unique=True)
    api_key = models.ForeignKey(
        APIKey,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='request_logs'
    )
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='api_request_logs'
    )
    
    # Request details
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=500)
    query_params = models.JSONField(default=dict, blank=True)
    headers = models.JSONField(default=dict, blank=True)
    body_size = models.PositiveIntegerField(default=0)
    
    # Client information
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Response details
    status_code = models.PositiveIntegerField()
    response_size = models.PositiveIntegerField(default=0)
    response_time_ms = models.PositiveIntegerField(help_text="Response time in milliseconds")
    
    # Error tracking
    error_type = models.CharField(max_length=100, blank=True)
    error_message = models.TextField(blank=True)

    class Meta:
        db_table = 'api_request_logs'
        indexes = [
            models.Index(fields=['api_key', 'created_at']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['status_code', 'created_at']),
            models.Index(fields=['path', 'method']),
            models.Index(fields=['ip_address', 'created_at']),
        ]

    def __str__(self):
        return f"{self.method} {self.path} - {self.status_code}"