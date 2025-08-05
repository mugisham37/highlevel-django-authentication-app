"""
API Serializers

Comprehensive serializers for API endpoints with validation,
pagination, filtering, and sorting support.
"""
from typing import Dict, Any, List, Optional
from rest_framework import serializers
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.core.validators import URLValidator
from django.utils import timezone

from .models import (
    APIKey, WebhookEndpoint, WebhookDelivery, APIRequestLog,
    APIKeyScope, APIKeyTier, WebhookEventType, WebhookDeliveryStatus
)

User = get_user_model()


class StandardResultsSetPagination(PageNumberPagination):
    """Standard pagination class for API responses."""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            'pagination': {
                'count': self.page.paginator.count,
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'page_size': self.page_size,
                'total_pages': self.page.paginator.num_pages,
                'current_page': self.page.number,
            },
            'results': data
        })


class APIKeySerializer(serializers.ModelSerializer):
    """Serializer for API Key management."""
    
    # Read-only fields
    key_id = serializers.CharField(read_only=True)
    key_prefix = serializers.CharField(read_only=True)
    created_by = serializers.StringRelatedField(read_only=True)
    usage_count = serializers.IntegerField(read_only=True)
    last_used_at = serializers.DateTimeField(read_only=True)
    
    # Write-only field for key generation
    generated_key = serializers.CharField(read_only=True)
    
    # Validation fields
    scopes = serializers.ListField(
        child=serializers.ChoiceField(choices=APIKeyScope.choices),
        allow_empty=False
    )
    tier = serializers.ChoiceField(choices=APIKeyTier.choices)
    allowed_ips = serializers.ListField(
        child=serializers.IPAddressField(),
        required=False,
        allow_empty=True
    )

    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'description', 'key_id', 'key_prefix', 'generated_key',
            'created_by', 'organization', 'scopes', 'tier', 'allowed_ips',
            'is_active', 'expires_at', 'last_used_at', 'usage_count',
            'rate_limit_per_minute', 'rate_limit_per_hour', 'rate_limit_per_day',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'key_id', 'key_prefix', 'created_by', 'usage_count',
            'last_used_at', 'created_at', 'updated_at'
        ]

    def validate_expires_at(self, value):
        """Validate expiration date is in the future."""
        if value and value <= timezone.now():
            raise serializers.ValidationError("Expiration date must be in the future.")
        return value

    def validate_scopes(self, value):
        """Validate scopes are valid and not conflicting."""
        if not value:
            raise serializers.ValidationError("At least one scope must be specified.")
        
        # Check for conflicting scopes
        if APIKeyScope.ADMIN in value and len(value) > 1:
            raise serializers.ValidationError("Admin scope cannot be combined with other scopes.")
        
        return value

    def create(self, validated_data):
        """Create API key and return generated key."""
        api_key = APIKey.objects.create(**validated_data)
        generated_key = api_key.generate_key()
        api_key.generated_key = generated_key
        return api_key

    def to_representation(self, instance):
        """Customize representation based on context."""
        data = super().to_representation(instance)
        
        # Only include generated key on creation
        if not hasattr(instance, 'generated_key'):
            data.pop('generated_key', None)
        
        return data


class APIKeyListSerializer(serializers.ModelSerializer):
    """Simplified serializer for API key listing."""
    
    created_by = serializers.StringRelatedField(read_only=True)
    is_expired = serializers.SerializerMethodField()
    
    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'key_prefix', 'created_by', 'organization',
            'tier', 'is_active', 'is_expired', 'expires_at', 'last_used_at',
            'usage_count', 'created_at'
        ]

    def get_is_expired(self, obj):
        """Check if API key is expired."""
        return obj.is_expired()


class WebhookEndpointSerializer(serializers.ModelSerializer):
    """Serializer for webhook endpoint management."""
    
    created_by = serializers.StringRelatedField(read_only=True)
    secret_key = serializers.CharField(read_only=True)
    verification_token = serializers.CharField(read_only=True)
    
    # Statistics
    success_rate = serializers.SerializerMethodField()
    
    subscribed_events = serializers.ListField(
        child=serializers.ChoiceField(choices=WebhookEventType.choices),
        allow_empty=False
    )

    class Meta:
        model = WebhookEndpoint
        fields = [
            'id', 'name', 'description', 'url', 'secret_key', 'verification_token',
            'created_by', 'organization', 'subscribed_events', 'headers',
            'timeout_seconds', 'max_retries', 'is_active', 'is_verified',
            'total_deliveries', 'successful_deliveries', 'failed_deliveries',
            'success_rate', 'last_delivery_at', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'secret_key', 'verification_token', 'created_by',
            'total_deliveries', 'successful_deliveries', 'failed_deliveries',
            'last_delivery_at', 'created_at', 'updated_at'
        ]

    def get_success_rate(self, obj):
        """Calculate webhook success rate."""
        if obj.total_deliveries == 0:
            return 0.0
        return round((obj.successful_deliveries / obj.total_deliveries) * 100, 2)

    def validate_url(self, value):
        """Validate webhook URL."""
        validator = URLValidator()
        validator(value)
        
        # Additional validation for webhook URLs
        if not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("URL must use HTTP or HTTPS protocol.")
        
        return value

    def validate_subscribed_events(self, value):
        """Validate subscribed events."""
        if not value:
            raise serializers.ValidationError("At least one event must be subscribed.")
        
        return value

    def validate_timeout_seconds(self, value):
        """Validate timeout is reasonable."""
        if value < 1 or value > 300:
            raise serializers.ValidationError("Timeout must be between 1 and 300 seconds.")
        return value

    def validate_max_retries(self, value):
        """Validate max retries is reasonable."""
        if value < 0 or value > 10:
            raise serializers.ValidationError("Max retries must be between 0 and 10.")
        return value


class WebhookEndpointListSerializer(serializers.ModelSerializer):
    """Simplified serializer for webhook endpoint listing."""
    
    created_by = serializers.StringRelatedField(read_only=True)
    success_rate = serializers.SerializerMethodField()
    event_count = serializers.SerializerMethodField()

    class Meta:
        model = WebhookEndpoint
        fields = [
            'id', 'name', 'url', 'created_by', 'organization',
            'is_active', 'is_verified', 'event_count', 'total_deliveries',
            'success_rate', 'last_delivery_at', 'created_at'
        ]

    def get_success_rate(self, obj):
        """Calculate webhook success rate."""
        if obj.total_deliveries == 0:
            return 0.0
        return round((obj.successful_deliveries / obj.total_deliveries) * 100, 2)

    def get_event_count(self, obj):
        """Get number of subscribed events."""
        return len(obj.subscribed_events)


class WebhookDeliverySerializer(serializers.ModelSerializer):
    """Serializer for webhook delivery tracking."""
    
    endpoint_name = serializers.CharField(source='endpoint.name', read_only=True)
    endpoint_url = serializers.CharField(source='endpoint.url', read_only=True)
    
    # Computed fields
    duration_ms = serializers.SerializerMethodField()
    is_retryable = serializers.SerializerMethodField()

    class Meta:
        model = WebhookDelivery
        fields = [
            'id', 'endpoint_name', 'endpoint_url', 'event_type', 'event_id',
            'status', 'attempt_count', 'max_attempts', 'response_status_code',
            'response_headers', 'response_body', 'error_message', 'duration_ms',
            'is_retryable', 'scheduled_at', 'first_attempted_at',
            'last_attempted_at', 'delivered_at', 'next_retry_at', 'created_at'
        ]

    def get_duration_ms(self, obj):
        """Calculate delivery duration in milliseconds."""
        if obj.first_attempted_at and obj.delivered_at:
            delta = obj.delivered_at - obj.first_attempted_at
            return int(delta.total_seconds() * 1000)
        return None

    def get_is_retryable(self, obj):
        """Check if delivery can be retried."""
        return obj.should_retry()


class APIRequestLogSerializer(serializers.ModelSerializer):
    """Serializer for API request logging."""
    
    api_key_name = serializers.CharField(source='api_key.name', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = APIRequestLog
        fields = [
            'id', 'request_id', 'api_key_name', 'user_email', 'method',
            'path', 'query_params', 'ip_address', 'user_agent',
            'status_code', 'response_size', 'response_time_ms',
            'error_type', 'error_message', 'created_at'
        ]


class WebhookEventSerializer(serializers.Serializer):
    """Serializer for webhook event data."""
    
    event_type = serializers.ChoiceField(choices=WebhookEventType.choices)
    event_id = serializers.UUIDField()
    timestamp = serializers.DateTimeField()
    data = serializers.JSONField()
    user_id = serializers.UUIDField(required=False, allow_null=True)
    organization = serializers.CharField(required=False, allow_blank=True)


class APIErrorSerializer(serializers.Serializer):
    """Standardized API error response serializer."""
    
    error = serializers.DictField(child=serializers.CharField())
    
    def to_representation(self, instance):
        """Format error response."""
        if isinstance(instance, dict):
            return instance
        
        return {
            'error': {
                'code': getattr(instance, 'code', 'UNKNOWN_ERROR'),
                'message': str(instance),
                'details': getattr(instance, 'details', {}),
                'timestamp': timezone.now().isoformat()
            }
        }


class APIVersionSerializer(serializers.Serializer):
    """API version information serializer."""
    
    version = serializers.CharField()
    supported_versions = serializers.ListField(child=serializers.CharField())
    deprecated_versions = serializers.ListField(child=serializers.CharField())
    documentation_url = serializers.URLField()
    changelog_url = serializers.URLField()


class APIHealthSerializer(serializers.Serializer):
    """API health check serializer."""
    
    status = serializers.CharField()
    version = serializers.CharField()
    timestamp = serializers.DateTimeField()
    checks = serializers.DictField(child=serializers.CharField())
    uptime_seconds = serializers.IntegerField()


# Filter and sorting utilities
class APIFilterMixin:
    """Mixin for API filtering capabilities."""
    
    def get_filtered_queryset(self, queryset, request):
        """Apply filters based on query parameters."""
        filters = {}
        
        # Common filters
        if 'is_active' in request.query_params:
            filters['is_active'] = request.query_params['is_active'].lower() == 'true'
        
        if 'organization' in request.query_params:
            filters['organization__icontains'] = request.query_params['organization']
        
        if 'created_after' in request.query_params:
            filters['created_at__gte'] = request.query_params['created_after']
        
        if 'created_before' in request.query_params:
            filters['created_at__lte'] = request.query_params['created_before']
        
        return queryset.filter(**filters)

    def get_sorted_queryset(self, queryset, request):
        """Apply sorting based on query parameters."""
        sort_by = request.query_params.get('sort_by', '-created_at')
        
        # Validate sort field
        allowed_sort_fields = [
            'created_at', '-created_at',
            'updated_at', '-updated_at',
            'name', '-name'
        ]
        
        if sort_by in allowed_sort_fields:
            return queryset.order_by(sort_by)
        
        return queryset.order_by('-created_at')


class BulkOperationSerializer(serializers.Serializer):
    """Serializer for bulk operations."""
    
    ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
        max_length=100
    )
    action = serializers.CharField()
    
    def validate_action(self, value):
        """Validate bulk action."""
        allowed_actions = ['activate', 'deactivate', 'delete']
        if value not in allowed_actions:
            raise serializers.ValidationError(f"Action must be one of: {allowed_actions}")
        return value