"""
API Views

Comprehensive API views for authentication system integration.
"""
import logging
from typing import Dict, Any, List
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import ValidationError
from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.openapi import AutoSchema

from .models import (
    APIKey, WebhookEndpoint, WebhookDelivery, APIRequestLog,
    APIKeyScope, APIKeyTier, WebhookEventType
)
from .serializers import (
    APIKeySerializer, APIKeyListSerializer, WebhookEndpointSerializer,
    WebhookEndpointListSerializer, WebhookDeliverySerializer,
    APIRequestLogSerializer, WebhookEventSerializer, APIErrorSerializer,
    APIVersionSerializer, APIHealthSerializer, StandardResultsSetPagination,
    APIFilterMixin, BulkOperationSerializer
)
from .authentication import APIKeyAuthentication, JWTAuthentication, CombinedAuthentication
from enterprise_auth.core.exceptions import AuthenticationError, AuthorizationError

User = get_user_model()
logger = logging.getLogger(__name__)


class APIKeyViewSet(APIFilterMixin, generics.ListCreateAPIView):
    """
    API Key management endpoints.
    
    Supports creating, listing, updating, and deleting API keys.
    """
    authentication_classes = [CombinedAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.request.method == 'GET':
            return APIKeyListSerializer
        return APIKeySerializer
    
    def get_queryset(self):
        """Get filtered and sorted queryset."""
        queryset = APIKey.objects.filter(created_by=self.request.user)
        queryset = self.get_filtered_queryset(queryset, self.request)
        queryset = self.get_sorted_queryset(queryset, self.request)
        return queryset
    
    @extend_schema(
        summary="List API keys",
        description="Retrieve a paginated list of API keys for the authenticated user.",
        parameters=[
            OpenApiParameter('is_active', bool, description='Filter by active status'),
            OpenApiParameter('tier', str, description='Filter by tier'),
            OpenApiParameter('sort_by', str, description='Sort field'),
        ]
    )
    def get(self, request: Request, *args, **kwargs) -> Response:
        """List API keys."""
        return super().get(request, *args, **kwargs)
    
    @extend_schema(
        summary="Create API key",
        description="Create a new API key with specified scopes and configuration.",
        request=APIKeySerializer,
        responses={201: APIKeySerializer}
    )
    def post(self, request: Request, *args, **kwargs) -> Response:
        """Create a new API key."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Set the creator
        serializer.validated_data['created_by'] = request.user
        
        # Create the API key
        api_key = serializer.save()
        
        # Log API key creation
        logger.info(f"API key created: {api_key.name} by {request.user.email}")
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class APIKeyDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Individual API key management.
    """
    authentication_classes = [CombinedAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = APIKeySerializer
    lookup_field = 'id'
    
    def get_queryset(self):
        """Get user's API keys."""
        return APIKey.objects.filter(created_by=self.request.user)
    
    @extend_schema(
        summary="Get API key details",
        description="Retrieve details of a specific API key.",
        responses={200: APIKeySerializer}
    )
    def get(self, request: Request, *args, **kwargs) -> Response:
        """Get API key details."""
        return super().get(request, *args, **kwargs)
    
    @extend_schema(
        summary="Update API key",
        description="Update API key configuration.",
        request=APIKeySerializer,
        responses={200: APIKeySerializer}
    )
    def put(self, request: Request, *args, **kwargs) -> Response:
        """Update API key."""
        return super().put(request, *args, **kwargs)
    
    @extend_schema(
        summary="Delete API key",
        description="Delete an API key permanently.",
        responses={204: None}
    )
    def delete(self, request: Request, *args, **kwargs) -> Response:
        """Delete API key."""
        api_key = self.get_object()
        logger.info(f"API key deleted: {api_key.name} by {request.user.email}")
        return super().delete(request, *args, **kwargs)


class WebhookEndpointViewSet(APIFilterMixin, generics.ListCreateAPIView):
    """
    Webhook endpoint management.
    """
    authentication_classes = [CombinedAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.request.method == 'GET':
            return WebhookEndpointListSerializer
        return WebhookEndpointSerializer
    
    def get_queryset(self):
        """Get filtered and sorted queryset."""
        queryset = WebhookEndpoint.objects.filter(created_by=self.request.user)
        queryset = self.get_filtered_queryset(queryset, self.request)
        queryset = self.get_sorted_queryset(queryset, self.request)
        return queryset
    
    @extend_schema(
        summary="List webhook endpoints",
        description="Retrieve a paginated list of webhook endpoints.",
        parameters=[
            OpenApiParameter('is_active', bool, description='Filter by active status'),
            OpenApiParameter('is_verified', bool, description='Filter by verification status'),
        ]
    )
    def get(self, request: Request, *args, **kwargs) -> Response:
        """List webhook endpoints."""
        return super().get(request, *args, **kwargs)
    
    @extend_schema(
        summary="Create webhook endpoint",
        description="Register a new webhook endpoint.",
        request=WebhookEndpointSerializer,
        responses={201: WebhookEndpointSerializer}
    )
    def post(self, request: Request, *args, **kwargs) -> Response:
        """Create webhook endpoint."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Set the creator
        serializer.validated_data['created_by'] = request.user
        
        # Create the webhook endpoint
        webhook = serializer.save()
        
        # Queue verification request
        from enterprise_auth.api.tasks import verify_webhook_endpoint
        verify_webhook_endpoint.delay(webhook.id)
        
        logger.info(f"Webhook endpoint created: {webhook.name} by {request.user.email}")
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class WebhookEndpointDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Individual webhook endpoint management.
    """
    authentication_classes = [CombinedAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = WebhookEndpointSerializer
    lookup_field = 'id'
    
    def get_queryset(self):
        """Get user's webhook endpoints."""
        return WebhookEndpoint.objects.filter(created_by=self.request.user)


class WebhookDeliveryListView(generics.ListAPIView):
    """
    Webhook delivery tracking.
    """
    authentication_classes = [CombinedAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = WebhookDeliverySerializer
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        """Get webhook deliveries for user's endpoints."""
        user_endpoints = WebhookEndpoint.objects.filter(created_by=self.request.user)
        queryset = WebhookDelivery.objects.filter(endpoint__in=user_endpoints)
        
        # Filter by endpoint if specified
        endpoint_id = self.request.query_params.get('endpoint_id')
        if endpoint_id:
            queryset = queryset.filter(endpoint_id=endpoint_id)
        
        # Filter by status if specified
        status_filter = self.request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by event type if specified
        event_type = self.request.query_params.get('event_type')
        if event_type:
            queryset = queryset.filter(event_type=event_type)
        
        return queryset.order_by('-created_at')


class APIRequestLogListView(generics.ListAPIView):
    """
    API request logging and analytics.
    """
    authentication_classes = [CombinedAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = APIRequestLogSerializer
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        """Get API request logs for user."""
        queryset = APIRequestLog.objects.filter(user=self.request.user)
        
        # Filter by API key if specified
        api_key_id = self.request.query_params.get('api_key_id')
        if api_key_id:
            queryset = queryset.filter(api_key_id=api_key_id)
        
        # Filter by status code if specified
        status_code = self.request.query_params.get('status_code')
        if status_code:
            queryset = queryset.filter(status_code=status_code)
        
        # Filter by date range
        start_date = self.request.query_params.get('start_date')
        if start_date:
            queryset = queryset.filter(created_at__gte=start_date)
        
        end_date = self.request.query_params.get('end_date')
        if end_date:
            queryset = queryset.filter(created_at__lte=end_date)
        
        return queryset.order_by('-created_at')


@extend_schema(
    summary="API version information",
    description="Get information about API versions and capabilities.",
    responses={200: APIVersionSerializer}
)
@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def api_version_info(request: Request) -> Response:
    """Get API version information."""
    version_info = {
        'version': 'v1',
        'supported_versions': ['v1'],
        'deprecated_versions': [],
        'documentation_url': 'https://docs.enterpriseauth.com/api/v1/',
        'changelog_url': 'https://docs.enterpriseauth.com/changelog/'
    }
    
    serializer = APIVersionSerializer(version_info)
    return Response(serializer.data)


@extend_schema(
    summary="API health check",
    description="Check API health and status.",
    responses={200: APIHealthSerializer}
)
@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def api_health_check(request: Request) -> Response:
    """API health check endpoint."""
    import psutil
    import time
    
    # Get system uptime
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)
    
    # Check database connectivity
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        db_status = 'healthy'
    except Exception:
        db_status = 'unhealthy'
    
    # Check cache connectivity
    try:
        from django.core.cache import cache
        cache.set('health_check', 'test', 1)
        cache_result = cache.get('health_check')
        cache_status = 'healthy' if cache_result == 'test' else 'unhealthy'
    except Exception:
        cache_status = 'unhealthy'
    
    overall_status = 'healthy' if db_status == 'healthy' and cache_status == 'healthy' else 'unhealthy'
    
    health_data = {
        'status': overall_status,
        'version': 'v1',
        'timestamp': timezone.now(),
        'checks': {
            'database': db_status,
            'cache': cache_status,
        },
        'uptime_seconds': uptime_seconds
    }
    
    serializer = APIHealthSerializer(health_data)
    status_code = 200 if overall_status == 'healthy' else 503
    
    return Response(serializer.data, status=status_code)


class BulkAPIKeyOperationsView(APIView):
    """
    Bulk operations for API keys.
    """
    authentication_classes = [CombinedAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        summary="Bulk API key operations",
        description="Perform bulk operations on multiple API keys.",
        request=BulkOperationSerializer,
        responses={200: dict}
    )
    def post(self, request: Request) -> Response:
        """Perform bulk operations on API keys."""
        serializer = BulkOperationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        ids = serializer.validated_data['ids']
        action = serializer.validated_data['action']
        
        # Get API keys owned by user
        api_keys = APIKey.objects.filter(
            id__in=ids,
            created_by=request.user
        )
        
        if len(api_keys) != len(ids):
            return Response({
                'error': 'Some API keys not found or not owned by user'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Perform bulk operation
        with transaction.atomic():
            if action == 'activate':
                api_keys.update(is_active=True)
            elif action == 'deactivate':
                api_keys.update(is_active=False)
            elif action == 'delete':
                api_keys.delete()
        
        logger.info(f"Bulk {action} performed on {len(api_keys)} API keys by {request.user.email}")
        
        return Response({
            'message': f'Successfully {action}d {len(api_keys)} API keys',
            'affected_count': len(api_keys)
        })


class WebhookTestView(APIView):
    """
    Test webhook endpoint connectivity.
    """
    authentication_classes = [CombinedAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        summary="Test webhook endpoint",
        description="Send a test event to a webhook endpoint.",
        responses={200: dict}
    )
    def post(self, request: Request, endpoint_id: str) -> Response:
        """Send test webhook."""
        try:
            webhook = WebhookEndpoint.objects.get(
                id=endpoint_id,
                created_by=request.user
            )
        except WebhookEndpoint.DoesNotExist:
            return Response({
                'error': 'Webhook endpoint not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Queue test webhook delivery
        from enterprise_auth.api.tasks import send_test_webhook
        task = send_test_webhook.delay(webhook.id, request.user.id)
        
        return Response({
            'message': 'Test webhook queued for delivery',
            'task_id': task.id
        })


class APIAnalyticsView(APIView):
    """
    API usage analytics and metrics.
    """
    authentication_classes = [CombinedAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    
    @extend_schema(
        summary="Get API analytics",
        description="Retrieve API usage analytics and metrics.",
        parameters=[
            OpenApiParameter('period', str, description='Time period (day, week, month)'),
            OpenApiParameter('api_key_id', str, description='Filter by API key'),
        ]
    )
    def get(self, request: Request) -> Response:
        """Get API usage analytics."""
        from django.db.models import Count, Avg, Q
        from datetime import timedelta
        
        period = request.query_params.get('period', 'week')
        api_key_id = request.query_params.get('api_key_id')
        
        # Calculate date range
        now = timezone.now()
        if period == 'day':
            start_date = now - timedelta(days=1)
        elif period == 'week':
            start_date = now - timedelta(weeks=1)
        elif period == 'month':
            start_date = now - timedelta(days=30)
        else:
            start_date = now - timedelta(weeks=1)
        
        # Base queryset
        queryset = APIRequestLog.objects.filter(
            user=request.user,
            created_at__gte=start_date
        )
        
        if api_key_id:
            queryset = queryset.filter(api_key_id=api_key_id)
        
        # Calculate metrics
        total_requests = queryset.count()
        successful_requests = queryset.filter(status_code__lt=400).count()
        error_requests = queryset.filter(status_code__gte=400).count()
        avg_response_time = queryset.aggregate(Avg('response_time_ms'))['response_time_ms__avg'] or 0
        
        # Top endpoints
        top_endpoints = queryset.values('path').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        # Status code distribution
        status_codes = queryset.values('status_code').annotate(
            count=Count('id')
        ).order_by('status_code')
        
        analytics_data = {
            'period': period,
            'start_date': start_date,
            'end_date': now,
            'total_requests': total_requests,
            'successful_requests': successful_requests,
            'error_requests': error_requests,
            'success_rate': round((successful_requests / total_requests * 100), 2) if total_requests > 0 else 0,
            'average_response_time_ms': round(avg_response_time, 2),
            'top_endpoints': list(top_endpoints),
            'status_code_distribution': list(status_codes)
        }
        
        return Response(analytics_data)


class APIDocumentationView(APIView):
    """
    API documentation endpoint.
    """
    permission_classes = [permissions.AllowAny]
    
    @extend_schema(
        summary="Get API documentation",
        description="Retrieve comprehensive API documentation including guides and examples.",
        responses={200: dict}
    )
    def get(self, request: Request) -> Response:
        """Get API documentation."""
        from .docs import APIDocumentationGenerator
        
        doc_generator = APIDocumentationGenerator()
        documentation = doc_generator.generate_full_documentation()
        
        return Response(documentation)