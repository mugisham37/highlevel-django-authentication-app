"""
API URL Configuration

URL patterns for the comprehensive API integration system.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

app_name = 'api'

# API v1 URL patterns
v1_patterns = [
    # API information and health
    path('', views.api_version_info, name='version_info'),
    path('health/', views.api_health_check, name='health_check'),
    
    # API Key management
    path('keys/', views.APIKeyViewSet.as_view(), name='api_keys'),
    path('keys/<uuid:id>/', views.APIKeyDetailView.as_view(), name='api_key_detail'),
    path('keys/bulk/', views.BulkAPIKeyOperationsView.as_view(), name='api_keys_bulk'),
    
    # Webhook management
    path('webhooks/', views.WebhookEndpointViewSet.as_view(), name='webhooks'),
    path('webhooks/<uuid:id>/', views.WebhookEndpointDetailView.as_view(), name='webhook_detail'),
    path('webhooks/<uuid:endpoint_id>/test/', views.WebhookTestView.as_view(), name='webhook_test'),
    
    # Webhook deliveries
    path('webhook-deliveries/', views.WebhookDeliveryListView.as_view(), name='webhook_deliveries'),
    
    # API request logs and analytics
    path('logs/', views.APIRequestLogListView.as_view(), name='api_logs'),
    path('analytics/', views.APIAnalyticsView.as_view(), name='api_analytics'),
    
    # API documentation
    path('docs/', views.APIDocumentationView.as_view(), name='api_docs'),
]

urlpatterns = [
    # API versioning
    path('v1/', include(v1_patterns)),
    
    # Default to v1 for backward compatibility
    path('', include(v1_patterns)),
]