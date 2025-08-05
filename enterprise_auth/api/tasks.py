"""
API Background Tasks

Celery tasks for webhook delivery, logging, and maintenance.
"""
import logging
import json
import uuid
import requests
import hashlib
import hmac
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.cache import cache
from celery import shared_task
from celery.exceptions import Retry

from .models import (
    WebhookEndpoint, WebhookDelivery, APIRequestLog,
    WebhookDeliveryStatus, WebhookEventType
)
from enterprise_auth.core.exceptions import WebhookDeliveryError

User = get_user_model()
logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def deliver_webhook(self, delivery_id: str) -> Dict[str, Any]:
    """
    Deliver webhook to endpoint with retry logic.
    
    Args:
        delivery_id: UUID of the WebhookDelivery instance
        
    Returns:
        Dict containing delivery status and details
    """
    try:
        delivery = WebhookDelivery.objects.select_related('endpoint').get(id=delivery_id)
    except WebhookDelivery.DoesNotExist:
        logger.error(f"Webhook delivery not found: {delivery_id}")
        return {'status': 'error', 'message': 'Delivery not found'}
    
    endpoint = delivery.endpoint
    
    # Check if endpoint is active
    if not endpoint.is_active:
        delivery.mark_failed("Endpoint is not active")
        return {'status': 'failed', 'message': 'Endpoint not active'}
    
    try:
        # Prepare payload
        timestamp = str(int(timezone.now().timestamp()))
        payload_data = {
            'event_type': delivery.event_type,
            'event_id': str(delivery.event_id),
            'timestamp': timestamp,
            'data': delivery.payload
        }
        payload_json = json.dumps(payload_data, separators=(',', ':'))
        payload_bytes = payload_json.encode('utf-8')
        
        # Generate signature
        signature = endpoint.generate_signature(payload_bytes, timestamp)
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'EnterpriseAuth-Webhook/1.0',
            'X-Webhook-Signature': signature,
            'X-Webhook-Timestamp': timestamp,
            'X-Webhook-Event-Type': delivery.event_type,
            'X-Webhook-Event-ID': str(delivery.event_id),
            'X-Webhook-Delivery-ID': str(delivery.id),
        }
        
        # Add custom headers
        if endpoint.headers:
            headers.update(endpoint.headers)
        
        # Record attempt
        delivery.attempt_count += 1
        if not delivery.first_attempted_at:
            delivery.first_attempted_at = timezone.now()
        delivery.last_attempted_at = timezone.now()
        delivery.save()
        
        # Make HTTP request
        response = requests.post(
            endpoint.url,
            data=payload_json,
            headers=headers,
            timeout=endpoint.timeout_seconds,
            allow_redirects=False
        )
        
        # Check response status
        if 200 <= response.status_code < 300:
            # Success
            delivery.mark_delivered(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text[:1000]  # Limit response body size
            )
            
            # Update endpoint statistics
            endpoint.total_deliveries += 1
            endpoint.successful_deliveries += 1
            endpoint.last_delivery_at = timezone.now()
            endpoint.save()
            
            logger.info(f"Webhook delivered successfully: {delivery_id}")
            return {
                'status': 'delivered',
                'status_code': response.status_code,
                'attempt': delivery.attempt_count
            }
        else:
            # HTTP error
            error_message = f"HTTP {response.status_code}: {response.text[:500]}"
            delivery.mark_failed(
                error_message=error_message,
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text[:1000]
            )
            
            # Update endpoint statistics
            endpoint.total_deliveries += 1
            endpoint.failed_deliveries += 1
            endpoint.save()
            
            # Retry if retryable status code
            if response.status_code in [429, 502, 503, 504] and delivery.should_retry():
                logger.warning(f"Webhook delivery failed, will retry: {delivery_id}")
                raise self.retry(countdown=delivery.calculate_next_retry().timestamp() - timezone.now().timestamp())
            
            logger.error(f"Webhook delivery failed: {delivery_id} - {error_message}")
            return {
                'status': 'failed',
                'status_code': response.status_code,
                'error': error_message,
                'attempt': delivery.attempt_count
            }
    
    except requests.exceptions.Timeout:
        error_message = f"Request timeout after {endpoint.timeout_seconds} seconds"
        delivery.mark_failed(error_message)
        
        endpoint.total_deliveries += 1
        endpoint.failed_deliveries += 1
        endpoint.save()
        
        if delivery.should_retry():
            logger.warning(f"Webhook delivery timeout, will retry: {delivery_id}")
            raise self.retry(countdown=60 * (2 ** delivery.attempt_count))
        
        logger.error(f"Webhook delivery timeout: {delivery_id}")
        return {'status': 'failed', 'error': error_message, 'attempt': delivery.attempt_count}
    
    except requests.exceptions.ConnectionError as e:
        error_message = f"Connection error: {str(e)}"
        delivery.mark_failed(error_message)
        
        endpoint.total_deliveries += 1
        endpoint.failed_deliveries += 1
        endpoint.save()
        
        if delivery.should_retry():
            logger.warning(f"Webhook delivery connection error, will retry: {delivery_id}")
            raise self.retry(countdown=60 * (2 ** delivery.attempt_count))
        
        logger.error(f"Webhook delivery connection error: {delivery_id}")
        return {'status': 'failed', 'error': error_message, 'attempt': delivery.attempt_count}
    
    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        delivery.mark_failed(error_message)
        
        endpoint.total_deliveries += 1
        endpoint.failed_deliveries += 1
        endpoint.save()
        
        logger.error(f"Webhook delivery unexpected error: {delivery_id} - {error_message}")
        return {'status': 'failed', 'error': error_message, 'attempt': delivery.attempt_count}


@shared_task
def queue_webhook_delivery(event_type: str, event_data: Dict[str, Any], 
                          user_id: Optional[str] = None, organization: Optional[str] = None) -> Dict[str, Any]:
    """
    Queue webhook deliveries for an event.
    
    Args:
        event_type: Type of event (from WebhookEventType)
        event_data: Event payload data
        user_id: Optional user ID associated with the event
        organization: Optional organization filter
        
    Returns:
        Dict containing queued delivery information
    """
    try:
        # Find matching webhook endpoints
        endpoints = WebhookEndpoint.objects.filter(
            is_active=True,
            subscribed_events__contains=[event_type]
        )
        
        # Filter by organization if specified
        if organization:
            endpoints = endpoints.filter(organization=organization)
        
        deliveries_queued = 0
        event_id = uuid.uuid4()
        
        for endpoint in endpoints:
            # Create delivery record
            delivery = WebhookDelivery.objects.create(
                endpoint=endpoint,
                event_type=event_type,
                event_id=event_id,
                payload=event_data,
                max_attempts=endpoint.max_retries + 1
            )
            
            # Queue delivery task
            deliver_webhook.delay(str(delivery.id))
            deliveries_queued += 1
        
        logger.info(f"Queued {deliveries_queued} webhook deliveries for event {event_type}")
        
        return {
            'event_id': str(event_id),
            'event_type': event_type,
            'deliveries_queued': deliveries_queued
        }
    
    except Exception as e:
        logger.error(f"Failed to queue webhook deliveries: {str(e)}")
        return {
            'error': str(e),
            'deliveries_queued': 0
        }


@shared_task
def retry_failed_webhooks() -> Dict[str, Any]:
    """
    Retry failed webhook deliveries that are eligible for retry.
    
    Returns:
        Dict containing retry statistics
    """
    try:
        # Find deliveries eligible for retry
        now = timezone.now()
        from django.db import models as django_models
        
        failed_deliveries = WebhookDelivery.objects.filter(
            status__in=[WebhookDeliveryStatus.FAILED, WebhookDeliveryStatus.RETRYING],
            next_retry_at__lte=now,
            attempt_count__lt=django_models.F('max_attempts')
        )
        
        retries_queued = 0
        
        for delivery in failed_deliveries:
            if delivery.should_retry():
                # Update status and queue retry
                delivery.status = WebhookDeliveryStatus.RETRYING
                delivery.save()
                
                deliver_webhook.delay(str(delivery.id))
                retries_queued += 1
        
        logger.info(f"Queued {retries_queued} webhook delivery retries")
        
        return {
            'retries_queued': retries_queued,
            'timestamp': now.isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to retry webhooks: {str(e)}")
        return {
            'error': str(e),
            'retries_queued': 0
        }


@shared_task
def cleanup_old_webhook_deliveries(days_to_keep: int = 30) -> Dict[str, Any]:
    """
    Clean up old webhook delivery records.
    
    Args:
        days_to_keep: Number of days to keep delivery records
        
    Returns:
        Dict containing cleanup statistics
    """
    try:
        cutoff_date = timezone.now() - timedelta(days=days_to_keep)
        
        # Delete old successful deliveries
        deleted_count, _ = WebhookDelivery.objects.filter(
            status=WebhookDeliveryStatus.DELIVERED,
            created_at__lt=cutoff_date
        ).delete()
        
        # Delete old abandoned deliveries
        abandoned_count, _ = WebhookDelivery.objects.filter(
            status=WebhookDeliveryStatus.ABANDONED,
            created_at__lt=cutoff_date
        ).delete()
        
        total_deleted = deleted_count + abandoned_count
        
        logger.info(f"Cleaned up {total_deleted} old webhook delivery records")
        
        return {
            'deleted_count': total_deleted,
            'cutoff_date': cutoff_date.isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to cleanup webhook deliveries: {str(e)}")
        return {
            'error': str(e),
            'deleted_count': 0
        }


@shared_task
def log_api_request_async(log_data: Dict[str, Any]) -> bool:
    """
    Asynchronously log API request data.
    
    Args:
        log_data: Dictionary containing request log data
        
    Returns:
        Boolean indicating success
    """
    try:
        # Create API request log entry
        APIRequestLog.objects.create(
            request_id=log_data['request_id'],
            api_key_id=log_data.get('api_key_id'),
            user_id=log_data.get('user_id'),
            method=log_data['method'],
            path=log_data['path'],
            query_params=log_data.get('query_params', {}),
            headers=log_data.get('headers', {}),
            body_size=log_data.get('body_size', 0),
            ip_address=log_data['ip_address'],
            user_agent=log_data.get('user_agent', ''),
            status_code=log_data['status_code'],
            response_size=log_data.get('response_size', 0),
            response_time_ms=log_data['response_time_ms'],
            error_type=log_data.get('error_type', ''),
            error_message=log_data.get('error_message', '')
        )
        
        return True
    
    except Exception as e:
        logger.error(f"Failed to log API request: {str(e)}")
        return False


@shared_task
def verify_webhook_endpoint(endpoint_id: str) -> Dict[str, Any]:
    """
    Verify webhook endpoint by sending a verification request.
    
    Args:
        endpoint_id: UUID of the WebhookEndpoint to verify
        
    Returns:
        Dict containing verification result
    """
    try:
        endpoint = WebhookEndpoint.objects.get(id=endpoint_id)
    except WebhookEndpoint.DoesNotExist:
        logger.error(f"Webhook endpoint not found for verification: {endpoint_id}")
        return {'status': 'error', 'message': 'Endpoint not found'}
    
    try:
        # Prepare verification payload
        verification_data = {
            'event_type': 'webhook.verification',
            'verification_token': endpoint.verification_token,
            'endpoint_id': str(endpoint.id),
            'timestamp': timezone.now().isoformat()
        }
        
        payload_json = json.dumps(verification_data, separators=(',', ':'))
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'EnterpriseAuth-Webhook/1.0',
            'X-Webhook-Verification': endpoint.verification_token,
        }
        
        # Add custom headers
        if endpoint.headers:
            headers.update(endpoint.headers)
        
        # Make verification request
        response = requests.post(
            endpoint.url,
            data=payload_json,
            headers=headers,
            timeout=endpoint.timeout_seconds,
            allow_redirects=False
        )
        
        # Check if verification was successful
        if 200 <= response.status_code < 300:
            # Check if response contains verification token
            response_text = response.text.lower()
            if endpoint.verification_token.lower() in response_text:
                endpoint.is_verified = True
                endpoint.save()
                
                logger.info(f"Webhook endpoint verified successfully: {endpoint_id}")
                return {
                    'status': 'verified',
                    'endpoint_id': endpoint_id,
                    'status_code': response.status_code
                }
            else:
                logger.warning(f"Webhook endpoint verification failed - token not found in response: {endpoint_id}")
                return {
                    'status': 'failed',
                    'message': 'Verification token not found in response',
                    'status_code': response.status_code
                }
        else:
            logger.warning(f"Webhook endpoint verification failed - HTTP {response.status_code}: {endpoint_id}")
            return {
                'status': 'failed',
                'message': f'HTTP {response.status_code}',
                'status_code': response.status_code
            }
    
    except requests.exceptions.Timeout:
        logger.warning(f"Webhook endpoint verification timeout: {endpoint_id}")
        return {'status': 'failed', 'message': 'Request timeout'}
    
    except requests.exceptions.ConnectionError:
        logger.warning(f"Webhook endpoint verification connection error: {endpoint_id}")
        return {'status': 'failed', 'message': 'Connection error'}
    
    except Exception as e:
        logger.error(f"Webhook endpoint verification error: {endpoint_id} - {str(e)}")
        return {'status': 'failed', 'message': str(e)}


@shared_task
def send_test_webhook(endpoint_id: str, user_id: str) -> Dict[str, Any]:
    """
    Send a test webhook to an endpoint.
    
    Args:
        endpoint_id: UUID of the WebhookEndpoint
        user_id: UUID of the user requesting the test
        
    Returns:
        Dict containing test result
    """
    try:
        endpoint = WebhookEndpoint.objects.get(id=endpoint_id)
        user = User.objects.get(id=user_id)
    except (WebhookEndpoint.DoesNotExist, User.DoesNotExist):
        return {'status': 'error', 'message': 'Endpoint or user not found'}
    
    # Create test event data
    test_event_data = {
        'test': True,
        'message': 'This is a test webhook from EnterpriseAuth',
        'user': {
            'id': str(user.id),
            'email': user.email
        },
        'timestamp': timezone.now().isoformat()
    }
    
    # Create test delivery
    delivery = WebhookDelivery.objects.create(
        endpoint=endpoint,
        event_type='webhook.test',
        event_id=uuid.uuid4(),
        payload=test_event_data,
        max_attempts=1  # Only try once for test
    )
    
    # Deliver immediately
    result = deliver_webhook(str(delivery.id))
    
    logger.info(f"Test webhook sent to endpoint {endpoint_id} by user {user_id}")
    
    return {
        'delivery_id': str(delivery.id),
        'result': result
    }


@shared_task
def cleanup_old_api_logs(days_to_keep: int = 90) -> Dict[str, Any]:
    """
    Clean up old API request logs.
    
    Args:
        days_to_keep: Number of days to keep log records
        
    Returns:
        Dict containing cleanup statistics
    """
    try:
        cutoff_date = timezone.now() - timedelta(days=days_to_keep)
        
        deleted_count, _ = APIRequestLog.objects.filter(
            created_at__lt=cutoff_date
        ).delete()
        
        logger.info(f"Cleaned up {deleted_count} old API request log records")
        
        return {
            'deleted_count': deleted_count,
            'cutoff_date': cutoff_date.isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to cleanup API logs: {str(e)}")
        return {
            'error': str(e),
            'deleted_count': 0
        }


@shared_task
def generate_api_analytics_report(user_id: str, period: str = 'week') -> Dict[str, Any]:
    """
    Generate API analytics report for a user.
    
    Args:
        user_id: UUID of the user
        period: Time period for the report (day, week, month)
        
    Returns:
        Dict containing analytics report
    """
    try:
        from django.db.models import Count, Avg, Q
        
        user = User.objects.get(id=user_id)
        
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
        
        # Get API request logs
        logs = APIRequestLog.objects.filter(
            user=user,
            created_at__gte=start_date
        )
        
        # Calculate metrics
        total_requests = logs.count()
        successful_requests = logs.filter(status_code__lt=400).count()
        error_requests = logs.filter(status_code__gte=400).count()
        avg_response_time = logs.aggregate(Avg('response_time_ms'))['response_time_ms__avg'] or 0
        
        # Generate report
        report = {
            'user_id': user_id,
            'period': period,
            'start_date': start_date.isoformat(),
            'end_date': now.isoformat(),
            'total_requests': total_requests,
            'successful_requests': successful_requests,
            'error_requests': error_requests,
            'success_rate': round((successful_requests / total_requests * 100), 2) if total_requests > 0 else 0,
            'average_response_time_ms': round(avg_response_time, 2),
            'generated_at': now.isoformat()
        }
        
        # Cache the report for 1 hour
        cache_key = f"api_analytics:{user_id}:{period}"
        cache.set(cache_key, report, 3600)
        
        logger.info(f"Generated API analytics report for user {user_id}")
        
        return report
    
    except Exception as e:
        logger.error(f"Failed to generate API analytics report: {str(e)}")
        return {
            'error': str(e),
            'user_id': user_id
        }