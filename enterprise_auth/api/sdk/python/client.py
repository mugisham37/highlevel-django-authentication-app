"""
EnterpriseAuth Python SDK Client

Main client class for interacting with the EnterpriseAuth API.
"""
import json
import time
from typing import Dict, Any, List, Optional, Union
from urllib.parse import urljoin, urlencode
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .exceptions import (
    EnterpriseAuthError,
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    ValidationError,
    WebhookError
)
from .models import User, APIKey, WebhookEndpoint, WebhookDelivery, Session


class EnterpriseAuthClient:
    """
    Main client for the EnterpriseAuth API.
    
    Provides methods for authentication, user management, API keys,
    webhooks, and other API operations.
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        jwt_token: Optional[str] = None,
        base_url: str = "https://api.enterpriseauth.com/v1",
        timeout: int = 30,
        max_retries: int = 3,
        retry_backoff_factor: float = 0.3
    ):
        """
        Initialize the EnterpriseAuth client.
        
        Args:
            api_key: API key for authentication
            jwt_token: JWT token for authentication
            base_url: Base URL for the API
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            retry_backoff_factor: Backoff factor for retries
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        
        # Set up authentication
        if api_key and jwt_token:
            raise ValueError("Cannot specify both api_key and jwt_token")
        elif api_key:
            self.auth_header = f"Bearer {api_key}"
        elif jwt_token:
            self.auth_header = f"Bearer {jwt_token}"
        else:
            self.auth_header = None
        
        # Set up HTTP session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=retry_backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            'User-Agent': 'EnterpriseAuth-Python-SDK/1.0.0',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        if self.auth_header:
            self.session.headers['Authorization'] = self.auth_header

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Make an HTTP request to the API.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            params: Query parameters
            data: Request body data
            headers: Additional headers
            
        Returns:
            Response data as dictionary
            
        Raises:
            EnterpriseAuthError: For API errors
        """
        url = urljoin(self.base_url + '/', endpoint.lstrip('/'))
        
        # Prepare request arguments
        request_kwargs = {
            'timeout': self.timeout,
            'params': params
        }
        
        if headers:
            request_kwargs['headers'] = headers
        
        if data is not None:
            request_kwargs['data'] = json.dumps(data)
        
        try:
            response = self.session.request(method, url, **request_kwargs)
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                raise RateLimitError(
                    f"Rate limit exceeded. Retry after {retry_after} seconds.",
                    retry_after=retry_after
                )
            
            # Parse response
            if response.content:
                try:
                    response_data = response.json()
                except json.JSONDecodeError:
                    response_data = {'message': response.text}
            else:
                response_data = {}
            
            # Handle errors
            if not response.ok:
                self._handle_error_response(response, response_data)
            
            return response_data
            
        except requests.exceptions.Timeout:
            raise EnterpriseAuthError("Request timeout")
        except requests.exceptions.ConnectionError:
            raise EnterpriseAuthError("Connection error")
        except requests.exceptions.RequestException as e:
            raise EnterpriseAuthError(f"Request failed: {str(e)}")

    def _handle_error_response(self, response: requests.Response, data: Dict[str, Any]):
        """Handle error responses from the API."""
        error_info = data.get('error', {})
        error_code = error_info.get('code', 'UNKNOWN_ERROR')
        error_message = error_info.get('message', 'Unknown error occurred')
        
        if response.status_code == 401:
            raise AuthenticationError(error_message)
        elif response.status_code == 403:
            raise AuthorizationError(error_message)
        elif response.status_code == 400:
            raise ValidationError(error_message, details=error_info.get('details', {}))
        elif response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))
            raise RateLimitError(error_message, retry_after=retry_after)
        else:
            raise EnterpriseAuthError(f"{error_code}: {error_message}")

    # API Information Methods
    
    def get_api_info(self) -> Dict[str, Any]:
        """Get API version and capability information."""
        return self._make_request('GET', '/')

    def get_health_status(self) -> Dict[str, Any]:
        """Get API health status."""
        return self._make_request('GET', '/health/')

    # API Key Management Methods
    
    def list_api_keys(
        self,
        page: int = 1,
        page_size: int = 20,
        is_active: Optional[bool] = None,
        tier: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List API keys.
        
        Args:
            page: Page number
            page_size: Number of items per page
            is_active: Filter by active status
            tier: Filter by tier
            
        Returns:
            Paginated list of API keys
        """
        params = {'page': page, 'page_size': page_size}
        if is_active is not None:
            params['is_active'] = is_active
        if tier:
            params['tier'] = tier
        
        return self._make_request('GET', '/keys/', params=params)

    def create_api_key(
        self,
        name: str,
        scopes: List[str],
        description: Optional[str] = None,
        organization: Optional[str] = None,
        tier: str = 'basic',
        allowed_ips: Optional[List[str]] = None,
        expires_at: Optional[str] = None,
        rate_limit_per_minute: int = 60,
        rate_limit_per_hour: int = 1000,
        rate_limit_per_day: int = 10000
    ) -> APIKey:
        """
        Create a new API key.
        
        Args:
            name: API key name
            scopes: List of scopes
            description: Optional description
            organization: Organization name
            tier: API key tier
            allowed_ips: List of allowed IP addresses
            expires_at: Expiration date (ISO format)
            rate_limit_per_minute: Rate limit per minute
            rate_limit_per_hour: Rate limit per hour
            rate_limit_per_day: Rate limit per day
            
        Returns:
            Created API key
        """
        data = {
            'name': name,
            'scopes': scopes,
            'tier': tier,
            'rate_limit_per_minute': rate_limit_per_minute,
            'rate_limit_per_hour': rate_limit_per_hour,
            'rate_limit_per_day': rate_limit_per_day
        }
        
        if description:
            data['description'] = description
        if organization:
            data['organization'] = organization
        if allowed_ips:
            data['allowed_ips'] = allowed_ips
        if expires_at:
            data['expires_at'] = expires_at
        
        response = self._make_request('POST', '/keys/', data=data)
        return APIKey.from_dict(response)

    def get_api_key(self, key_id: str) -> APIKey:
        """
        Get API key details.
        
        Args:
            key_id: API key ID
            
        Returns:
            API key details
        """
        response = self._make_request('GET', f'/keys/{key_id}/')
        return APIKey.from_dict(response)

    def update_api_key(
        self,
        key_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        tier: Optional[str] = None,
        allowed_ips: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
        expires_at: Optional[str] = None,
        rate_limit_per_minute: Optional[int] = None,
        rate_limit_per_hour: Optional[int] = None,
        rate_limit_per_day: Optional[int] = None
    ) -> APIKey:
        """
        Update an API key.
        
        Args:
            key_id: API key ID
            name: New name
            description: New description
            scopes: New scopes
            tier: New tier
            allowed_ips: New allowed IPs
            is_active: Active status
            expires_at: New expiration date
            rate_limit_per_minute: New rate limit per minute
            rate_limit_per_hour: New rate limit per hour
            rate_limit_per_day: New rate limit per day
            
        Returns:
            Updated API key
        """
        data = {}
        
        if name is not None:
            data['name'] = name
        if description is not None:
            data['description'] = description
        if scopes is not None:
            data['scopes'] = scopes
        if tier is not None:
            data['tier'] = tier
        if allowed_ips is not None:
            data['allowed_ips'] = allowed_ips
        if is_active is not None:
            data['is_active'] = is_active
        if expires_at is not None:
            data['expires_at'] = expires_at
        if rate_limit_per_minute is not None:
            data['rate_limit_per_minute'] = rate_limit_per_minute
        if rate_limit_per_hour is not None:
            data['rate_limit_per_hour'] = rate_limit_per_hour
        if rate_limit_per_day is not None:
            data['rate_limit_per_day'] = rate_limit_per_day
        
        response = self._make_request('PUT', f'/keys/{key_id}/', data=data)
        return APIKey.from_dict(response)

    def delete_api_key(self, key_id: str) -> bool:
        """
        Delete an API key.
        
        Args:
            key_id: API key ID
            
        Returns:
            True if successful
        """
        self._make_request('DELETE', f'/keys/{key_id}/')
        return True

    def bulk_api_key_operation(self, ids: List[str], action: str) -> Dict[str, Any]:
        """
        Perform bulk operation on API keys.
        
        Args:
            ids: List of API key IDs
            action: Action to perform (activate, deactivate, delete)
            
        Returns:
            Operation result
        """
        data = {'ids': ids, 'action': action}
        return self._make_request('POST', '/keys/bulk/', data=data)

    # Webhook Management Methods
    
    def list_webhooks(
        self,
        page: int = 1,
        page_size: int = 20,
        is_active: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        List webhook endpoints.
        
        Args:
            page: Page number
            page_size: Number of items per page
            is_active: Filter by active status
            
        Returns:
            Paginated list of webhook endpoints
        """
        params = {'page': page, 'page_size': page_size}
        if is_active is not None:
            params['is_active'] = is_active
        
        return self._make_request('GET', '/webhooks/', params=params)

    def create_webhook(
        self,
        name: str,
        url: str,
        subscribed_events: List[str],
        description: Optional[str] = None,
        organization: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout_seconds: int = 30,
        max_retries: int = 3
    ) -> WebhookEndpoint:
        """
        Create a new webhook endpoint.
        
        Args:
            name: Webhook name
            url: Webhook URL
            subscribed_events: List of event types to subscribe to
            description: Optional description
            organization: Organization name
            headers: Additional headers to send
            timeout_seconds: Request timeout
            max_retries: Maximum retry attempts
            
        Returns:
            Created webhook endpoint
        """
        data = {
            'name': name,
            'url': url,
            'subscribed_events': subscribed_events,
            'timeout_seconds': timeout_seconds,
            'max_retries': max_retries
        }
        
        if description:
            data['description'] = description
        if organization:
            data['organization'] = organization
        if headers:
            data['headers'] = headers
        
        response = self._make_request('POST', '/webhooks/', data=data)
        return WebhookEndpoint.from_dict(response)

    def get_webhook(self, webhook_id: str) -> WebhookEndpoint:
        """
        Get webhook endpoint details.
        
        Args:
            webhook_id: Webhook endpoint ID
            
        Returns:
            Webhook endpoint details
        """
        response = self._make_request('GET', f'/webhooks/{webhook_id}/')
        return WebhookEndpoint.from_dict(response)

    def update_webhook(
        self,
        webhook_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        url: Optional[str] = None,
        subscribed_events: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout_seconds: Optional[int] = None,
        max_retries: Optional[int] = None,
        is_active: Optional[bool] = None
    ) -> WebhookEndpoint:
        """
        Update a webhook endpoint.
        
        Args:
            webhook_id: Webhook endpoint ID
            name: New name
            description: New description
            url: New URL
            subscribed_events: New subscribed events
            headers: New headers
            timeout_seconds: New timeout
            max_retries: New max retries
            is_active: Active status
            
        Returns:
            Updated webhook endpoint
        """
        data = {}
        
        if name is not None:
            data['name'] = name
        if description is not None:
            data['description'] = description
        if url is not None:
            data['url'] = url
        if subscribed_events is not None:
            data['subscribed_events'] = subscribed_events
        if headers is not None:
            data['headers'] = headers
        if timeout_seconds is not None:
            data['timeout_seconds'] = timeout_seconds
        if max_retries is not None:
            data['max_retries'] = max_retries
        if is_active is not None:
            data['is_active'] = is_active
        
        response = self._make_request('PUT', f'/webhooks/{webhook_id}/', data=data)
        return WebhookEndpoint.from_dict(response)

    def delete_webhook(self, webhook_id: str) -> bool:
        """
        Delete a webhook endpoint.
        
        Args:
            webhook_id: Webhook endpoint ID
            
        Returns:
            True if successful
        """
        self._make_request('DELETE', f'/webhooks/{webhook_id}/')
        return True

    def test_webhook(self, webhook_id: str) -> Dict[str, Any]:
        """
        Send a test webhook to an endpoint.
        
        Args:
            webhook_id: Webhook endpoint ID
            
        Returns:
            Test result
        """
        return self._make_request('POST', f'/webhooks/{webhook_id}/test/')

    def list_webhook_deliveries(
        self,
        page: int = 1,
        page_size: int = 20,
        endpoint_id: Optional[str] = None,
        status: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List webhook deliveries.
        
        Args:
            page: Page number
            page_size: Number of items per page
            endpoint_id: Filter by endpoint ID
            status: Filter by delivery status
            event_type: Filter by event type
            
        Returns:
            Paginated list of webhook deliveries
        """
        params = {'page': page, 'page_size': page_size}
        if endpoint_id:
            params['endpoint_id'] = endpoint_id
        if status:
            params['status'] = status
        if event_type:
            params['event_type'] = event_type
        
        return self._make_request('GET', '/webhook-deliveries/', params=params)

    # Analytics Methods
    
    def get_analytics(
        self,
        period: str = 'week',
        api_key_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get API usage analytics.
        
        Args:
            period: Time period (day, week, month)
            api_key_id: Filter by API key ID
            
        Returns:
            Analytics data
        """
        params = {'period': period}
        if api_key_id:
            params['api_key_id'] = api_key_id
        
        return self._make_request('GET', '/analytics/', params=params)

    def list_api_logs(
        self,
        page: int = 1,
        page_size: int = 20,
        api_key_id: Optional[str] = None,
        status_code: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        List API request logs.
        
        Args:
            page: Page number
            page_size: Number of items per page
            api_key_id: Filter by API key ID
            status_code: Filter by status code
            start_date: Filter by start date
            end_date: Filter by end date
            
        Returns:
            Paginated list of API logs
        """
        params = {'page': page, 'page_size': page_size}
        if api_key_id:
            params['api_key_id'] = api_key_id
        if status_code:
            params['status_code'] = status_code
        if start_date:
            params['start_date'] = start_date
        if end_date:
            params['end_date'] = end_date
        
        return self._make_request('GET', '/logs/', params=params)

    # Webhook Signature Verification
    
    @staticmethod
    def verify_webhook_signature(
        payload: bytes,
        signature: str,
        secret: str,
        timestamp: Optional[str] = None
    ) -> bool:
        """
        Verify webhook signature.
        
        Args:
            payload: Raw webhook payload
            signature: Webhook signature header
            secret: Webhook secret key
            timestamp: Webhook timestamp
            
        Returns:
            True if signature is valid
        """
        import hmac
        import hashlib
        
        if timestamp:
            message = f"{timestamp}.{payload.decode()}"
        else:
            message = payload.decode()
        
        expected_signature = hmac.new(
            secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Extract signature from header (format: t=timestamp,v1=signature)
        if ',' in signature:
            parts = signature.split(',')
            for part in parts:
                if part.startswith('v1='):
                    provided_signature = part[3:]
                    return hmac.compare_digest(expected_signature, provided_signature)
        
        # Direct signature comparison
        return hmac.compare_digest(expected_signature, signature)

    # Context Manager Support
    
    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.session.close()