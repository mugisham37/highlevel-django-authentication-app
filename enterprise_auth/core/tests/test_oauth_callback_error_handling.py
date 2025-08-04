"""
Tests for OAuth callback error handling and fallback authentication methods.

This module tests the comprehensive error handling, monitoring, and fallback
mechanisms implemented for OAuth callback flows.
"""

import json
import secrets
from unittest.mock import Mock, patch, MagicMock
from django.test import TestCase, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status

from ..exceptions import (
    OAuthError,
    OAuthProviderError,
    OAuthStateInvalidError,
    OAuthCodeInvalidError,
    OAuthUserInfoError,
    OAuthTokenExpiredError,
)
from ..services.oauth_callback_service import oauth_callback_service
from ..utils.monitoring import oauth_metrics

User = get_user_model()


class OAuthCallbackErrorHandlingTestCase(TestCase):
    """Test cases for OAuth callback error handling."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.client = APIClient()
        self.provider_name = 'google'
        self.callback_url = reverse('core:handle_oauth_callback', kwargs={'provider_name': self.provider_name})
        self.state = secrets.token_urlsafe(32)
        self.code = 'test_auth_code'
        self.correlation_id = secrets.token_urlsafe(16)
        
        # Clear cache before each test
        cache.clear()
    
    def test_oauth_provider_error_handling(self):
        """Test handling of OAuth provider errors."""
        # Test access_denied error
        response = self.client.post(self.callback_url, {
            'error': 'access_denied',
            'error_description': 'User denied access',
            'state': self.state
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        
        self.assertEqual(response_data['error']['code'], 'OAUTH_PROVIDER_ERROR')
        self.assertEqual(response_data['error']['oauth_error'], 'access_denied')
        self.assertIn('fallback_methods', response_data)
        self.assertTrue(response_data['retry_available'])
        
        # Verify fallback methods are provided
        fallback_methods = response_data['fallback_methods']
        self.assertGreater(len(fallback_methods), 0)
        
        # Check for email/password fallback
        email_fallback = next((f for f in fallback_methods if f['method'] == 'email_password'), None)
        self.assertIsNotNone(email_fallback)
        self.assertEqual(email_fallback['title'], 'Sign in with Email')
    
    def test_missing_parameters_error_handling(self):
        """Test handling of missing OAuth callback parameters."""
        # Test missing code parameter
        response = self.client.post(self.callback_url, {
            'state': self.state
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        
        self.assertEqual(response_data['error']['code'], 'OAUTH_MISSING_PARAMETERS')
        self.assertIn('fallback_methods', response_data)
        self.assertTrue(response_data['retry_available'])
    
    def test_state_mismatch_error_handling(self):
        """Test handling of OAuth state parameter mismatch."""
        # Set up session state
        session = self.client.session
        session[f'oauth_state_{self.provider_name}'] = 'expected_state'
        session.save()
        
        # Send request with different state
        response = self.client.post(self.callback_url, {
            'code': self.code,
            'state': 'different_state'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        
        self.assertEqual(response_data['error']['code'], 'OAUTH_STATE_MISMATCH')
        self.assertIn('security_warning', response_data['error'])
        self.assertIn('fallback_methods', response_data)
    
    @patch('enterprise_auth.core.services.oauth_service.oauth_service.handle_callback')
    def test_callback_processing_error_handling(self, mock_handle_callback):
        """Test handling of OAuth callback processing errors."""
        # Set up session state
        session = self.client.session
        session[f'oauth_state_{self.provider_name}'] = self.state
        session.save()
        
        # Mock callback processing error
        mock_handle_callback.side_effect = OAuthTokenExpiredError("Token expired")
        
        response = self.client.post(self.callback_url, {
            'code': self.code,
            'state': self.state
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        
        self.assertEqual(response_data['error']['code'], 'OAUTH_PROCESSING_ERROR')
        self.assertIn('fallback_methods', response_data)
        self.assertTrue(response_data['retry_available'])
    
    @patch('enterprise_auth.core.services.oauth_service.oauth_service.handle_callback')
    @patch('enterprise_auth.core.services.oauth_service.oauth_service.find_user_by_provider_identity')
    def test_user_creation_error_handling(self, mock_find_user, mock_handle_callback):
        """Test handling of user creation errors."""
        # Set up session state
        session = self.client.session
        session[f'oauth_state_{self.provider_name}'] = self.state
        session.save()
        
        # Mock successful callback but user creation failure
        mock_token_data = Mock()
        mock_user_data = Mock()
        mock_user_data.provider_user_id = 'test_user_id'
        mock_user_data.email = None  # Missing email will cause error
        mock_handle_callback.return_value = (mock_token_data, mock_user_data)
        mock_find_user.return_value = None
        
        response = self.client.post(self.callback_url, {
            'code': self.code,
            'state': self.state
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.json()
        
        self.assertEqual(response_data['error']['code'], 'OAUTH_MISSING_USER_DATA')
        self.assertIn('fallback_methods', response_data)
    
    @patch('enterprise_auth.core.services.jwt_service.jwt_service.generate_token_pair')
    @patch('enterprise_auth.core.services.oauth_service.oauth_service.link_user_identity')
    @patch('enterprise_auth.core.services.oauth_service.oauth_service.handle_callback')
    @patch('enterprise_auth.core.services.oauth_service.oauth_service.find_user_by_provider_identity')
    def test_token_generation_error_handling(self, mock_find_user, mock_handle_callback, mock_link_identity, mock_generate_tokens):
        """Test handling of JWT token generation errors."""
        # Set up session state
        session = self.client.session
        session[f'oauth_state_{self.provider_name}'] = self.state
        session.save()
        
        # Create test user
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Mock successful callback, user finding, and identity linking but token generation failure
        mock_token_data = Mock()
        mock_user_data = Mock()
        mock_user_data.provider_user_id = 'test_user_id'
        mock_user_data.email = 'test@example.com'
        mock_user_data.first_name = 'Test'
        mock_user_data.last_name = 'User'
        mock_user_data.verified_email = True
        mock_user_data.profile_picture_url = None
        mock_user_data.locale = 'en'
        mock_user_data.timezone = 'UTC'
        mock_user_data.username = 'testuser'
        
        mock_identity = Mock()
        mock_identity.id = 'test_identity_id'
        mock_identity.is_primary = True
        mock_identity.linked_at = timezone.now()
        
        mock_handle_callback.return_value = (mock_token_data, mock_user_data)
        mock_find_user.return_value = user
        mock_link_identity.return_value = mock_identity
        mock_generate_tokens.side_effect = Exception("Token generation failed")
        
        response = self.client.post(self.callback_url, {
            'code': self.code,
            'state': self.state
        })
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        response_data = response.json()
        
        self.assertEqual(response_data['error']['code'], 'OAUTH_TOKEN_GENERATION_ERROR')
        self.assertIn('fallback_methods', response_data)
    
    def test_oauth_error_details_endpoint(self):
        """Test OAuth error details endpoint."""
        error_details_url = reverse('core:oauth_error_details', kwargs={'provider_name': self.provider_name})
        
        response = self.client.get(error_details_url, {
            'error_code': 'access_denied',
            'correlation_id': self.correlation_id
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        
        self.assertEqual(response_data['provider'], self.provider_name)
        self.assertEqual(response_data['error_code'], 'access_denied')
        self.assertEqual(response_data['correlation_id'], self.correlation_id)
        self.assertIn('error_info', response_data)
        self.assertIn('fallback_methods', response_data)
        self.assertIn('provider_metrics', response_data)
        
        # Check error info structure
        error_info = response_data['error_info']
        self.assertIn('title', error_info)
        self.assertIn('description', error_info)
        self.assertIn('common_causes', error_info)
        self.assertIn('troubleshooting_steps', error_info)
    
    def test_oauth_metrics_summary_endpoint(self):
        """Test OAuth metrics summary endpoint."""
        metrics_url = reverse('core:oauth_metrics_summary')
        
        # Record some test metrics
        oauth_metrics.record_successful_authentication(
            provider=self.provider_name,
            user_id='test_user_id',
            is_new_user=False,
            correlation_id=self.correlation_id
        )
        oauth_metrics.record_callback_error(
            provider=self.provider_name,
            error_type='processing_error'
        )
        
        response = self.client.get(metrics_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        
        self.assertIn('overall_metrics', response_data)
        self.assertIn('provider_metrics', response_data)
        self.assertIn('timestamp', response_data)
        
        # Check overall metrics structure
        overall_metrics = response_data['overall_metrics']
        self.assertIn('total_successful_authentications', overall_metrics)
        self.assertIn('total_callback_errors', overall_metrics)
        self.assertIn('overall_success_rate', overall_metrics)
    
    def test_oauth_metrics_summary_specific_provider(self):
        """Test OAuth metrics summary for specific provider."""
        metrics_url = reverse('core:oauth_metrics_summary')
        
        # Record some test metrics
        oauth_metrics.record_successful_authentication(
            provider=self.provider_name,
            user_id='test_user_id',
            is_new_user=True,
            correlation_id=self.correlation_id
        )
        
        response = self.client.get(metrics_url, {'provider': self.provider_name})
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        response_data = response.json()
        
        self.assertIn('provider_metrics', response_data)
        self.assertNotIn('overall_metrics', response_data)
        
        # Check provider metrics structure
        provider_metrics = response_data['provider_metrics']
        self.assertEqual(provider_metrics['provider'], self.provider_name)
        self.assertIn('successful_authentications', provider_metrics)
        self.assertIn('new_user_registrations', provider_metrics)
        self.assertIn('success_rate', provider_metrics)


class OAuthCallbackServiceTestCase(TestCase):
    """Test cases for OAuth callback service."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.service = oauth_callback_service
        self.provider_name = 'google'
        self.correlation_id = secrets.token_urlsafe(16)
    
    def test_generate_fallback_suggestions(self):
        """Test fallback suggestion generation."""
        fallback_methods = ['email_password', 'alternative_oauth']
        suggestions = self.service._generate_fallback_suggestions(
            provider_name=self.provider_name,
            fallback_methods=fallback_methods
        )
        
        self.assertIsInstance(suggestions, list)
        self.assertGreater(len(suggestions), 0)
        
        # Check email/password fallback
        email_fallback = next((s for s in suggestions if s['method'] == 'email_password'), None)
        self.assertIsNotNone(email_fallback)
        self.assertEqual(email_fallback['title'], 'Sign in with Email')
        self.assertEqual(email_fallback['endpoint'], '/api/v1/auth/login')
    
    def test_suggest_email_password_fallback(self):
        """Test email/password fallback suggestion."""
        suggestion = self.service._suggest_email_password_fallback(self.provider_name)
        
        self.assertIsInstance(suggestion, dict)
        self.assertEqual(suggestion['method'], 'email_password')
        self.assertEqual(suggestion['title'], 'Sign in with Email')
        self.assertIn('description', suggestion)
        self.assertIn('endpoint', suggestion)
        self.assertIn('estimated_time', suggestion)
    
    def test_suggest_magic_link_fallback(self):
        """Test magic link fallback suggestion."""
        suggestion = self.service._suggest_magic_link_fallback(self.provider_name)
        
        self.assertIsInstance(suggestion, dict)
        self.assertEqual(suggestion['method'], 'magic_link')
        self.assertEqual(suggestion['title'], 'Sign in with Magic Link')
        self.assertIn('description', suggestion)
        self.assertIn('endpoint', suggestion)
    
    @patch('enterprise_auth.core.services.oauth_service.oauth_service.get_available_providers')
    def test_suggest_alternative_oauth_fallback(self, mock_get_providers):
        """Test alternative OAuth provider fallback suggestion."""
        # Mock available providers
        mock_get_providers.return_value = [
            {'name': 'google', 'display_name': 'Google', 'enabled': True},
            {'name': 'github', 'display_name': 'GitHub', 'enabled': True},
            {'name': 'microsoft', 'display_name': 'Microsoft', 'enabled': True},
        ]
        
        # Test with google as current provider (should suggest github or microsoft)
        suggestion = self.service._suggest_alternative_oauth_fallback('google')
        
        self.assertIsNotNone(suggestion)
        self.assertEqual(suggestion['method'], 'oauth')
        self.assertIn(suggestion['provider'], ['github', 'microsoft'])
        self.assertIn('title', suggestion)
        self.assertIn('endpoint', suggestion)
    
    def test_handle_oauth_provider_error_access_denied(self):
        """Test handling of access_denied OAuth provider error."""
        response = self.service.handle_oauth_provider_error(
            provider_name=self.provider_name,
            oauth_error='access_denied',
            error_description='User denied access',
            error_uri='',
            correlation_id=self.correlation_id
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.data
        
        self.assertEqual(response_data['error']['code'], 'OAUTH_PROVIDER_ERROR')
        self.assertEqual(response_data['error']['oauth_error'], 'access_denied')
        self.assertIn('fallback_methods', response_data)
        self.assertTrue(response_data['retry_available'])
    
    def test_handle_oauth_provider_error_server_error(self):
        """Test handling of server_error OAuth provider error."""
        response = self.service.handle_oauth_provider_error(
            provider_name=self.provider_name,
            oauth_error='server_error',
            error_description='Internal server error',
            error_uri='',
            correlation_id=self.correlation_id
        )
        
        self.assertEqual(response.status_code, status.HTTP_502_BAD_GATEWAY)
        response_data = response.data
        
        self.assertEqual(response_data['error']['code'], 'OAUTH_PROVIDER_ERROR')
        self.assertEqual(response_data['error']['oauth_error'], 'server_error')
        self.assertTrue(response_data['retry_available'])
    
    def test_handle_missing_parameters_error(self):
        """Test handling of missing parameters error."""
        response = self.service.handle_missing_parameters_error(
            provider_name=self.provider_name,
            correlation_id=self.correlation_id
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.data
        
        self.assertEqual(response_data['error']['code'], 'OAUTH_MISSING_PARAMETERS')
        self.assertIn('fallback_methods', response_data)
        self.assertTrue(response_data['retry_available'])
    
    def test_handle_state_mismatch_error(self):
        """Test handling of state mismatch error."""
        response = self.service.handle_state_mismatch_error(
            provider_name=self.provider_name,
            correlation_id=self.correlation_id
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response_data = response.data
        
        self.assertEqual(response_data['error']['code'], 'OAUTH_STATE_MISMATCH')
        self.assertIn('security_warning', response_data['error'])
        self.assertIn('fallback_methods', response_data)


class OAuthMetricsTestCase(TestCase):
    """Test cases for OAuth metrics collection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.metrics = oauth_metrics
        self.provider_name = 'google'
        self.correlation_id = secrets.token_urlsafe(16)
        
        # Clear cache before each test
        cache.clear()
    
    def test_record_provider_error(self):
        """Test recording OAuth provider errors."""
        error_code = 'access_denied'
        error_description = 'User denied access'
        
        self.metrics.record_provider_error(
            provider=self.provider_name,
            error_code=error_code,
            error_description=error_description
        )
        
        # Check that error was recorded
        error_key = f"{self.metrics.cache_prefix}:provider_errors:{self.provider_name}:{error_code}"
        error_count = cache.get(error_key, 0)
        self.assertEqual(error_count, 1)
        
        # Check recent errors
        recent_errors_key = f"{self.metrics.cache_prefix}:recent_errors:{self.provider_name}"
        recent_errors = cache.get(recent_errors_key, [])
        self.assertEqual(len(recent_errors), 1)
        self.assertEqual(recent_errors[0]['error_code'], error_code)
    
    def test_record_callback_error(self):
        """Test recording OAuth callback errors."""
        error_type = 'processing_error'
        
        self.metrics.record_callback_error(
            provider=self.provider_name,
            error_type=error_type
        )
        
        # Check that error was recorded
        error_key = f"{self.metrics.cache_prefix}:callback_errors:{self.provider_name}:{error_type}"
        error_count = cache.get(error_key, 0)
        self.assertEqual(error_count, 1)
        
        # Check total callback errors
        total_key = f"{self.metrics.cache_prefix}:callback_errors:total"
        total_count = cache.get(total_key, 0)
        self.assertEqual(total_count, 1)
    
    def test_record_security_event(self):
        """Test recording OAuth security events."""
        event_type = 'state_mismatch'
        severity = 'high'
        
        self.metrics.record_security_event(
            provider=self.provider_name,
            event_type=event_type,
            severity=severity
        )
        
        # Check that event was recorded
        event_key = f"{self.metrics.cache_prefix}:security_events:{self.provider_name}:{event_type}"
        event_count = cache.get(event_key, 0)
        self.assertEqual(event_count, 1)
        
        # Check severity tracking
        severity_key = f"{self.metrics.cache_prefix}:security_events:severity:{severity}"
        severity_count = cache.get(severity_key, 0)
        self.assertEqual(severity_count, 1)
    
    def test_record_successful_authentication(self):
        """Test recording successful OAuth authentication."""
        user_id = 'test_user_id'
        is_new_user = True
        
        self.metrics.record_successful_authentication(
            provider=self.provider_name,
            user_id=user_id,
            is_new_user=is_new_user,
            correlation_id=self.correlation_id
        )
        
        # Check success counter
        success_key = f"{self.metrics.cache_prefix}:successful_auth:{self.provider_name}"
        success_count = cache.get(success_key, 0)
        self.assertEqual(success_count, 1)
        
        # Check new user counter
        new_user_key = f"{self.metrics.cache_prefix}:new_users:{self.provider_name}"
        new_user_count = cache.get(new_user_key, 0)
        self.assertEqual(new_user_count, 1)
        
        # Check total success counter
        total_key = f"{self.metrics.cache_prefix}:successful_auth:total"
        total_count = cache.get(total_key, 0)
        self.assertEqual(total_count, 1)
    
    def test_get_provider_metrics(self):
        """Test getting provider-specific metrics."""
        # Record some test data
        self.metrics.record_successful_authentication(
            provider=self.provider_name,
            user_id='test_user_id',
            is_new_user=False,
            correlation_id=self.correlation_id
        )
        self.metrics.record_callback_error(
            provider=self.provider_name,
            error_type='processing_error'
        )
        
        metrics = self.metrics.get_provider_metrics(self.provider_name)
        
        self.assertEqual(metrics['provider'], self.provider_name)
        self.assertEqual(metrics['successful_authentications'], 1)
        self.assertEqual(metrics['callback_errors']['processing_error'], 1)
        self.assertEqual(metrics['success_rate'], 0.5)  # 1 success, 1 error
    
    def test_get_overall_metrics(self):
        """Test getting overall OAuth metrics."""
        # Record some test data
        self.metrics.record_successful_authentication(
            provider=self.provider_name,
            user_id='test_user_id',
            is_new_user=False,
            correlation_id=self.correlation_id
        )
        self.metrics.record_callback_error(
            provider=self.provider_name,
            error_type='processing_error'
        )
        
        metrics = self.metrics.get_overall_metrics()
        
        self.assertEqual(metrics['total_successful_authentications'], 1)
        self.assertEqual(metrics['total_callback_errors'], 1)
        self.assertEqual(metrics['overall_success_rate'], 0.5)
        self.assertIn('timestamp', metrics)