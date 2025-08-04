"""
Tests for Google OAuth provider implementation.

This module contains comprehensive tests for the Google OAuth provider,
including authorization URL generation, token exchange, user data normalization,
and error handling scenarios.
"""

import json
import uuid
from unittest.mock import Mock, patch, MagicMock
from urllib.error import HTTPError

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model

from ..exceptions import (
    ConfigurationError,
    OAuthError,
    OAuthProviderError,
    OAuthTokenExpiredError,
)
from ..services.providers.google_oauth import GoogleOAuthProvider
from ..services.oauth_provider import ProviderConfig, NormalizedUserData, TokenData
from ..models.user import UserIdentity

User = get_user_model()


class GoogleOAuthProviderTest(TestCase):
    """Test cases for Google OAuth provider."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.provider = GoogleOAuthProvider()
        self.config = ProviderConfig(
            client_id='test-client-id.apps.googleusercontent.com',
            client_secret='test-client-secret',
            redirect_uri='https://example.com/auth/google/callback',
            scopes=['openid', 'email', 'profile'],
            authorization_url='https://accounts.google.com/o/oauth2/v2/auth',
            token_url='https://oauth2.googleapis.com/token',
            user_info_url='https://www.googleapis.com/oauth2/v2/userinfo',
            revoke_url='https://oauth2.googleapis.com/revoke',
            extra_params={'access_type': 'offline', 'prompt': 'consent'},
            timeout=30,
            use_pkce=True
        )
        self.provider.configure(self.config)
    
    def test_provider_metadata(self):
        """Test provider metadata properties."""
        self.assertEqual(self.provider.provider_name, 'google')
        self.assertEqual(self.provider.display_name, 'Google')
        
        supported_scopes = self.provider.supported_scopes
        self.assertIn('openid', supported_scopes)
        self.assertIn('email', supported_scopes)
        self.assertIn('profile', supported_scopes)
        self.assertIn('https://www.googleapis.com/auth/userinfo.email', supported_scopes)
    
    def test_configuration_validation(self):
        """Test provider configuration validation."""
        # Valid configuration should pass
        self.assertTrue(self.provider.validate_configuration())
        
        # Missing required scopes should fail
        invalid_config = ProviderConfig(
            client_id='test-client-id',
            client_secret='test-client-secret',
            redirect_uri='https://example.com/callback',
            scopes=['profile'],  # Missing 'openid' and 'email'
            authorization_url='https://accounts.google.com/o/oauth2/v2/auth',
            token_url='https://oauth2.googleapis.com/token',
            user_info_url='https://www.googleapis.com/oauth2/v2/userinfo',
        )
        
        invalid_provider = GoogleOAuthProvider()
        
        with self.assertRaises(ConfigurationError):
            invalid_provider.configure(invalid_config)
    
    def test_authorization_url_generation(self):
        """Test OAuth authorization URL generation with PKCE."""
        state = 'test-state-123'
        scopes = ['openid', 'email', 'profile']
        
        auth_request = self.provider.get_authorization_url(
            state=state,
            scopes=scopes
        )
        
        self.assertIsNotNone(auth_request.authorization_url)
        self.assertEqual(auth_request.state, state)
        self.assertIsNotNone(auth_request.code_verifier)
        self.assertIsNotNone(auth_request.code_challenge)
        
        # Check that URL contains expected parameters
        url = auth_request.authorization_url
        self.assertIn('client_id=test-client-id.apps.googleusercontent.com', url)
        self.assertIn('redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fgoogle%2Fcallback', url)
        self.assertIn('response_type=code', url)
        self.assertIn(f'state={state}', url)
        self.assertIn('scope=openid+email+profile', url)
        self.assertIn('code_challenge=', url)
        self.assertIn('code_challenge_method=S256', url)
        self.assertIn('access_type=offline', url)
        self.assertIn('prompt=consent', url)
    
    def test_authorization_url_with_default_scopes(self):
        """Test authorization URL generation with default scopes."""
        state = 'test-state-456'
        
        auth_request = self.provider.get_authorization_url(state=state)
        
        # Should include required scopes even if not explicitly provided
        url = auth_request.authorization_url
        self.assertIn('scope=openid+email+profile', url)
    
    @patch('enterprise_auth.core.services.providers.google_oauth.GoogleOAuthProvider._make_http_request')
    def test_token_exchange_success(self, mock_request):
        """Test successful token exchange."""
        # Mock token response
        mock_token_response = {
            'access_token': 'test-access-token',
            'refresh_token': 'test-refresh-token',
            'expires_in': 3600,
            'token_type': 'Bearer',
            'scope': 'openid email profile',
            'id_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXVkIjoidGVzdC1jbGllbnQtaWQiLCJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIn0.signature'
        }
        mock_request.return_value = mock_token_response
        
        token_data = self.provider.exchange_code_for_token(
            code='test-auth-code',
            state='test-state',
            code_verifier='test-code-verifier'
        )
        
        self.assertEqual(token_data.access_token, 'test-access-token')
        self.assertEqual(token_data.refresh_token, 'test-refresh-token')
        self.assertEqual(token_data.expires_in, 3600)
        self.assertEqual(token_data.token_type, 'Bearer')
        self.assertEqual(token_data.scope, 'openid email profile')
        self.assertIsNotNone(token_data.id_token)
        
        # Verify the request was made with correct parameters
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        self.assertEqual(call_args[0][0], 'https://oauth2.googleapis.com/token')
        self.assertIn('code', call_args[1]['data'])
        self.assertIn('code_verifier', call_args[1]['data'])
    
    @patch('enterprise_auth.core.services.providers.google_oauth.GoogleOAuthProvider._make_http_request')
    def test_user_info_retrieval_openid_connect(self, mock_request):
        """Test user info retrieval from OpenID Connect endpoint."""
        # Mock user info response
        mock_user_response = {
            'sub': '1234567890',
            'email': 'test@example.com',
            'email_verified': True,
            'given_name': 'Test',
            'family_name': 'User',
            'name': 'Test User',
            'picture': 'https://example.com/avatar.jpg',
            'locale': 'en-US',
            'hd': 'example.com'  # Hosted domain
        }
        mock_request.return_value = mock_user_response
        
        user_data = self.provider.get_user_info('test-access-token')
        
        self.assertIsInstance(user_data, NormalizedUserData)
        self.assertEqual(user_data.provider_user_id, '1234567890')
        self.assertEqual(user_data.email, 'test@example.com')
        self.assertEqual(user_data.first_name, 'Test')
        self.assertEqual(user_data.last_name, 'User')
        self.assertEqual(user_data.username, 'test@example.com')
        self.assertEqual(user_data.profile_picture_url, 'https://example.com/avatar.jpg')
        self.assertEqual(user_data.locale, 'en-US')
        self.assertTrue(user_data.verified_email)
        self.assertIsNotNone(user_data.raw_data)
        self.assertEqual(user_data.raw_data['hd'], 'example.com')
    
    @patch('enterprise_auth.core.services.providers.google_oauth.GoogleOAuthProvider._make_http_request')
    def test_user_info_retrieval_oauth2_fallback(self, mock_request):
        """Test user info retrieval with OAuth2 endpoint fallback."""
        # Mock OpenID Connect endpoint failure, OAuth2 endpoint success
        def mock_request_side_effect(url, *args, **kwargs):
            if 'openidconnect.googleapis.com' in url:
                # Simulate OpenID Connect endpoint failure
                error = HTTPError(url, 401, 'Unauthorized', {}, None)
                raise error
            else:
                # OAuth2 endpoint success
                return {
                    'id': '1234567890',
                    'email': 'test@example.com',
                    'verified_email': True,  # Boolean like OAuth2 endpoint returns
                    'given_name': 'Test',
                    'family_name': 'User',
                    'name': 'Test User',
                    'picture': 'https://example.com/avatar.jpg',
                    'locale': 'en-US'
                }
        
        mock_request.side_effect = mock_request_side_effect
        
        user_data = self.provider.get_user_info('test-access-token')
        
        self.assertEqual(user_data.provider_user_id, '1234567890')
        self.assertEqual(user_data.email, 'test@example.com')
        self.assertTrue(user_data.verified_email)  # Should be converted from string 'true'
        
        # Should have made two requests (OpenID Connect failed, OAuth2 succeeded)
        self.assertEqual(mock_request.call_count, 2)
    
    @patch('enterprise_auth.core.services.providers.google_oauth.GoogleOAuthProvider._make_http_request')
    def test_user_info_token_expired(self, mock_request):
        """Test user info retrieval with expired token."""
        # Mock token expired error
        error = HTTPError('https://example.com', 401, 'Unauthorized', {}, None)
        mock_request.side_effect = error
        
        with self.assertRaises(OAuthTokenExpiredError):
            self.provider.get_user_info('expired-token')
    
    def test_user_data_normalization_with_name_parsing(self):
        """Test user data normalization when name needs to be parsed."""
        raw_data = {
            'sub': '1234567890',
            'email': 'test@example.com',
            'email_verified': 'true',  # String boolean
            'name': 'John Doe Smith',  # Full name to be parsed
            'picture': 'https://example.com/avatar.jpg',
            'locale': 'fr-FR'
        }
        
        normalized_data = self.provider._normalize_google_user_data(raw_data)
        
        self.assertEqual(normalized_data.first_name, 'John')
        self.assertEqual(normalized_data.last_name, 'Doe Smith')
        self.assertTrue(normalized_data.verified_email)  # Converted from string
        self.assertEqual(normalized_data.timezone, 'Europe/Paris')  # Mapped from locale
    
    def test_user_data_normalization_missing_required_field(self):
        """Test user data normalization with missing required field."""
        raw_data = {
            'email': 'test@example.com',
            # Missing 'sub' or 'id' field
        }
        
        with self.assertRaises(OAuthProviderError):
            self.provider._normalize_google_user_data(raw_data)
    
    @patch('enterprise_auth.core.services.providers.google_oauth.GoogleOAuthProvider._make_http_request')
    def test_token_refresh_success(self, mock_request):
        """Test successful token refresh."""
        mock_refresh_response = {
            'access_token': 'new-access-token',
            'expires_in': 3600,
            'token_type': 'Bearer',
            'scope': 'openid email profile'
            # Note: Google may not return a new refresh token
        }
        mock_request.return_value = mock_refresh_response
        
        token_data = self.provider.refresh_access_token('test-refresh-token')
        
        self.assertEqual(token_data.access_token, 'new-access-token')
        self.assertEqual(token_data.refresh_token, 'test-refresh-token')  # Should keep old one
        self.assertEqual(token_data.expires_in, 3600)
    
    @patch('enterprise_auth.core.services.providers.google_oauth.GoogleOAuthProvider._make_http_request')
    def test_token_revocation_success(self, mock_request):
        """Test successful token revocation."""
        mock_request.return_value = {}  # Google returns empty response on success
        
        result = self.provider.revoke_token('test-token')
        
        self.assertTrue(result)
        mock_request.assert_called_once_with(
            'https://oauth2.googleapis.com/revoke',
            data={'token': 'test-token'},
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
    
    @patch('enterprise_auth.core.services.providers.google_oauth.GoogleOAuthProvider._make_http_request')
    def test_token_revocation_http_200_success(self, mock_request):
        """Test token revocation with HTTP 200 response."""
        # Google sometimes returns 200 for successful revocation
        error = HTTPError('https://example.com', 200, 'OK', {}, None)
        mock_request.side_effect = error
        
        result = self.provider.revoke_token('test-token')
        
        self.assertTrue(result)
    
    def test_id_token_decoding(self):
        """Test ID token payload decoding."""
        # Create a simple JWT-like token (header.payload.signature)
        import base64
        
        payload = {
            'iss': 'https://accounts.google.com',
            'aud': 'test-client-id',
            'sub': '1234567890',
            'email': 'test@example.com'
        }
        
        # Encode payload
        payload_json = json.dumps(payload)
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
        
        # Create fake JWT
        fake_jwt = f'header.{payload_b64}.signature'
        
        decoded_payload = self.provider._decode_id_token(fake_jwt)
        
        self.assertEqual(decoded_payload['iss'], 'https://accounts.google.com')
        self.assertEqual(decoded_payload['aud'], 'test-client-id')
        self.assertEqual(decoded_payload['sub'], '1234567890')
        self.assertEqual(decoded_payload['email'], 'test@example.com')
    
    def test_provider_metadata_retrieval(self):
        """Test provider metadata retrieval."""
        metadata = self.provider.get_provider_metadata()
        
        self.assertEqual(metadata['provider_name'], 'google')
        self.assertEqual(metadata['display_name'], 'Google')
        self.assertTrue(metadata['supports_pkce'])
        self.assertTrue(metadata['supports_refresh_token'])
        self.assertTrue(metadata['supports_id_token'])
        self.assertTrue(metadata['supports_openid_connect'])
        self.assertIn('openid', metadata['supported_scopes'])
        self.assertIn('email', metadata['supported_scopes'])
        self.assertIn('profile', metadata['supported_scopes'])


class GoogleOAuthIntegrationTest(TestCase):
    """Integration tests for Google OAuth provider with database models."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.user = User.objects.create_user(
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
        
        self.provider = GoogleOAuthProvider()
        self.config = ProviderConfig(
            client_id='test-client-id',
            client_secret='test-client-secret',
            redirect_uri='https://example.com/callback',
            scopes=['openid', 'email', 'profile'],
            authorization_url='https://accounts.google.com/o/oauth2/v2/auth',
            token_url='https://oauth2.googleapis.com/token',
            user_info_url='https://www.googleapis.com/oauth2/v2/userinfo',
        )
        self.provider.configure(self.config)
    
    def test_user_identity_creation(self):
        """Test creating UserIdentity from Google OAuth data."""
        # Create normalized user data
        user_data = NormalizedUserData(
            provider_user_id='google-123456',
            email='test@example.com',
            first_name='Test',
            last_name='User',
            username='test@example.com',
            profile_picture_url='https://example.com/avatar.jpg',
            locale='en-US',
            verified_email=True,
            raw_data={'sub': 'google-123456', 'hd': 'example.com'}
        )
        
        # Create UserIdentity
        identity = UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id=user_data.provider_user_id,
            provider_username=user_data.username,
            provider_email=user_data.email,
            provider_data=user_data.raw_data,
            is_verified=user_data.verified_email,
            is_primary=True
        )
        
        # Verify identity was created correctly
        self.assertEqual(identity.user, self.user)
        self.assertEqual(identity.provider, 'google')
        self.assertEqual(identity.provider_user_id, 'google-123456')
        self.assertEqual(identity.provider_email, 'test@example.com')
        self.assertTrue(identity.is_verified)
        self.assertTrue(identity.is_primary)
        self.assertEqual(identity.provider_data['hd'], 'example.com')
    
    def test_user_identity_token_storage(self):
        """Test storing encrypted tokens in UserIdentity."""
        identity = UserIdentity.objects.create(
            user=self.user,
            provider='google',
            provider_user_id='google-123456',
            provider_email='test@example.com'
        )
        
        # Store access token
        identity.set_access_token('test-access-token', expires_in=3600)
        
        # Store refresh token
        identity.set_refresh_token('test-refresh-token')
        
        # Verify tokens can be retrieved
        self.assertEqual(identity.get_access_token(), 'test-access-token')
        self.assertEqual(identity.get_refresh_token(), 'test-refresh-token')
        self.assertIsNotNone(identity.token_expires_at)
        
        # Verify tokens are encrypted in database
        identity.refresh_from_db()
        self.assertNotEqual(identity.access_token, 'test-access-token')
        self.assertNotEqual(identity.refresh_token, 'test-refresh-token')


@override_settings(
    GOOGLE_OAUTH_CLIENT_ID='test-client-id',
    GOOGLE_OAUTH_CLIENT_SECRET='test-client-secret',
    GOOGLE_OAUTH_REDIRECT_URI='https://example.com/callback'
)
class GoogleOAuthConfigurationTest(TestCase):
    """Test Google OAuth provider configuration from Django settings."""
    
    def test_configuration_from_settings(self):
        """Test loading configuration from Django settings."""
        from ..services.oauth_config import oauth_config_manager
        
        config = oauth_config_manager.load_config_from_settings('google')
        
        # Should return None since we don't have OAUTH_PROVIDERS setting
        self.assertIsNone(config)
    
    def test_configuration_from_environment(self):
        """Test loading configuration from environment variables."""
        import os
        from unittest.mock import patch
        from ..services.oauth_config import oauth_config_manager
        
        env_vars = {
            'OAUTH_GOOGLE_CLIENT_ID': 'env-client-id',
            'OAUTH_GOOGLE_CLIENT_SECRET': 'env-client-secret',
            'OAUTH_GOOGLE_REDIRECT_URI': 'https://env.example.com/callback',
            'OAUTH_GOOGLE_SCOPES': 'openid,email,profile',
            'OAUTH_GOOGLE_AUTHORIZATION_URL': 'https://accounts.google.com/o/oauth2/v2/auth',
            'OAUTH_GOOGLE_TOKEN_URL': 'https://oauth2.googleapis.com/token',
            'OAUTH_GOOGLE_USER_INFO_URL': 'https://www.googleapis.com/oauth2/v2/userinfo',
            'OAUTH_GOOGLE_USE_PKCE': 'true',
        }
        
        with patch.dict(os.environ, env_vars):
            config = oauth_config_manager.load_config_from_env('google')
            
            self.assertIsNotNone(config)
            self.assertEqual(config.client_id, 'env-client-id')
            self.assertEqual(config.client_secret, 'env-client-secret')
            self.assertEqual(config.redirect_uri, 'https://env.example.com/callback')
            self.assertEqual(config.scopes, ['openid', 'email', 'profile'])
            self.assertTrue(config.use_pkce)