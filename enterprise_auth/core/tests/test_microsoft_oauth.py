"""
Tests for Microsoft OAuth provider implementation.

This module contains comprehensive tests for the Microsoft OAuth provider,
including authorization URL generation, token exchange, user data normalization,
Microsoft Graph API integration, and error handling scenarios.
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
from ..services.providers.microsoft_oauth import MicrosoftOAuthProvider
from ..services.oauth_provider import ProviderConfig, NormalizedUserData, TokenData
from ..models.user import UserIdentity

User = get_user_model()


class MicrosoftOAuthProviderTest(TestCase):
    """Test cases for Microsoft OAuth provider."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.provider = MicrosoftOAuthProvider()
        self.config = ProviderConfig(
            client_id='test-microsoft-client-id',
            client_secret='test-microsoft-client-secret',
            redirect_uri='https://example.com/auth/microsoft/callback',
            scopes=['openid', 'profile', 'email', 'User.Read'],
            authorization_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
            user_info_url='https://graph.microsoft.com/v1.0/me',
            revoke_url='https://login.microsoftonline.com/common/oauth2/v2.0/logout',
            extra_params={'response_mode': 'query', 'prompt': 'select_account'},
            timeout=30,
            use_pkce=True
        )
        self.provider.configure(self.config)
    
    def test_provider_metadata(self):
        """Test provider metadata properties."""
        self.assertEqual(self.provider.provider_name, 'microsoft')
        self.assertEqual(self.provider.display_name, 'Microsoft')
        
        supported_scopes = self.provider.supported_scopes
        self.assertIn('openid', supported_scopes)
        self.assertIn('email', supported_scopes)
        self.assertIn('profile', supported_scopes)
        self.assertIn('User.Read', supported_scopes)
        self.assertIn('offline_access', supported_scopes)
        
        # Test Microsoft Graph API scopes
        self.assertIn('Directory.Read.All', supported_scopes)
        self.assertIn('Group.Read.All', supported_scopes)
        self.assertIn('User.ReadBasic.All', supported_scopes)
    
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
            authorization_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
            user_info_url='https://graph.microsoft.com/v1.0/me',
        )
        
        invalid_provider = MicrosoftOAuthProvider()
        
        with self.assertRaises(ConfigurationError):
            invalid_provider.configure(invalid_config)
    
    def test_authorization_url_generation(self):
        """Test OAuth authorization URL generation with PKCE."""
        state = 'test-state-123'
        scopes = ['openid', 'profile', 'email', 'User.Read']
        
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
        self.assertIn('client_id=test-microsoft-client-id', url)
        self.assertIn('redirect_uri=https%3A%2F%2Fexample.com%2Fauth%2Fmicrosoft%2Fcallback', url)
        self.assertIn('response_type=code', url)
        self.assertIn(f'state={state}', url)
        self.assertIn('scope=openid+profile+email+User.Read', url)
        self.assertIn('code_challenge=', url)
        self.assertIn('code_challenge_method=S256', url)
        self.assertIn('response_mode=query', url)
        self.assertIn('prompt=select_account', url)
    
    def test_authorization_url_with_default_scopes(self):
        """Test authorization URL generation with default scopes."""
        state = 'test-state-456'
        
        auth_request = self.provider.get_authorization_url(state=state)
        
        # Should include required scopes even if not explicitly provided
        url = auth_request.authorization_url
        self.assertIn('scope=openid+profile+email+User.Read', url)
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_token_exchange_success(self, mock_request):
        """Test successful token exchange."""
        # Mock token response
        mock_token_response = {
            'access_token': 'test-microsoft-access-token',
            'refresh_token': 'test-microsoft-refresh-token',
            'expires_in': 3600,
            'token_type': 'Bearer',
            'scope': 'openid profile email User.Read',
            'id_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vdGVzdC10ZW5hbnQtaWQvdjIuMCIsImF1ZCI6InRlc3QtY2xpZW50LWlkIiwic3ViIjoiMTIzNDU2Nzg5MCIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsInRpZCI6InRlc3QtdGVuYW50LWlkIn0.signature'
        }
        mock_request.return_value = mock_token_response
        
        token_data = self.provider.exchange_code_for_token(
            code='test-auth-code',
            state='test-state',
            code_verifier='test-code-verifier'
        )
        
        self.assertEqual(token_data.access_token, 'test-microsoft-access-token')
        self.assertEqual(token_data.refresh_token, 'test-microsoft-refresh-token')
        self.assertEqual(token_data.expires_in, 3600)
        self.assertEqual(token_data.token_type, 'Bearer')
        self.assertEqual(token_data.scope, 'openid profile email User.Read')
        self.assertIsNotNone(token_data.id_token)
        
        # Verify the request was made with correct parameters
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        self.assertEqual(call_args[0][0], 'https://login.microsoftonline.com/common/oauth2/v2.0/token')
        self.assertIn('code', call_args[1]['data'])
        self.assertIn('code_verifier', call_args[1]['data'])
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._get_user_profile')
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._get_user_photo_url')
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_user_info_retrieval_personal_account(self, mock_request, mock_photo, mock_profile):
        """Test user info retrieval for personal Microsoft account."""
        # Mock user info response for personal account
        mock_user_response = {
            'id': '1234567890abcdef',
            'userPrincipalName': 'test@outlook.com',
            'displayName': 'Test User',
            'givenName': 'Test',
            'surname': 'User',
            'mail': 'test@outlook.com',
            'jobTitle': None,
            'department': None,
            'companyName': None,
            'officeLocation': None,
            'businessPhones': [],
            'mobilePhone': None,
            'preferredLanguage': 'en-US',
            'userType': 'Member',
            'accountEnabled': True,
            'usageLocation': 'US'
        }
        mock_request.return_value = mock_user_response
        mock_profile.return_value = None
        mock_photo.return_value = 'https://graph.microsoft.com/v1.0/me/photo/$value'
        
        user_data = self.provider.get_user_info('test-access-token')
        
        self.assertIsInstance(user_data, NormalizedUserData)
        self.assertEqual(user_data.provider_user_id, '1234567890abcdef')
        self.assertEqual(user_data.email, 'test@outlook.com')
        self.assertEqual(user_data.first_name, 'Test')
        self.assertEqual(user_data.last_name, 'User')
        self.assertEqual(user_data.username, 'test@outlook.com')
        self.assertEqual(user_data.profile_picture_url, 'https://graph.microsoft.com/v1.0/me/photo/$value')
        self.assertEqual(user_data.locale, 'en-US')
        self.assertTrue(user_data.verified_email)
        self.assertIsNotNone(user_data.raw_data)
        
        # Check Microsoft-specific data
        microsoft_data = user_data.raw_data['microsoft_specific']
        self.assertEqual(microsoft_data['account_type'], 'personal')
        self.assertEqual(microsoft_data['user_principal_name'], 'test@outlook.com')
        self.assertEqual(microsoft_data['display_name'], 'Test User')
        self.assertEqual(microsoft_data['preferred_language'], 'en-US')
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._get_user_profile')
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._get_user_photo_url')
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_user_info_retrieval_work_school_account(self, mock_request, mock_photo, mock_profile):
        """Test user info retrieval for work/school Microsoft account."""
        # Mock user info response for work/school account
        mock_user_response = {
            'id': 'abcdef1234567890',
            'userPrincipalName': 'test@company.com',
            'displayName': 'Test Employee',
            'givenName': 'Test',
            'surname': 'Employee',
            'mail': 'test@company.com',
            'jobTitle': 'Software Engineer',
            'department': 'Engineering',
            'companyName': 'Test Company Inc.',
            'officeLocation': 'Building A, Floor 3',
            'businessPhones': ['+1-555-123-4567'],
            'mobilePhone': '+1-555-987-6543',
            'preferredLanguage': 'en-US',
            'userType': 'Member',
            'accountEnabled': True,
            'usageLocation': 'US',
            'tenantId': 'test-tenant-id-12345'
        }
        mock_request.return_value = mock_user_response
        mock_profile.return_value = {'additional': 'profile_data'}
        mock_photo.return_value = None
        
        user_data = self.provider.get_user_info('test-access-token')
        
        self.assertIsInstance(user_data, NormalizedUserData)
        self.assertEqual(user_data.provider_user_id, 'abcdef1234567890')
        self.assertEqual(user_data.email, 'test@company.com')
        self.assertEqual(user_data.first_name, 'Test')
        self.assertEqual(user_data.last_name, 'Employee')
        self.assertEqual(user_data.username, 'test@company.com')
        self.assertIsNone(user_data.profile_picture_url)
        self.assertEqual(user_data.locale, 'en-US')
        self.assertTrue(user_data.verified_email)
        
        # Check Microsoft-specific data for work/school account
        microsoft_data = user_data.raw_data['microsoft_specific']
        self.assertEqual(microsoft_data['account_type'], 'work_school')
        self.assertEqual(microsoft_data['job_title'], 'Software Engineer')
        self.assertEqual(microsoft_data['department'], 'Engineering')
        self.assertEqual(microsoft_data['company_name'], 'Test Company Inc.')
        self.assertEqual(microsoft_data['office_location'], 'Building A, Floor 3')
        self.assertEqual(microsoft_data['business_phones'], ['+1-555-123-4567'])
        self.assertEqual(microsoft_data['mobile_phone'], '+1-555-987-6543')
        self.assertEqual(microsoft_data['tenant_id'], 'test-tenant-id-12345')
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_user_info_retrieval_token_expired(self, mock_request):
        """Test user info retrieval with expired token."""
        # Mock 401 Unauthorized response
        error = HTTPError('https://graph.microsoft.com/v1.0/me', 401, 'Unauthorized', {}, None)
        mock_request.side_effect = error
        
        with self.assertRaises(OAuthTokenExpiredError):
            self.provider.get_user_info('expired-access-token')
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_user_info_retrieval_api_error(self, mock_request):
        """Test user info retrieval with API error."""
        # Mock 403 Forbidden response
        error = HTTPError('https://graph.microsoft.com/v1.0/me', 403, 'Forbidden', {}, None)
        mock_request.side_effect = error
        
        with self.assertRaises(OAuthProviderError):
            self.provider.get_user_info('test-access-token')
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_get_user_profile_success(self, mock_request):
        """Test successful user profile retrieval."""
        mock_profile_response = {
            'profile': {
                'additional': 'profile_data',
                'interests': ['technology', 'music'],
                'skills': ['Python', 'JavaScript', 'Azure']
            }
        }
        mock_request.return_value = mock_profile_response
        
        profile_data = self.provider._get_user_profile('test-access-token')
        
        self.assertIsNotNone(profile_data)
        self.assertEqual(profile_data['profile']['additional'], 'profile_data')
        self.assertIn('interests', profile_data['profile'])
        self.assertIn('skills', profile_data['profile'])
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_get_user_profile_insufficient_permissions(self, mock_request):
        """Test user profile retrieval with insufficient permissions."""
        # Mock 403 Forbidden response (insufficient permissions)
        error = HTTPError('https://graph.microsoft.com/v1.0/me/profile', 403, 'Forbidden', {}, None)
        mock_request.side_effect = error
        
        profile_data = self.provider._get_user_profile('test-access-token')
        
        self.assertIsNone(profile_data)
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_get_user_photo_url_success(self, mock_request):
        """Test successful user photo URL retrieval."""
        # Mock successful photo metadata response
        mock_photo_metadata = {
            '@odata.mediaContentType': 'image/jpeg',
            'id': '240X240',
            'height': 240,
            'width': 240
        }
        mock_request.return_value = mock_photo_metadata
        
        photo_url = self.provider._get_user_photo_url('test-access-token')
        
        self.assertEqual(photo_url, 'https://graph.microsoft.com/v1.0/me/photo/$value')
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_get_user_photo_url_not_found(self, mock_request):
        """Test user photo URL retrieval when photo doesn't exist."""
        # Mock 404 Not Found response
        error = HTTPError('https://graph.microsoft.com/v1.0/me/photo', 404, 'Not Found', {}, None)
        mock_request.side_effect = error
        
        photo_url = self.provider._get_user_photo_url('test-access-token')
        
        self.assertIsNone(photo_url)
    
    def test_normalize_microsoft_user_data_personal_account(self):
        """Test Microsoft user data normalization for personal account."""
        user_data = {
            'id': '1234567890abcdef',
            'userPrincipalName': 'test@outlook.com',
            'displayName': 'Test User',
            'givenName': 'Test',
            'surname': 'User',
            'mail': 'test@outlook.com',
            'preferredLanguage': 'en-US',
            'usageLocation': 'US'
        }
        
        normalized_data = self.provider._normalize_microsoft_user_data(
            user_data=user_data,
            profile_data=None,
            photo_url=None
        )
        
        self.assertEqual(normalized_data.provider_user_id, '1234567890abcdef')
        self.assertEqual(normalized_data.email, 'test@outlook.com')
        self.assertEqual(normalized_data.first_name, 'Test')
        self.assertEqual(normalized_data.last_name, 'User')
        self.assertEqual(normalized_data.username, 'test@outlook.com')
        self.assertEqual(normalized_data.locale, 'en-US')
        self.assertEqual(normalized_data.timezone, 'America/New_York')  # Based on usage location
        self.assertTrue(normalized_data.verified_email)
        
        # Check account type detection
        microsoft_data = normalized_data.raw_data['microsoft_specific']
        self.assertEqual(microsoft_data['account_type'], 'personal')
    
    def test_normalize_microsoft_user_data_work_school_account(self):
        """Test Microsoft user data normalization for work/school account."""
        user_data = {
            'id': 'abcdef1234567890',
            'userPrincipalName': 'test@company.com',
            'displayName': 'Test Employee',
            'givenName': 'Test',
            'surname': 'Employee',
            'mail': 'test@company.com',
            'jobTitle': 'Software Engineer',
            'department': 'Engineering',
            'companyName': 'Test Company Inc.',
            'preferredLanguage': 'de-DE',
            'usageLocation': 'DE'
        }
        
        normalized_data = self.provider._normalize_microsoft_user_data(
            user_data=user_data,
            profile_data={'additional': 'data'},
            photo_url='https://graph.microsoft.com/v1.0/me/photo/$value'
        )
        
        self.assertEqual(normalized_data.provider_user_id, 'abcdef1234567890')
        self.assertEqual(normalized_data.email, 'test@company.com')
        self.assertEqual(normalized_data.first_name, 'Test')
        self.assertEqual(normalized_data.last_name, 'Employee')
        self.assertEqual(normalized_data.username, 'test@company.com')
        self.assertEqual(normalized_data.profile_picture_url, 'https://graph.microsoft.com/v1.0/me/photo/$value')
        self.assertEqual(normalized_data.locale, 'de-DE')
        self.assertEqual(normalized_data.timezone, 'Europe/Berlin')  # Based on usage location
        self.assertTrue(normalized_data.verified_email)
        
        # Check account type detection
        microsoft_data = normalized_data.raw_data['microsoft_specific']
        self.assertEqual(microsoft_data['account_type'], 'work_school')
        self.assertEqual(microsoft_data['job_title'], 'Software Engineer')
        self.assertEqual(microsoft_data['department'], 'Engineering')
        self.assertEqual(microsoft_data['company_name'], 'Test Company Inc.')
    
    def test_normalize_microsoft_user_data_missing_names(self):
        """Test Microsoft user data normalization when given/surname are missing."""
        user_data = {
            'id': '1234567890abcdef',
            'userPrincipalName': 'test@outlook.com',
            'displayName': 'Test User',
            'mail': 'test@outlook.com',
            'preferredLanguage': 'en-US'
        }
        
        normalized_data = self.provider._normalize_microsoft_user_data(
            user_data=user_data,
            profile_data=None,
            photo_url=None
        )
        
        # Should parse displayName when givenName/surname are missing
        self.assertEqual(normalized_data.first_name, 'Test')
        self.assertEqual(normalized_data.last_name, 'User')
    
    def test_normalize_microsoft_user_data_missing_id(self):
        """Test Microsoft user data normalization with missing user ID."""
        user_data = {
            'userPrincipalName': 'test@outlook.com',
            'displayName': 'Test User',
            'mail': 'test@outlook.com'
        }
        
        with self.assertRaises(OAuthProviderError) as context:
            self.provider._normalize_microsoft_user_data(
                user_data=user_data,
                profile_data=None,
                photo_url=None
            )
        
        self.assertIn("missing required 'id' field", str(context.exception))
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_refresh_access_token_success(self, mock_request):
        """Test successful access token refresh."""
        mock_token_response = {
            'access_token': 'new-access-token',
            'refresh_token': 'new-refresh-token',
            'expires_in': 3600,
            'token_type': 'Bearer',
            'scope': 'openid profile email User.Read'
        }
        mock_request.return_value = mock_token_response
        
        token_data = self.provider.refresh_access_token('old-refresh-token')
        
        self.assertEqual(token_data.access_token, 'new-access-token')
        self.assertEqual(token_data.refresh_token, 'new-refresh-token')
        self.assertEqual(token_data.expires_in, 3600)
    
    @patch('enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider._make_http_request')
    def test_refresh_access_token_no_new_refresh_token(self, mock_request):
        """Test access token refresh when no new refresh token is provided."""
        mock_token_response = {
            'access_token': 'new-access-token',
            'expires_in': 3600,
            'token_type': 'Bearer',
            'scope': 'openid profile email User.Read'
        }
        mock_request.return_value = mock_token_response
        
        token_data = self.provider.refresh_access_token('old-refresh-token')
        
        self.assertEqual(token_data.access_token, 'new-access-token')
        self.assertEqual(token_data.refresh_token, 'old-refresh-token')  # Should keep old one
    
    def test_revoke_token_success(self):
        """Test successful token revocation."""
        # Microsoft doesn't have a standard revocation endpoint
        # This method should return True but log that user logout is required
        result = self.provider.revoke_token('test-token')
        
        self.assertTrue(result)
    
    def test_revoke_token_no_config(self):
        """Test token revocation without configuration."""
        unconfigured_provider = MicrosoftOAuthProvider()
        
        result = unconfigured_provider.revoke_token('test-token')
        
        self.assertFalse(result)
    
    def test_decode_id_token_success(self):
        """Test successful ID token decoding."""
        # Create a simple test JWT (header.payload.signature)
        import base64
        import json
        
        header = {'typ': 'JWT', 'alg': 'RS256'}
        payload = {
            'iss': 'https://login.microsoftonline.com/test-tenant/v2.0',
            'aud': 'test-client-id',
            'sub': '1234567890',
            'email': 'test@example.com',
            'tid': 'test-tenant-id'
        }
        
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature_b64 = 'test-signature'
        
        test_jwt = f"{header_b64}.{payload_b64}.{signature_b64}"
        
        decoded_payload = self.provider._decode_id_token(test_jwt)
        
        self.assertEqual(decoded_payload['iss'], 'https://login.microsoftonline.com/test-tenant/v2.0')
        self.assertEqual(decoded_payload['aud'], 'test-client-id')
        self.assertEqual(decoded_payload['sub'], '1234567890')
        self.assertEqual(decoded_payload['email'], 'test@example.com')
        self.assertEqual(decoded_payload['tid'], 'test-tenant-id')
    
    def test_decode_id_token_invalid_format(self):
        """Test ID token decoding with invalid format."""
        invalid_jwt = 'invalid.jwt'
        
        decoded_payload = self.provider._decode_id_token(invalid_jwt)
        
        self.assertEqual(decoded_payload, {})
    
    def test_get_provider_metadata(self):
        """Test provider metadata retrieval."""
        metadata = self.provider.get_provider_metadata()
        
        self.assertEqual(metadata['provider_name'], 'microsoft')
        self.assertEqual(metadata['display_name'], 'Microsoft')
        self.assertEqual(metadata['authorization_endpoint'], 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize')
        self.assertEqual(metadata['token_endpoint'], 'https://login.microsoftonline.com/common/oauth2/v2.0/token')
        self.assertEqual(metadata['userinfo_endpoint'], 'https://graph.microsoft.com/v1.0/me')
        self.assertEqual(metadata['graph_api_endpoint'], 'https://graph.microsoft.com/v1.0')
        self.assertTrue(metadata['supports_pkce'])
        self.assertTrue(metadata['supports_refresh_token'])
        self.assertTrue(metadata['supports_id_token'])
        self.assertTrue(metadata['supports_openid_connect'])
        self.assertTrue(metadata['supports_personal_accounts'])
        self.assertTrue(metadata['supports_work_school_accounts'])
        self.assertEqual(metadata['issuer'], 'https://login.microsoftonline.com')
        
        # Check default and required scopes
        self.assertEqual(metadata['default_scopes'], ['openid', 'profile', 'email', 'User.Read'])
        self.assertEqual(metadata['required_scopes'], ['openid', 'email'])
        
        # Check supported scopes include Microsoft Graph scopes
        supported_scopes = metadata['supported_scopes']
        self.assertIn('User.Read', supported_scopes)
        self.assertIn('Directory.Read.All', supported_scopes)
        self.assertIn('Group.Read.All', supported_scopes)
        self.assertIn('offline_access', supported_scopes)


class MicrosoftOAuthProviderIntegrationTest(TestCase):
    """Integration tests for Microsoft OAuth provider."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.provider = MicrosoftOAuthProvider()
        self.config = ProviderConfig(
            client_id='integration-test-client-id',
            client_secret='integration-test-client-secret',
            redirect_uri='https://example.com/auth/microsoft/callback',
            scopes=['openid', 'profile', 'email', 'User.Read'],
            authorization_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
            user_info_url='https://graph.microsoft.com/v1.0/me',
            revoke_url='https://login.microsoftonline.com/common/oauth2/v2.0/logout',
            timeout=30,
            use_pkce=True
        )
        self.provider.configure(self.config)
    
    def test_full_oauth_flow_simulation(self):
        """Test complete OAuth flow simulation."""
        # Step 1: Generate authorization URL
        state = 'integration-test-state'
        auth_request = self.provider.get_authorization_url(state=state)
        
        self.assertIsNotNone(auth_request.authorization_url)
        self.assertIsNotNone(auth_request.code_verifier)
        self.assertIsNotNone(auth_request.code_challenge)
        
        # Step 2: Simulate token exchange (mocked)
        with patch.object(self.provider, '_make_http_request') as mock_request:
            mock_token_response = {
                'access_token': 'integration-access-token',
                'refresh_token': 'integration-refresh-token',
                'expires_in': 3600,
                'token_type': 'Bearer',
                'scope': 'openid profile email User.Read',
                'id_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vdGVzdC10ZW5hbnQtaWQvdjIuMCIsImF1ZCI6ImludGVncmF0aW9uLXRlc3QtY2xpZW50LWlkIiwic3ViIjoiaW50ZWdyYXRpb24tdGVzdC11c2VyLWlkIiwiZW1haWwiOiJpbnRlZ3JhdGlvbkBleGFtcGxlLmNvbSIsInRpZCI6InRlc3QtdGVuYW50LWlkIn0.signature'
            }
            mock_request.return_value = mock_token_response
            
            token_data = self.provider.exchange_code_for_token(
                code='integration-auth-code',
                state=state,
                code_verifier=auth_request.code_verifier
            )
            
            self.assertEqual(token_data.access_token, 'integration-access-token')
            self.assertEqual(token_data.refresh_token, 'integration-refresh-token')
        
        # Step 3: Simulate user info retrieval (mocked)
        with patch.object(self.provider, '_make_http_request') as mock_request, \
             patch.object(self.provider, '_get_user_profile') as mock_profile, \
             patch.object(self.provider, '_get_user_photo_url') as mock_photo:
            
            mock_user_response = {
                'id': 'integration-test-user-id',
                'userPrincipalName': 'integration@example.com',
                'displayName': 'Integration Test User',
                'givenName': 'Integration',
                'surname': 'User',
                'mail': 'integration@example.com',
                'jobTitle': 'Test Engineer',
                'department': 'QA',
                'companyName': 'Test Company',
                'preferredLanguage': 'en-US',
                'usageLocation': 'US'
            }
            mock_request.return_value = mock_user_response
            mock_profile.return_value = None
            mock_photo.return_value = None
            
            user_data = self.provider.get_user_info(token_data.access_token)
            
            self.assertEqual(user_data.provider_user_id, 'integration-test-user-id')
            self.assertEqual(user_data.email, 'integration@example.com')
            self.assertEqual(user_data.first_name, 'Integration')
            self.assertEqual(user_data.last_name, 'User')
            self.assertEqual(user_data.username, 'integration@example.com')
            self.assertTrue(user_data.verified_email)
            
            # Check Microsoft-specific data
            microsoft_data = user_data.raw_data['microsoft_specific']
            self.assertEqual(microsoft_data['job_title'], 'Test Engineer')
            self.assertEqual(microsoft_data['department'], 'QA')
            self.assertEqual(microsoft_data['company_name'], 'Test Company')