"""
Tests for GitHub OAuth provider implementation.

This module contains comprehensive tests for the GitHub OAuth provider,
including user data normalization, organization/team retrieval, and
error handling scenarios.
"""

import json
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from django.test import TestCase

from ..exceptions import (
    ConfigurationError,
    OAuthProviderError,
    OAuthTokenExpiredError,
)
from ..services.oauth_provider import ProviderConfig, NormalizedUserData
from ..services.providers.github_oauth import GitHubOAuthProvider


class GitHubOAuthProviderTest(TestCase):
    """Test cases for GitHub OAuth provider."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.provider = GitHubOAuthProvider()
        self.config = ProviderConfig(
            client_id="test-github-client-id",
            client_secret="test-github-client-secret",
            redirect_uri="https://example.com/auth/github/callback",
            scopes=["user:email", "read:user", "read:org"],
            authorization_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            user_info_url="https://api.github.com/user",
            timeout=30,
            use_pkce=True
        )
        self.provider.configure(self.config)
    
    def test_provider_properties(self):
        """Test basic provider properties."""
        self.assertEqual(self.provider.provider_name, "github")
        self.assertEqual(self.provider.display_name, "GitHub")
        
        # Test supported scopes
        expected_scopes = {
            "user", "user:email", "user:follow", "read:user",
            "public_repo", "repo", "repo:status", "repo_deployment", "delete_repo",
            "read:org", "write:org", "admin:org",
            "notifications", "gist",
            "read:repo_hook", "write:repo_hook", "admin:repo_hook",
            "read:org_hook", "write:org_hook", "admin:org_hook",
            "read:public_key", "write:public_key", "admin:public_key",
            "read:gpg_key", "write:gpg_key", "admin:gpg_key",
            "read:discussion", "write:discussion",
            "read:packages", "write:packages", "delete:packages",
            "read:project", "write:project",
            "security_events", "codespace", "workflow",
        }
        self.assertTrue(expected_scopes.issubset(self.provider.supported_scopes))
    
    def test_validate_configuration_success(self):
        """Test successful configuration validation."""
        self.assertTrue(self.provider.validate_configuration())
    
    def test_validate_configuration_missing_required_scopes(self):
        """Test configuration validation with missing required scopes."""
        config = ProviderConfig(
            client_id="test-client-id",
            client_secret="test-client-secret",
            redirect_uri="https://example.com/callback",
            scopes=["read:user"],  # Missing user:email
            authorization_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token",
            user_info_url="https://api.github.com/user",
            timeout=30,
            use_pkce=True
        )
        
        provider = GitHubOAuthProvider()
        
        with self.assertRaises(ConfigurationError) as cm:
            provider.configure(config)
        
        self.assertIn("GitHub OAuth requires scopes", str(cm.exception))
        self.assertIn("user:email", str(cm.exception))
    
    def test_validate_configuration_invalid_urls(self):
        """Test configuration validation with invalid URLs."""
        config = ProviderConfig(
            client_id="test-client-id",
            client_secret="test-client-secret",
            redirect_uri="https://example.com/callback",
            scopes=["user:email", "read:user"],
            authorization_url="http://github.com/login/oauth/authorize",  # HTTP instead of HTTPS
            token_url="https://github.com/login/oauth/access_token",
            user_info_url="https://api.github.com/user",
            timeout=30,
            use_pkce=True
        )
        
        provider = GitHubOAuthProvider()
        
        with self.assertRaises(ConfigurationError) as cm:
            provider.configure(config)
        
        self.assertIn("GitHub OAuth URLs must use HTTPS", str(cm.exception))
    
    @patch.object(GitHubOAuthProvider, '_make_http_request')
    def test_get_user_info_success(self, mock_request):
        """Test successful user info retrieval."""
        # Mock user data response
        user_data = {
            'id': 12345,
            'login': 'testuser',
            'name': 'Test User',
            'email': 'test@example.com',
            'avatar_url': 'https://avatars.githubusercontent.com/u/12345',
            'company': 'Test Company',
            'location': 'San Francisco',
            'bio': 'Test bio',
            'public_repos': 10,
            'followers': 5,
            'following': 3,
            'created_at': '2020-01-01T00:00:00Z',
            'updated_at': '2023-01-01T00:00:00Z',
        }
        
        # Mock email data response
        email_data = [
            {
                'email': 'test@example.com',
                'primary': True,
                'verified': True,
                'visibility': 'public'
            },
            {
                'email': 'private@example.com',
                'primary': False,
                'verified': True,
                'visibility': 'private'
            }
        ]
        
        # Mock organization data response
        org_data = [
            {
                'id': 67890,
                'login': 'testorg',
                'name': 'Test Organization',
                'description': 'Test organization description',
                'url': 'https://api.github.com/orgs/testorg',
                'avatar_url': 'https://avatars.githubusercontent.com/u/67890',
                'type': 'Organization'
            }
        ]
        
        # Mock team data response
        team_data = [
            {
                'id': 11111,
                'name': 'developers',
                'slug': 'developers',
                'description': 'Development team',
                'privacy': 'closed',
                'permission': 'push',
                'organization': {
                    'id': 67890,
                    'login': 'testorg',
                    'name': 'Test Organization'
                }
            }
        ]
        
        # Configure mock to return different responses for different URLs
        def mock_request_side_effect(url, headers=None):
            if url == "https://api.github.com/user":
                return user_data
            elif url == "https://api.github.com/user/emails":
                return email_data
            elif url == "https://api.github.com/user/orgs":
                return org_data
            elif url == "https://api.github.com/user/teams":
                return team_data
            else:
                raise ValueError(f"Unexpected URL: {url}")
        
        mock_request.side_effect = mock_request_side_effect
        
        # Test user info retrieval
        result = self.provider.get_user_info("test-access-token")
        
        # Verify the result
        self.assertIsInstance(result, NormalizedUserData)
        self.assertEqual(result.provider_user_id, "12345")
        self.assertEqual(result.email, "test@example.com")
        self.assertEqual(result.first_name, "Test")
        self.assertEqual(result.last_name, "User")
        self.assertEqual(result.username, "testuser")
        self.assertEqual(result.profile_picture_url, "https://avatars.githubusercontent.com/u/12345")
        self.assertTrue(result.verified_email)
        self.assertEqual(result.timezone, "America/Los_Angeles")  # San Francisco timezone
        
        # Verify GitHub-specific data
        github_data = result.raw_data['github_specific']
        self.assertEqual(github_data['login'], 'testuser')
        self.assertEqual(github_data['company'], 'Test Company')
        self.assertEqual(github_data['location'], 'San Francisco')
        self.assertEqual(len(github_data['organizations']), 1)
        self.assertEqual(len(github_data['teams']), 1)
        self.assertEqual(len(github_data['emails']), 2)
        
        # Verify organization data
        org = github_data['organizations'][0]
        self.assertEqual(org['id'], 67890)
        self.assertEqual(org['login'], 'testorg')
        self.assertEqual(org['name'], 'Test Organization')
        
        # Verify team data
        team = github_data['teams'][0]
        self.assertEqual(team['id'], 11111)
        self.assertEqual(team['name'], 'developers')
        self.assertEqual(team['organization']['login'], 'testorg')
        
        # Verify API calls were made with correct headers
        expected_headers = {
            'Authorization': 'Bearer test-access-token',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Enterprise-Auth-Backend/1.0',
        }
        
        # Check that all expected API calls were made
        self.assertEqual(mock_request.call_count, 4)
        for call in mock_request.call_args_list:
            self.assertEqual(call[1]['headers'], expected_headers)
    
    @patch.object(GitHubOAuthProvider, '_make_http_request')
    def test_get_user_info_with_minimal_data(self, mock_request):
        """Test user info retrieval with minimal data."""
        # Mock minimal user data response
        user_data = {
            'id': 12345,
            'login': 'testuser',
        }
        
        # Configure mock to return minimal data
        def mock_request_side_effect(url, headers=None):
            if url == "https://api.github.com/user":
                return user_data
            elif url == "https://api.github.com/user/emails":
                return []
            elif url == "https://api.github.com/user/orgs":
                return []
            elif url == "https://api.github.com/user/teams":
                return []
            else:
                raise ValueError(f"Unexpected URL: {url}")
        
        mock_request.side_effect = mock_request_side_effect
        
        # Test user info retrieval
        result = self.provider.get_user_info("test-access-token")
        
        # Verify the result with minimal data
        self.assertIsInstance(result, NormalizedUserData)
        self.assertEqual(result.provider_user_id, "12345")
        self.assertIsNone(result.email)
        self.assertEqual(result.first_name, "")
        self.assertEqual(result.last_name, "")
        self.assertEqual(result.username, "testuser")
        self.assertIsNone(result.profile_picture_url)
        self.assertFalse(result.verified_email)
        self.assertIsNone(result.timezone)
    
    @patch.object(GitHubOAuthProvider, '_make_http_request')
    def test_get_user_info_token_expired(self, mock_request):
        """Test user info retrieval with expired token."""
        # Mock HTTP 401 error
        mock_request.side_effect = HTTPError(
            url="https://api.github.com/user",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=None
        )
        
        # Test that token expired error is raised
        with self.assertRaises(OAuthTokenExpiredError) as cm:
            self.provider.get_user_info("expired-token")
        
        self.assertEqual(cm.exception.details.get('provider'), "github")
        self.assertIn("Access token expired", str(cm.exception))
    
    @patch.object(GitHubOAuthProvider, '_make_http_request')
    def test_get_user_info_api_error(self, mock_request):
        """Test user info retrieval with API error."""
        # Mock HTTP 500 error
        mock_request.side_effect = HTTPError(
            url="https://api.github.com/user",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=None
        )
        
        # Test that provider error is raised
        with self.assertRaises(OAuthProviderError) as cm:
            self.provider.get_user_info("test-token")
        
        self.assertEqual(cm.exception.details.get('provider'), "github")
        self.assertIn("Failed to get user info", str(cm.exception))
    
    @patch.object(GitHubOAuthProvider, '_make_http_request')
    def test_get_user_emails_insufficient_scope(self, mock_request):
        """Test user email retrieval with insufficient scope."""
        # Mock user data response
        user_data = {
            'id': 12345,
            'login': 'testuser',
        }
        
        # Configure mock to return 403 for emails endpoint
        def mock_request_side_effect(url, headers=None):
            if url == "https://api.github.com/user":
                return user_data
            elif url == "https://api.github.com/user/emails":
                raise HTTPError(
                    url=url,
                    code=403,
                    msg="Forbidden",
                    hdrs={},
                    fp=None
                )
            elif url == "https://api.github.com/user/orgs":
                return []
            elif url == "https://api.github.com/user/teams":
                return []
            else:
                raise ValueError(f"Unexpected URL: {url}")
        
        mock_request.side_effect = mock_request_side_effect
        
        # Test user info retrieval (should succeed despite email error)
        result = self.provider.get_user_info("test-access-token")
        
        # Verify the result
        self.assertIsInstance(result, NormalizedUserData)
        self.assertEqual(result.provider_user_id, "12345")
        self.assertIsNone(result.email)  # No email due to insufficient scope
        self.assertEqual(result.username, "testuser")
    
    @patch.object(GitHubOAuthProvider, '_make_http_request')
    def test_get_user_organizations_insufficient_scope(self, mock_request):
        """Test user organization retrieval with insufficient scope."""
        # Mock user data response
        user_data = {
            'id': 12345,
            'login': 'testuser',
        }
        
        # Configure mock to return 403 for orgs endpoint
        def mock_request_side_effect(url, headers=None):
            if url == "https://api.github.com/user":
                return user_data
            elif url == "https://api.github.com/user/emails":
                return []
            elif url == "https://api.github.com/user/orgs":
                raise HTTPError(
                    url=url,
                    code=403,
                    msg="Forbidden",
                    hdrs={},
                    fp=None
                )
            elif url == "https://api.github.com/user/teams":
                return []
            else:
                raise ValueError(f"Unexpected URL: {url}")
        
        mock_request.side_effect = mock_request_side_effect
        
        # Test user info retrieval (should succeed despite org error)
        result = self.provider.get_user_info("test-access-token")
        
        # Verify the result
        self.assertIsInstance(result, NormalizedUserData)
        self.assertEqual(result.provider_user_id, "12345")
        self.assertEqual(result.username, "testuser")
        
        # Verify no organizations were retrieved
        github_data = result.raw_data['github_specific']
        self.assertEqual(len(github_data['organizations']), 0)
    
    def test_get_authorization_url(self):
        """Test authorization URL generation."""
        auth_request = self.provider.get_authorization_url(
            state="test-state",
            scopes=["user:email", "read:user"],
            extra_params={"custom_param": "value"}
        )
        
        # Verify the authorization URL contains expected parameters
        self.assertIn("github.com/login/oauth/authorize", auth_request.authorization_url)
        self.assertIn("client_id=test-github-client-id", auth_request.authorization_url)
        self.assertIn("state=test-state", auth_request.authorization_url)
        self.assertIn("scope=user%3Aemail+read%3Auser", auth_request.authorization_url)
        self.assertIn("allow_signup=true", auth_request.authorization_url)
        self.assertIn("custom_param=value", auth_request.authorization_url)
    
    def test_get_authorization_url_with_default_scopes(self):
        """Test authorization URL generation with default scopes."""
        auth_request = self.provider.get_authorization_url(state="test-state")
        
        # Verify default scopes are used
        self.assertIn("scope=user%3Aemail+read%3Auser", auth_request.authorization_url)
    
    def test_refresh_access_token_not_supported(self):
        """Test that refresh token is not supported by GitHub."""
        with self.assertRaises(OAuthProviderError) as cm:
            self.provider.refresh_access_token("test-refresh-token")
        
        self.assertEqual(cm.exception.details.get('provider'), "github")
        self.assertIn("GitHub OAuth doesn't support refresh tokens", str(cm.exception))
    
    @patch.object(GitHubOAuthProvider, '_make_http_request')
    def test_revoke_token_success(self, mock_request):
        """Test successful token revocation."""
        # Mock successful revocation (GitHub returns 204)
        mock_request.side_effect = HTTPError(
            url="https://api.github.com/applications/test-github-client-id/grant",
            code=204,
            msg="No Content",
            hdrs={},
            fp=None
        )
        
        result = self.provider.revoke_token("test-access-token")
        
        self.assertTrue(result)
        
        # Verify the request was made with correct parameters
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        
        # Check URL
        expected_url = "https://api.github.com/applications/test-github-client-id/grant"
        self.assertEqual(call_args[0][0], expected_url)
        
        # Check data
        self.assertEqual(call_args[1]['data'], {'access_token': 'test-access-token'})
        
        # Check headers
        headers = call_args[1]['headers']
        self.assertIn('Authorization', headers)
        self.assertTrue(headers['Authorization'].startswith('Basic '))
        self.assertEqual(headers['Accept'], 'application/vnd.github.v3+json')
        self.assertEqual(headers['User-Agent'], 'Enterprise-Auth-Backend/1.0')
    
    @patch.object(GitHubOAuthProvider, '_make_http_request')
    def test_revoke_token_failure(self, mock_request):
        """Test token revocation failure."""
        # Mock revocation failure
        mock_request.side_effect = HTTPError(
            url="https://api.github.com/applications/test-github-client-id/grant",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None
        )
        
        result = self.provider.revoke_token("test-access-token")
        
        self.assertFalse(result)
    
    def test_get_provider_metadata(self):
        """Test provider metadata retrieval."""
        metadata = self.provider.get_provider_metadata()
        
        # Verify metadata structure
        self.assertEqual(metadata['provider_name'], 'github')
        self.assertEqual(metadata['display_name'], 'GitHub')
        self.assertEqual(metadata['authorization_endpoint'], 'https://github.com/login/oauth/authorize')
        self.assertEqual(metadata['token_endpoint'], 'https://github.com/login/oauth/access_token')
        self.assertEqual(metadata['userinfo_endpoint'], 'https://api.github.com/user')
        
        # Verify capabilities
        self.assertTrue(metadata['supports_pkce'])
        self.assertFalse(metadata['supports_refresh_token'])
        self.assertFalse(metadata['supports_id_token'])
        self.assertFalse(metadata['supports_openid_connect'])
        self.assertTrue(metadata['supports_organizations'])
        self.assertTrue(metadata['supports_teams'])
        
        # Verify scopes
        self.assertIn('user:email', metadata['supported_scopes'])
        self.assertIn('read:user', metadata['supported_scopes'])
        self.assertIn('read:org', metadata['supported_scopes'])
        self.assertEqual(metadata['default_scopes'], ['user:email', 'read:user'])
        self.assertEqual(metadata['required_scopes'], ['user:email'])
    
    def test_normalize_github_user_data_with_full_name(self):
        """Test user data normalization with full name."""
        user_data = {
            'id': 12345,
            'login': 'testuser',
            'name': 'John Doe Smith',
            'email': 'john@example.com',
        }
        
        result = self.provider._normalize_github_user_data(
            user_data, [], [], []
        )
        
        self.assertEqual(result.first_name, 'John')
        self.assertEqual(result.last_name, 'Doe Smith')
    
    def test_normalize_github_user_data_email_priority(self):
        """Test user data normalization email priority logic."""
        user_data = {
            'id': 12345,
            'login': 'testuser',
        }
        
        email_data = [
            {
                'email': 'secondary@example.com',
                'primary': False,
                'verified': True,
            },
            {
                'email': 'primary@example.com',
                'primary': True,
                'verified': True,
            },
            {
                'email': 'unverified@example.com',
                'primary': False,
                'verified': False,
            }
        ]
        
        result = self.provider._normalize_github_user_data(
            user_data, email_data, [], []
        )
        
        # Should prioritize primary email
        self.assertEqual(result.email, 'primary@example.com')
        self.assertTrue(result.verified_email)
    
    def test_normalize_github_user_data_timezone_mapping(self):
        """Test timezone mapping from location."""
        test_cases = [
            ('San Francisco', 'America/Los_Angeles'),
            ('New York', 'America/New_York'),
            ('London', 'Europe/London'),
            ('Tokyo', 'Asia/Tokyo'),
            ('Unknown City', None),
        ]
        
        for location, expected_timezone in test_cases:
            user_data = {
                'id': 12345,
                'login': 'testuser',
                'location': location,
            }
            
            result = self.provider._normalize_github_user_data(
                user_data, [], [], []
            )
            
            self.assertEqual(result.timezone, expected_timezone)
    
    def test_normalize_github_user_data_missing_id(self):
        """Test user data normalization with missing ID."""
        user_data = {
            'login': 'testuser',
            # Missing 'id' field
        }
        
        with self.assertRaises(OAuthProviderError) as cm:
            self.provider._normalize_github_user_data(
                user_data, [], [], []
            )
        
        self.assertIn("GitHub user data missing required 'id' field", str(cm.exception))