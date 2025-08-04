"""
GitHub OAuth2 provider implementation.

This module provides a complete implementation of GitHub OAuth2 integration
with support for PKCE, organization/team data retrieval, and comprehensive
user data normalization.
"""

import logging
from typing import Any, Dict, List, Optional, Set
from urllib.error import HTTPError

from ...exceptions import (
    ConfigurationError,
    OAuthError,
    OAuthProviderError,
    OAuthTokenExpiredError,
)
from ..oauth_provider import BaseOAuthProvider, NormalizedUserData, TokenData

logger = logging.getLogger(__name__)


class GitHubOAuthProvider(BaseOAuthProvider):
    """
    GitHub OAuth2 provider implementation.
    
    This provider supports:
    - OAuth2 authorization code flow with PKCE
    - GitHub-specific scope handling
    - Organization and team information retrieval
    - Comprehensive user data normalization
    - GitHub Apps integration support
    """
    
    # GitHub OAuth2 endpoints
    AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_INFO_URL = "https://api.github.com/user"
    USER_EMAILS_URL = "https://api.github.com/user/emails"
    USER_ORGS_URL = "https://api.github.com/user/orgs"
    USER_TEAMS_URL = "https://api.github.com/user/teams"
    REVOKE_URL = "https://api.github.com/applications/{client_id}/grant"
    
    # GitHub-specific configuration
    DEFAULT_SCOPES = ["user:email", "read:user"]
    REQUIRED_SCOPES = ["user:email"]
    
    @property
    def provider_name(self) -> str:
        """Return the unique name of this OAuth provider."""
        return "github"
    
    @property
    def display_name(self) -> str:
        """Return the human-readable display name of this provider."""
        return "GitHub"
    
    @property
    def supported_scopes(self) -> Set[str]:
        """Return the set of scopes supported by this provider."""
        return {
            # User scopes
            "user",
            "user:email",
            "user:follow",
            "read:user",
            
            # Repository scopes
            "public_repo",
            "repo",
            "repo:status",
            "repo_deployment",
            "delete_repo",
            
            # Organization scopes
            "read:org",
            "write:org",
            "admin:org",
            
            # Team scopes (legacy, but still supported)
            "read:org",  # Required for team access
            
            # Notification scopes
            "notifications",
            
            # Gist scopes
            "gist",
            
            # Hook scopes
            "read:repo_hook",
            "write:repo_hook",
            "admin:repo_hook",
            "read:org_hook",
            "write:org_hook",
            "admin:org_hook",
            
            # Key scopes
            "read:public_key",
            "write:public_key",
            "admin:public_key",
            "read:gpg_key",
            "write:gpg_key",
            "admin:gpg_key",
            
            # Discussion scopes
            "read:discussion",
            "write:discussion",
            
            # Package scopes
            "read:packages",
            "write:packages",
            "delete:packages",
            
            # Project scopes
            "read:project",
            "write:project",
            
            # Security events
            "security_events",
            
            # Codespace scopes
            "codespace",
            
            # Workflow scopes
            "workflow",
        }
    
    def validate_configuration(self) -> bool:
        """Validate the GitHub OAuth provider configuration."""
        if not super().validate_configuration():
            return False
        
        # Validate GitHub-specific requirements
        if not self.config:
            return False
        
        # Ensure required scopes are included
        config_scopes = set(self.config.scopes)
        required_scopes = set(self.REQUIRED_SCOPES)
        
        if not required_scopes.issubset(config_scopes):
            missing_scopes = required_scopes - config_scopes
            raise ConfigurationError(
                f"GitHub OAuth requires scopes: {missing_scopes}",
                config_key=f"oauth.{self.provider_name}.scopes"
            )
        
        # Validate GitHub-specific URLs if overridden
        expected_urls = {
            'authorization_url': self.AUTHORIZATION_URL,
            'token_url': self.TOKEN_URL,
            'user_info_url': self.USER_INFO_URL,
        }
        
        for url_field, expected_url in expected_urls.items():
            config_url = getattr(self.config, url_field)
            if config_url and not config_url.startswith('https://'):
                raise ConfigurationError(
                    f"GitHub OAuth URLs must use HTTPS: {url_field}",
                    config_key=f"oauth.{self.provider_name}.{url_field}"
                )
        
        return True
    
    def get_user_info(self, access_token: str) -> NormalizedUserData:
        """
        Retrieve user information from GitHub's API endpoints.
        
        Args:
            access_token: OAuth access token
            
        Returns:
            Normalized user data with organization and team information
            
        Raises:
            OAuthProviderError: If user info retrieval fails
            OAuthTokenExpiredError: If access token is expired
        """
        if not self.config:
            raise ConfigurationError(f"Provider {self.provider_name} is not configured")
        
        try:
            # Get basic user information
            logger.debug(
                f"Fetching user info from GitHub user endpoint",
                extra={'provider': self.provider_name, 'endpoint': self.USER_INFO_URL}
            )
            
            user_data = self._make_http_request(
                self.USER_INFO_URL,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/vnd.github.v3+json',
                    'User-Agent': 'Enterprise-Auth-Backend/1.0',
                }
            )
            
            # Get user's email addresses
            email_data = self._get_user_emails(access_token)
            
            # Get user's organizations (if scope allows)
            org_data = self._get_user_organizations(access_token)
            
            # Get user's teams (if scope allows)
            team_data = self._get_user_teams(access_token)
            
            logger.info(
                f"Successfully retrieved user info from GitHub",
                extra={
                    'provider': self.provider_name,
                    'user_id': user_data.get('id'),
                    'login': user_data.get('login'),
                    'organizations_count': len(org_data),
                    'teams_count': len(team_data),
                }
            )
            
            # Normalize GitHub user data
            return self._normalize_github_user_data(
                user_data, email_data, org_data, team_data
            )
            
        except HTTPError as e:
            if e.code == 401:
                logger.warning(
                    f"Access token expired for GitHub",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                raise OAuthTokenExpiredError(
                    f"Access token expired for {self.provider_name}",
                    provider=self.provider_name
                )
            else:
                logger.warning(
                    f"Failed to get user info from GitHub",
                    extra={
                        'provider': self.provider_name,
                        'status_code': e.code,
                    }
                )
                raise OAuthProviderError(
                    f"Failed to get user info from {self.provider_name}",
                    provider=self.provider_name,
                    provider_error=f"HTTP {e.code}"
                )
        
        except Exception as e:
            logger.error(
                f"Unexpected error getting user info from GitHub",
                extra={
                    'provider': self.provider_name,
                    'error': str(e),
                }
            )
            raise OAuthProviderError(
                f"Failed to get user info from {self.provider_name}: {e}",
                provider=self.provider_name,
                provider_error=str(e)
            )
    
    def _get_user_emails(self, access_token: str) -> List[Dict[str, Any]]:
        """
        Retrieve user's email addresses from GitHub.
        
        Args:
            access_token: OAuth access token
            
        Returns:
            List of email data dictionaries
        """
        try:
            logger.debug(
                f"Fetching user emails from GitHub",
                extra={'provider': self.provider_name}
            )
            
            email_data = self._make_http_request(
                self.USER_EMAILS_URL,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/vnd.github.v3+json',
                    'User-Agent': 'Enterprise-Auth-Backend/1.0',
                }
            )
            
            logger.debug(
                f"Retrieved {len(email_data)} email addresses from GitHub",
                extra={'provider': self.provider_name}
            )
            
            return email_data
            
        except HTTPError as e:
            if e.code == 403:
                # Insufficient scope - user:email scope required
                logger.warning(
                    f"Insufficient scope to access GitHub user emails",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                return []
            else:
                logger.warning(
                    f"Failed to get user emails from GitHub",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                return []
        
        except Exception as e:
            logger.warning(
                f"Error getting user emails from GitHub: {e}",
                extra={'provider': self.provider_name}
            )
            return []
    
    def _get_user_organizations(self, access_token: str) -> List[Dict[str, Any]]:
        """
        Retrieve user's organization memberships from GitHub.
        
        Args:
            access_token: OAuth access token
            
        Returns:
            List of organization data dictionaries
        """
        try:
            logger.debug(
                f"Fetching user organizations from GitHub",
                extra={'provider': self.provider_name}
            )
            
            org_data = self._make_http_request(
                self.USER_ORGS_URL,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/vnd.github.v3+json',
                    'User-Agent': 'Enterprise-Auth-Backend/1.0',
                }
            )
            
            logger.debug(
                f"Retrieved {len(org_data)} organizations from GitHub",
                extra={'provider': self.provider_name}
            )
            
            return org_data
            
        except HTTPError as e:
            if e.code == 403:
                # Insufficient scope - read:org scope required
                logger.warning(
                    f"Insufficient scope to access GitHub user organizations",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                return []
            else:
                logger.warning(
                    f"Failed to get user organizations from GitHub",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                return []
        
        except Exception as e:
            logger.warning(
                f"Error getting user organizations from GitHub: {e}",
                extra={'provider': self.provider_name}
            )
            return []
    
    def _get_user_teams(self, access_token: str) -> List[Dict[str, Any]]:
        """
        Retrieve user's team memberships from GitHub.
        
        Args:
            access_token: OAuth access token
            
        Returns:
            List of team data dictionaries
        """
        try:
            logger.debug(
                f"Fetching user teams from GitHub",
                extra={'provider': self.provider_name}
            )
            
            team_data = self._make_http_request(
                self.USER_TEAMS_URL,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/vnd.github.v3+json',
                    'User-Agent': 'Enterprise-Auth-Backend/1.0',
                }
            )
            
            logger.debug(
                f"Retrieved {len(team_data)} teams from GitHub",
                extra={'provider': self.provider_name}
            )
            
            return team_data
            
        except HTTPError as e:
            if e.code == 403:
                # Insufficient scope - read:org scope required for teams
                logger.warning(
                    f"Insufficient scope to access GitHub user teams",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                return []
            else:
                logger.warning(
                    f"Failed to get user teams from GitHub",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                return []
        
        except Exception as e:
            logger.warning(
                f"Error getting user teams from GitHub: {e}",
                extra={'provider': self.provider_name}
            )
            return []
    
    def _normalize_github_user_data(
        self,
        user_data: Dict[str, Any],
        email_data: List[Dict[str, Any]],
        org_data: List[Dict[str, Any]],
        team_data: List[Dict[str, Any]]
    ) -> NormalizedUserData:
        """
        Normalize GitHub user data to standard format.
        
        Args:
            user_data: Raw user data from GitHub API
            email_data: User's email addresses
            org_data: User's organization memberships
            team_data: User's team memberships
            
        Returns:
            Normalized user data
        """
        # GitHub user ID is required
        provider_user_id = user_data.get('id')
        if not provider_user_id:
            raise OAuthProviderError(
                "GitHub user data missing required 'id' field",
                provider=self.provider_name
            )
        
        # Extract name information
        full_name = user_data.get('name', '')
        if full_name:
            name_parts = full_name.split(' ', 1)
            first_name = name_parts[0] if len(name_parts) > 0 else ''
            last_name = name_parts[1] if len(name_parts) > 1 else ''
        else:
            first_name = ''
            last_name = ''
        
        # Extract email information - prioritize primary verified email
        email = None
        verified_email = False
        
        if email_data:
            # Find primary email first
            for email_info in email_data:
                if email_info.get('primary', False):
                    email = email_info.get('email')
                    verified_email = email_info.get('verified', False)
                    break
            
            # If no primary email found, use first verified email
            if not email:
                for email_info in email_data:
                    if email_info.get('verified', False):
                        email = email_info.get('email')
                        verified_email = True
                        break
            
            # If no verified email found, use first email
            if not email and email_data:
                email_info = email_data[0]
                email = email_info.get('email')
                verified_email = email_info.get('verified', False)
        
        # Fallback to public email from user data
        if not email:
            email = user_data.get('email')
            verified_email = bool(email)  # GitHub public emails are generally verified
        
        # Extract profile information
        username = user_data.get('login')
        profile_picture_url = user_data.get('avatar_url')
        
        # Extract location and company information
        location = user_data.get('location')
        company = user_data.get('company')
        
        # Process organization data
        organizations = []
        for org in org_data:
            organizations.append({
                'id': org.get('id'),
                'login': org.get('login'),
                'name': org.get('name'),
                'description': org.get('description'),
                'url': org.get('url'),
                'avatar_url': org.get('avatar_url'),
                'type': org.get('type'),
            })
        
        # Process team data
        teams = []
        for team in team_data:
            teams.append({
                'id': team.get('id'),
                'name': team.get('name'),
                'slug': team.get('slug'),
                'description': team.get('description'),
                'privacy': team.get('privacy'),
                'permission': team.get('permission'),
                'organization': {
                    'id': team.get('organization', {}).get('id'),
                    'login': team.get('organization', {}).get('login'),
                    'name': team.get('organization', {}).get('name'),
                } if team.get('organization') else None,
            })
        
        # Extract GitHub-specific data
        github_data = {
            'login': username,
            'node_id': user_data.get('node_id'),
            'type': user_data.get('type'),
            'site_admin': user_data.get('site_admin', False),
            'company': company,
            'blog': user_data.get('blog'),
            'location': location,
            'bio': user_data.get('bio'),
            'twitter_username': user_data.get('twitter_username'),
            'public_repos': user_data.get('public_repos', 0),
            'public_gists': user_data.get('public_gists', 0),
            'followers': user_data.get('followers', 0),
            'following': user_data.get('following', 0),
            'created_at': user_data.get('created_at'),
            'updated_at': user_data.get('updated_at'),
            'private_gists': user_data.get('private_gists'),
            'total_private_repos': user_data.get('total_private_repos'),
            'owned_private_repos': user_data.get('owned_private_repos'),
            'disk_usage': user_data.get('disk_usage'),
            'collaborators': user_data.get('collaborators'),
            'two_factor_authentication': user_data.get('two_factor_authentication'),
            'plan': user_data.get('plan'),
            'organizations': organizations,
            'teams': teams,
            'emails': email_data,
        }
        
        # Remove None values from github_data
        github_data = {k: v for k, v in github_data.items() if v is not None}
        
        # Determine timezone from location if available
        timezone = None
        if location:
            # Basic timezone mapping from common locations
            timezone_mapping = {
                'san francisco': 'America/Los_Angeles',
                'new york': 'America/New_York',
                'london': 'Europe/London',
                'berlin': 'Europe/Berlin',
                'paris': 'Europe/Paris',
                'tokyo': 'Asia/Tokyo',
                'sydney': 'Australia/Sydney',
                'toronto': 'America/Toronto',
                'vancouver': 'America/Vancouver',
                'chicago': 'America/Chicago',
                'los angeles': 'America/Los_Angeles',
                'seattle': 'America/Los_Angeles',
                'boston': 'America/New_York',
                'amsterdam': 'Europe/Amsterdam',
                'zurich': 'Europe/Zurich',
                'singapore': 'Asia/Singapore',
                'hong kong': 'Asia/Hong_Kong',
                'mumbai': 'Asia/Kolkata',
                'bangalore': 'Asia/Kolkata',
                'delhi': 'Asia/Kolkata',
                'beijing': 'Asia/Shanghai',
                'shanghai': 'Asia/Shanghai',
                'seoul': 'Asia/Seoul',
                'moscow': 'Europe/Moscow',
                'stockholm': 'Europe/Stockholm',
                'oslo': 'Europe/Oslo',
                'copenhagen': 'Europe/Copenhagen',
                'helsinki': 'Europe/Helsinki',
                'dublin': 'Europe/Dublin',
                'madrid': 'Europe/Madrid',
                'rome': 'Europe/Rome',
                'vienna': 'Europe/Vienna',
                'prague': 'Europe/Prague',
                'warsaw': 'Europe/Warsaw',
                'budapest': 'Europe/Budapest',
                'bucharest': 'Europe/Bucharest',
                'athens': 'Europe/Athens',
                'istanbul': 'Europe/Istanbul',
                'tel aviv': 'Asia/Jerusalem',
                'dubai': 'Asia/Dubai',
                'riyadh': 'Asia/Riyadh',
                'cairo': 'Africa/Cairo',
                'johannesburg': 'Africa/Johannesburg',
                'cape town': 'Africa/Johannesburg',
                'lagos': 'Africa/Lagos',
                'nairobi': 'Africa/Nairobi',
                'melbourne': 'Australia/Melbourne',
                'brisbane': 'Australia/Brisbane',
                'perth': 'Australia/Perth',
                'auckland': 'Pacific/Auckland',
                'wellington': 'Pacific/Auckland',
                'mexico city': 'America/Mexico_City',
                'buenos aires': 'America/Argentina/Buenos_Aires',
                'sao paulo': 'America/Sao_Paulo',
                'rio de janeiro': 'America/Sao_Paulo',
                'lima': 'America/Lima',
                'bogota': 'America/Bogota',
                'santiago': 'America/Santiago',
                'caracas': 'America/Caracas',
                'montevideo': 'America/Montevideo',
            }
            location_lower = location.lower().strip()
            timezone = timezone_mapping.get(location_lower)
        
        logger.debug(
            f"Normalized GitHub user data",
            extra={
                'provider': self.provider_name,
                'user_id': provider_user_id,
                'login': username,
                'email': email,
                'verified_email': verified_email,
                'has_profile_picture': bool(profile_picture_url),
                'organizations_count': len(organizations),
                'teams_count': len(teams),
                'location': location,
                'company': company,
            }
        )
        
        return NormalizedUserData(
            provider_user_id=str(provider_user_id),
            email=email,
            first_name=first_name,
            last_name=last_name,
            username=username,
            profile_picture_url=profile_picture_url,
            locale=None,  # GitHub doesn't provide locale information
            timezone=timezone,
            verified_email=verified_email,
            raw_data={
                **user_data,
                'github_specific': github_data,
            }
        )
    
    def get_authorization_url(
        self,
        state: str,
        scopes: Optional[list[str]] = None,
        extra_params: Optional[Dict[str, str]] = None
    ) -> "AuthorizationRequest":
        """
        Generate GitHub OAuth authorization URL.
        
        Args:
            state: State parameter for CSRF protection
            scopes: List of OAuth scopes to request
            extra_params: Additional parameters for the authorization URL
            
        Returns:
            Authorization request data including URL and PKCE parameters
        """
        # Use default scopes if none provided
        if scopes is None:
            scopes = self.DEFAULT_SCOPES.copy()
        
        # Ensure required scopes are included
        scopes_set = set(scopes)
        for required_scope in self.REQUIRED_SCOPES:
            if required_scope not in scopes_set:
                scopes.append(required_scope)
        
        # GitHub-specific extra parameters
        github_extra_params = {
            'allow_signup': 'true',  # Allow new user registration
        }
        
        # Merge with provided extra parameters
        if extra_params:
            github_extra_params.update(extra_params)
        
        # Call parent implementation with GitHub-specific parameters
        return super().get_authorization_url(
            state=state,
            scopes=scopes,
            extra_params=github_extra_params
        )
    
    def exchange_code_for_token(
        self,
        code: str,
        state: str,
        code_verifier: Optional[str] = None
    ) -> TokenData:
        """
        Exchange authorization code for GitHub OAuth tokens.
        
        Args:
            code: Authorization code from OAuth callback
            state: State parameter for verification
            code_verifier: PKCE code verifier if used
            
        Returns:
            Token data including access token
        """
        # GitHub doesn't support refresh tokens in the standard OAuth flow
        # Call parent implementation
        token_data = super().exchange_code_for_token(code, state, code_verifier)
        
        # GitHub-specific token validation
        logger.debug(
            f"Received GitHub access token",
            extra={
                'provider': self.provider_name,
                'has_access_token': bool(token_data.access_token),
                'has_refresh_token': bool(token_data.refresh_token),
                'token_type': token_data.token_type,
                'expires_in': token_data.expires_in,
            }
        )
        
        return token_data
    
    def refresh_access_token(self, refresh_token: str) -> TokenData:
        """
        Refresh GitHub OAuth access token.
        
        Note: GitHub doesn't support refresh tokens in the standard OAuth flow.
        This method will raise an error.
        
        Args:
            refresh_token: OAuth refresh token
            
        Returns:
            New token data
            
        Raises:
            OAuthProviderError: GitHub doesn't support token refresh
        """
        raise OAuthProviderError(
            "GitHub OAuth doesn't support refresh tokens. "
            "Users must re-authorize to get a new access token.",
            provider=self.provider_name
        )
    
    def revoke_token(self, token: str, token_type: str = "access_token") -> bool:
        """
        Revoke a GitHub OAuth token.
        
        Args:
            token: Token to revoke
            token_type: Type of token (access_token)
            
        Returns:
            True if revocation was successful
        """
        if not self.config:
            logger.warning(
                f"Cannot revoke token - provider not configured",
                extra={'provider': self.provider_name}
            )
            return False
        
        try:
            # GitHub's revoke endpoint requires client credentials
            revoke_url = self.REVOKE_URL.format(client_id=self.config.client_id)
            
            # GitHub requires HTTP Basic authentication with client credentials
            import base64
            credentials = f"{self.config.client_id}:{self.config.client_secret}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            
            self._make_http_request(
                revoke_url,
                data={'access_token': token},
                headers={
                    'Authorization': f'Basic {encoded_credentials}',
                    'Accept': 'application/vnd.github.v3+json',
                    'User-Agent': 'Enterprise-Auth-Backend/1.0',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            )
            
            logger.info(
                f"Successfully revoked GitHub token",
                extra={
                    'provider': self.provider_name,
                    'token_type': token_type,
                }
            )
            
            return True
            
        except HTTPError as e:
            if e.code == 204:
                # GitHub returns 204 for successful revocation
                logger.info(
                    f"Successfully revoked GitHub token",
                    extra={
                        'provider': self.provider_name,
                        'token_type': token_type,
                    }
                )
                return True
            else:
                logger.warning(
                    f"Failed to revoke GitHub token",
                    extra={
                        'provider': self.provider_name,
                        'status_code': e.code,
                        'token_type': token_type,
                    }
                )
                return False
        
        except Exception as e:
            logger.error(
                f"Error revoking GitHub token: {e}",
                extra={
                    'provider': self.provider_name,
                    'token_type': token_type,
                }
            )
            return False
    
    def get_provider_metadata(self) -> Dict[str, Any]:
        """
        Get GitHub OAuth provider metadata.
        
        Returns:
            Provider metadata including endpoints and capabilities
        """
        return {
            'provider_name': self.provider_name,
            'display_name': self.display_name,
            'authorization_endpoint': self.AUTHORIZATION_URL,
            'token_endpoint': self.TOKEN_URL,
            'userinfo_endpoint': self.USER_INFO_URL,
            'revocation_endpoint': self.REVOKE_URL,
            'supported_scopes': list(self.supported_scopes),
            'default_scopes': self.DEFAULT_SCOPES,
            'required_scopes': self.REQUIRED_SCOPES,
            'supports_pkce': True,
            'supports_refresh_token': False,
            'supports_id_token': False,
            'supports_openid_connect': False,
            'supports_organizations': True,
            'supports_teams': True,
            'api_base_url': 'https://api.github.com',
            'documentation_url': 'https://docs.github.com/en/developers/apps/building-oauth-apps',
            'privacy_policy_url': 'https://docs.github.com/en/github/site-policy/github-privacy-statement',
            'terms_of_service_url': 'https://docs.github.com/en/github/site-policy/github-terms-of-service',
        }