"""
Microsoft OAuth2/OpenID Connect provider implementation.

This module provides a complete implementation of Microsoft Azure AD OAuth2 and OpenID Connect
integration with support for both personal and work/school accounts, PKCE, Microsoft Graph API
integration, and comprehensive user data normalization.
"""

import json
import logging
from typing import Any, Dict, Optional, Set
from urllib.error import HTTPError
from urllib.parse import urlencode

from django.conf import settings

from ...exceptions import (
    ConfigurationError,
    OAuthError,
    OAuthProviderError,
    OAuthTokenExpiredError,
)
from ..oauth_provider import BaseOAuthProvider, NormalizedUserData, TokenData

logger = logging.getLogger(__name__)


class MicrosoftOAuthProvider(BaseOAuthProvider):
    """
    Microsoft OAuth2/OpenID Connect provider implementation.
    
    This provider supports:
    - OAuth2 authorization code flow with PKCE
    - OpenID Connect for identity verification
    - Both personal Microsoft accounts and work/school accounts (Azure AD)
    - Microsoft Graph API integration for user data
    - Automatic token refresh
    - Comprehensive user data normalization
    - Microsoft-specific scope handling
    """
    
    # Microsoft OAuth2 endpoints
    # Using v2.0 endpoint for unified personal and work/school account support
    AUTHORIZATION_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    USER_INFO_URL = "https://graph.microsoft.com/v1.0/me"
    USER_PROFILE_URL = "https://graph.microsoft.com/v1.0/me/profile"
    USER_PHOTO_URL = "https://graph.microsoft.com/v1.0/me/photo/$value"
    REVOKE_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/logout"
    JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    
    # Alternative endpoints for specific tenant configurations
    TENANT_AUTHORIZATION_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
    TENANT_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    
    # Microsoft-specific configuration
    DEFAULT_SCOPES = ["openid", "profile", "email", "User.Read"]
    REQUIRED_SCOPES = ["openid", "email"]
    
    @property
    def provider_name(self) -> str:
        """Return the unique name of this OAuth provider."""
        return "microsoft"
    
    @property
    def display_name(self) -> str:
        """Return the human-readable display name of this provider."""
        return "Microsoft"
    
    @property
    def supported_scopes(self) -> Set[str]:
        """Return the set of scopes supported by this provider."""
        return {
            # OpenID Connect scopes
            "openid",
            "profile",
            "email",
            "offline_access",  # Required for refresh tokens
            
            # Microsoft Graph User scopes
            "User.Read",
            "User.ReadBasic.All",
            "User.Read.All",
            "User.ReadWrite",
            "User.ReadWrite.All",
            
            # Directory scopes
            "Directory.Read.All",
            "Directory.ReadWrite.All",
            "Directory.AccessAsUser.All",
            
            # Group scopes
            "Group.Read.All",
            "Group.ReadWrite.All",
            "GroupMember.Read.All",
            "GroupMember.ReadWrite.All",
            
            # Organization scopes
            "Organization.Read.All",
            "Organization.ReadWrite.All",
            
            # Application scopes
            "Application.Read.All",
            "Application.ReadWrite.All",
            
            # Calendar scopes
            "Calendars.Read",
            "Calendars.ReadWrite",
            "Calendars.Read.Shared",
            "Calendars.ReadWrite.Shared",
            
            # Mail scopes
            "Mail.Read",
            "Mail.ReadWrite",
            "Mail.Read.Shared",
            "Mail.ReadWrite.Shared",
            "Mail.Send",
            "Mail.Send.Shared",
            
            # Files scopes (OneDrive)
            "Files.Read",
            "Files.ReadWrite",
            "Files.Read.All",
            "Files.ReadWrite.All",
            "Files.Read.Selected",
            "Files.ReadWrite.Selected",
            
            # Sites scopes (SharePoint)
            "Sites.Read.All",
            "Sites.ReadWrite.All",
            "Sites.Manage.All",
            "Sites.FullControl.All",
            
            # Teams scopes
            "Team.ReadBasic.All",
            "TeamSettings.Read.All",
            "TeamSettings.ReadWrite.All",
            "TeamsActivity.Read",
            "TeamsActivity.Send",
            
            # Presence scopes
            "Presence.Read",
            "Presence.Read.All",
            "Presence.ReadWrite",
            
            # Tasks scopes
            "Tasks.Read",
            "Tasks.ReadWrite",
            "Tasks.Read.Shared",
            "Tasks.ReadWrite.Shared",
            
            # Notes scopes (OneNote)
            "Notes.Read",
            "Notes.Create",
            "Notes.ReadWrite",
            "Notes.Read.All",
            "Notes.ReadWrite.All",
        }
    
    def validate_configuration(self) -> bool:
        """Validate the Microsoft OAuth provider configuration."""
        if not super().validate_configuration():
            return False
        
        # Validate Microsoft-specific requirements
        if not self.config:
            return False
        
        # Ensure required scopes are included
        config_scopes = set(self.config.scopes)
        required_scopes = set(self.REQUIRED_SCOPES)
        
        if not required_scopes.issubset(config_scopes):
            missing_scopes = required_scopes - config_scopes
            raise ConfigurationError(
                f"Microsoft OAuth requires scopes: {missing_scopes}",
                config_key=f"oauth.{self.provider_name}.scopes"
            )
        
        # Check if offline_access is included for refresh token support
        if "offline_access" not in config_scopes:
            logger.warning(
                f"Microsoft OAuth configuration missing 'offline_access' scope - refresh tokens will not be available",
                extra={'provider': self.provider_name}
            )
        
        # Validate Microsoft-specific URLs if overridden
        expected_urls = {
            'authorization_url': self.AUTHORIZATION_URL,
            'token_url': self.TOKEN_URL,
            'user_info_url': self.USER_INFO_URL,
        }
        
        for url_field, expected_url in expected_urls.items():
            config_url = getattr(self.config, url_field)
            if config_url and not config_url.startswith('https://'):
                raise ConfigurationError(
                    f"Microsoft OAuth URLs must use HTTPS: {url_field}",
                    config_key=f"oauth.{self.provider_name}.{url_field}"
                )
        
        return True
    
    def get_user_info(self, access_token: str) -> NormalizedUserData:
        """
        Retrieve user information from Microsoft Graph API.
        
        Args:
            access_token: OAuth access token
            
        Returns:
            Normalized user data
            
        Raises:
            OAuthProviderError: If user info retrieval fails
            OAuthTokenExpiredError: If access token is expired
        """
        if not self.config:
            raise ConfigurationError(f"Provider {self.provider_name} is not configured")
        
        try:
            # Get basic user information from Microsoft Graph
            logger.debug(
                f"Fetching user info from Microsoft Graph",
                extra={'provider': self.provider_name, 'endpoint': self.USER_INFO_URL}
            )
            
            user_data = self._make_http_request(
                self.USER_INFO_URL,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                }
            )
            
            # Get additional profile information if available
            profile_data = self._get_user_profile(access_token)
            
            # Get user's photo if available
            photo_url = self._get_user_photo_url(access_token)
            
            logger.info(
                f"Successfully retrieved user info from Microsoft Graph",
                extra={
                    'provider': self.provider_name,
                    'user_id': user_data.get('id'),
                    'user_principal_name': user_data.get('userPrincipalName'),
                    'has_profile_data': bool(profile_data),
                    'has_photo': bool(photo_url),
                }
            )
            
            # Normalize Microsoft user data
            return self._normalize_microsoft_user_data(user_data, profile_data, photo_url)
            
        except HTTPError as e:
            if e.code == 401:
                logger.warning(
                    f"Access token expired for Microsoft Graph",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                raise OAuthTokenExpiredError(
                    f"Access token expired for {self.provider_name}",
                    provider=self.provider_name
                )
            else:
                error_data = {}
                try:
                    error_response = e.read().decode('utf-8')
                    error_data = json.loads(error_response)
                except Exception:
                    pass
                
                logger.warning(
                    f"Failed to get user info from Microsoft Graph",
                    extra={
                        'provider': self.provider_name,
                        'status_code': e.code,
                        'error_data': error_data,
                    }
                )
                raise OAuthProviderError(
                    f"Failed to get user info from {self.provider_name}",
                    provider=self.provider_name,
                    provider_error=error_data.get('error', {}).get('message', f"HTTP {e.code}")
                )
        
        except Exception as e:
            logger.error(
                f"Unexpected error getting user info from Microsoft Graph",
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
    
    def _get_user_profile(self, access_token: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve additional user profile information from Microsoft Graph.
        
        Args:
            access_token: OAuth access token
            
        Returns:
            Profile data dictionary or None if not available
        """
        try:
            logger.debug(
                f"Fetching user profile from Microsoft Graph",
                extra={'provider': self.provider_name}
            )
            
            profile_data = self._make_http_request(
                self.USER_PROFILE_URL,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                }
            )
            
            logger.debug(
                f"Retrieved user profile from Microsoft Graph",
                extra={'provider': self.provider_name}
            )
            
            return profile_data
            
        except HTTPError as e:
            if e.code == 403:
                # Insufficient permissions - profile data not accessible
                logger.debug(
                    f"Insufficient permissions to access Microsoft user profile",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                return None
            else:
                logger.warning(
                    f"Failed to get user profile from Microsoft Graph",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                return None
        
        except Exception as e:
            logger.warning(
                f"Error getting user profile from Microsoft Graph: {e}",
                extra={'provider': self.provider_name}
            )
            return None
    
    def _get_user_photo_url(self, access_token: str) -> Optional[str]:
        """
        Get user's profile photo URL from Microsoft Graph.
        
        Args:
            access_token: OAuth access token
            
        Returns:
            Photo URL or None if not available
        """
        try:
            # First check if photo exists
            photo_metadata_url = "https://graph.microsoft.com/v1.0/me/photo"
            
            logger.debug(
                f"Checking for user photo in Microsoft Graph",
                extra={'provider': self.provider_name}
            )
            
            self._make_http_request(
                photo_metadata_url,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json',
                }
            )
            
            # If photo exists, return the URL to get the actual photo
            photo_url = self.USER_PHOTO_URL
            
            logger.debug(
                f"User photo available in Microsoft Graph",
                extra={'provider': self.provider_name}
            )
            
            return photo_url
            
        except HTTPError as e:
            if e.code == 404:
                # No photo available
                logger.debug(
                    f"No user photo available in Microsoft Graph",
                    extra={'provider': self.provider_name}
                )
                return None
            else:
                logger.debug(
                    f"Cannot access user photo in Microsoft Graph",
                    extra={'provider': self.provider_name, 'status_code': e.code}
                )
                return None
        
        except Exception as e:
            logger.debug(
                f"Error checking user photo in Microsoft Graph: {e}",
                extra={'provider': self.provider_name}
            )
            return None    

    def _normalize_microsoft_user_data(
        self,
        user_data: Dict[str, Any],
        profile_data: Optional[Dict[str, Any]],
        photo_url: Optional[str]
    ) -> NormalizedUserData:
        """
        Normalize Microsoft user data to standard format.
        
        Args:
            user_data: Raw user data from Microsoft Graph API
            profile_data: Additional profile data from Microsoft Graph
            photo_url: User's profile photo URL
            
        Returns:
            Normalized user data
        """
        # Microsoft user ID is required
        provider_user_id = user_data.get('id')
        if not provider_user_id:
            raise OAuthProviderError(
                "Microsoft user data missing required 'id' field",
                provider=self.provider_name
            )
        
        # Extract name information
        first_name = user_data.get('givenName', '')
        last_name = user_data.get('surname', '')
        
        # If we don't have given/surname, try to parse displayName
        if not first_name and not last_name and user_data.get('displayName'):
            name_parts = user_data['displayName'].split(' ', 1)
            first_name = name_parts[0] if len(name_parts) > 0 else ''
            last_name = name_parts[1] if len(name_parts) > 1 else ''
        
        # Extract email information
        email = user_data.get('mail') or user_data.get('userPrincipalName')
        
        # Microsoft Graph doesn't provide explicit email verification status
        # but we can assume work/school accounts are verified
        verified_email = bool(email)
        
        # Extract username - use userPrincipalName as primary identifier
        username = user_data.get('userPrincipalName') or email
        
        # Extract profile information
        display_name = user_data.get('displayName')
        job_title = user_data.get('jobTitle')
        department = user_data.get('department')
        company_name = user_data.get('companyName')
        office_location = user_data.get('officeLocation')
        business_phones = user_data.get('businessPhones', [])
        mobile_phone = user_data.get('mobilePhone')
        
        # Extract locale and timezone information
        preferred_language = user_data.get('preferredLanguage')
        
        # Extract additional profile data if available
        additional_info = {}
        if profile_data:
            # Profile data contains more detailed information
            additional_info.update({
                'profile_data': profile_data
            })
        
        # Determine account type based on userPrincipalName
        account_type = "personal"
        tenant_id = None
        
        if username and '@' in username:
            domain = username.split('@')[1].lower()
            # Common personal account domains
            personal_domains = {
                'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
                'passport.com', 'windowslive.com'
            }
            
            if domain not in personal_domains:
                account_type = "work_school"
                # Extract tenant information if available
                tenant_id = user_data.get('tenantId')
        
        # Extract Microsoft-specific data
        microsoft_data = {
            'user_principal_name': user_data.get('userPrincipalName'),
            'display_name': display_name,
            'account_type': account_type,
            'tenant_id': tenant_id,
            'job_title': job_title,
            'department': department,
            'company_name': company_name,
            'office_location': office_location,
            'business_phones': business_phones,
            'mobile_phone': mobile_phone,
            'preferred_language': preferred_language,
            'user_type': user_data.get('userType'),
            'account_enabled': user_data.get('accountEnabled'),
            'creation_type': user_data.get('creationType'),
            'external_user_state': user_data.get('externalUserState'),
            'external_user_state_change_date_time': user_data.get('externalUserStateChangeDateTime'),
            'identity_providers': user_data.get('identityProviders', []),
            'im_addresses': user_data.get('imAddresses', []),
            'is_resource_account': user_data.get('isResourceAccount'),
            'last_password_change_date_time': user_data.get('lastPasswordChangeDateTime'),
            'legal_age_group_classification': user_data.get('legalAgeGroupClassification'),
            'license_assignment_states': user_data.get('licenseAssignmentStates', []),
            'on_premises_distinguished_name': user_data.get('onPremisesDistinguishedName'),
            'on_premises_domain_name': user_data.get('onPremisesDomainName'),
            'on_premises_sam_account_name': user_data.get('onPremisesSamAccountName'),
            'on_premises_security_identifier': user_data.get('onPremisesSecurityIdentifier'),
            'on_premises_sync_enabled': user_data.get('onPremisesSyncEnabled'),
            'on_premises_user_principal_name': user_data.get('onPremisesUserPrincipalName'),
            'password_policies': user_data.get('passwordPolicies'),
            'password_profile': user_data.get('passwordProfile'),
            'postal_code': user_data.get('postalCode'),
            'preferred_data_location': user_data.get('preferredDataLocation'),
            'proxy_addresses': user_data.get('proxyAddresses', []),
            'refresh_tokens_valid_from_date_time': user_data.get('refreshTokensValidFromDateTime'),
            'show_in_address_list': user_data.get('showInAddressList'),
            'sign_in_sessions_valid_from_date_time': user_data.get('signInSessionsValidFromDateTime'),
            'state': user_data.get('state'),
            'street_address': user_data.get('streetAddress'),
            'usage_location': user_data.get('usageLocation'),
            'user_principal_name': user_data.get('userPrincipalName'),
        }
        
        # Add additional profile information
        if additional_info:
            microsoft_data.update(additional_info)
        
        # Remove None values from microsoft_data
        microsoft_data = {k: v for k, v in microsoft_data.items() if v is not None}
        
        # Determine timezone from usage location or preferred language
        timezone = None
        if user_data.get('usageLocation'):
            # Basic timezone mapping from country codes
            timezone_mapping = {
                'US': 'America/New_York',
                'CA': 'America/Toronto',
                'GB': 'Europe/London',
                'DE': 'Europe/Berlin',
                'FR': 'Europe/Paris',
                'IT': 'Europe/Rome',
                'ES': 'Europe/Madrid',
                'NL': 'Europe/Amsterdam',
                'BE': 'Europe/Brussels',
                'CH': 'Europe/Zurich',
                'AT': 'Europe/Vienna',
                'SE': 'Europe/Stockholm',
                'NO': 'Europe/Oslo',
                'DK': 'Europe/Copenhagen',
                'FI': 'Europe/Helsinki',
                'PL': 'Europe/Warsaw',
                'CZ': 'Europe/Prague',
                'HU': 'Europe/Budapest',
                'RO': 'Europe/Bucharest',
                'BG': 'Europe/Sofia',
                'GR': 'Europe/Athens',
                'TR': 'Europe/Istanbul',
                'RU': 'Europe/Moscow',
                'JP': 'Asia/Tokyo',
                'KR': 'Asia/Seoul',
                'CN': 'Asia/Shanghai',
                'IN': 'Asia/Kolkata',
                'SG': 'Asia/Singapore',
                'HK': 'Asia/Hong_Kong',
                'TW': 'Asia/Taipei',
                'AU': 'Australia/Sydney',
                'NZ': 'Pacific/Auckland',
                'ZA': 'Africa/Johannesburg',
                'EG': 'Africa/Cairo',
                'IL': 'Asia/Jerusalem',
                'AE': 'Asia/Dubai',
                'SA': 'Asia/Riyadh',
                'BR': 'America/Sao_Paulo',
                'MX': 'America/Mexico_City',
                'AR': 'America/Argentina/Buenos_Aires',
                'CL': 'America/Santiago',
                'CO': 'America/Bogota',
                'PE': 'America/Lima',
                'VE': 'America/Caracas',
            }
            timezone = timezone_mapping.get(user_data.get('usageLocation'))
        
        # Fallback to language-based timezone mapping
        if not timezone and preferred_language:
            language_timezone_mapping = {
                'en-US': 'America/New_York',
                'en-GB': 'Europe/London',
                'en-CA': 'America/Toronto',
                'en-AU': 'Australia/Sydney',
                'de-DE': 'Europe/Berlin',
                'fr-FR': 'Europe/Paris',
                'es-ES': 'Europe/Madrid',
                'it-IT': 'Europe/Rome',
                'ja-JP': 'Asia/Tokyo',
                'ko-KR': 'Asia/Seoul',
                'zh-CN': 'Asia/Shanghai',
                'zh-TW': 'Asia/Taipei',
                'pt-BR': 'America/Sao_Paulo',
                'ru-RU': 'Europe/Moscow',
                'ar-SA': 'Asia/Riyadh',
                'hi-IN': 'Asia/Kolkata',
                'nl-NL': 'Europe/Amsterdam',
                'sv-SE': 'Europe/Stockholm',
                'no-NO': 'Europe/Oslo',
                'da-DK': 'Europe/Copenhagen',
                'fi-FI': 'Europe/Helsinki',
                'pl-PL': 'Europe/Warsaw',
                'cs-CZ': 'Europe/Prague',
                'hu-HU': 'Europe/Budapest',
                'ro-RO': 'Europe/Bucharest',
                'bg-BG': 'Europe/Sofia',
                'el-GR': 'Europe/Athens',
                'tr-TR': 'Europe/Istanbul',
            }
            timezone = language_timezone_mapping.get(preferred_language)
        
        logger.debug(
            f"Normalized Microsoft user data",
            extra={
                'provider': self.provider_name,
                'user_id': provider_user_id,
                'user_principal_name': username,
                'email': email,
                'verified_email': verified_email,
                'account_type': account_type,
                'has_profile_picture': bool(photo_url),
                'preferred_language': preferred_language,
                'usage_location': user_data.get('usageLocation'),
                'company_name': company_name,
                'department': department,
                'job_title': job_title,
            }
        )
        
        return NormalizedUserData(
            provider_user_id=str(provider_user_id),
            email=email,
            first_name=first_name,
            last_name=last_name,
            username=username,
            profile_picture_url=photo_url,
            locale=preferred_language,
            timezone=timezone,
            verified_email=verified_email,
            raw_data={
                **user_data,
                'microsoft_specific': microsoft_data,
            }
        )
    
    def get_authorization_url(
        self,
        state: str,
        scopes: Optional[list[str]] = None,
        extra_params: Optional[Dict[str, str]] = None
    ) -> "AuthorizationRequest":
        """
        Generate Microsoft OAuth authorization URL with PKCE and OpenID Connect support.
        
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
        
        # Microsoft-specific extra parameters
        microsoft_extra_params = {
            'response_mode': 'query',  # Use query parameters for response
            'prompt': 'select_account',  # Allow user to select account
        }
        
        # Merge with provided extra parameters
        if extra_params:
            microsoft_extra_params.update(extra_params)
        
        # Call parent implementation with Microsoft-specific parameters
        return super().get_authorization_url(
            state=state,
            scopes=scopes,
            extra_params=microsoft_extra_params
        )
    
    def exchange_code_for_token(
        self,
        code: str,
        state: str,
        code_verifier: Optional[str] = None
    ) -> TokenData:
        """
        Exchange authorization code for Microsoft OAuth tokens.
        
        This method handles Microsoft-specific token exchange requirements
        and validates the returned tokens.
        
        Args:
            code: Authorization code from OAuth callback
            state: State parameter for verification
            code_verifier: PKCE code verifier if used
            
        Returns:
            Token data including access and refresh tokens
        """
        # Call parent implementation
        token_data = super().exchange_code_for_token(code, state, code_verifier)
        
        # Microsoft-specific token validation
        if token_data.id_token:
            try:
                # Basic ID token validation (in production, you'd want to verify signature)
                id_token_payload = self._decode_id_token(token_data.id_token)
                
                logger.debug(
                    f"Received Microsoft ID token",
                    extra={
                        'provider': self.provider_name,
                        'aud': id_token_payload.get('aud'),
                        'iss': id_token_payload.get('iss'),
                        'sub': id_token_payload.get('sub'),
                        'tid': id_token_payload.get('tid'),  # Tenant ID
                    }
                )
                
                # Validate issuer
                expected_issuers = [
                    'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',  # Personal accounts
                    f"https://login.microsoftonline.com/{id_token_payload.get('tid')}/v2.0",  # Work/school accounts
                ]
                
                if not any(id_token_payload.get('iss', '').startswith(issuer.split('/v2.0')[0]) for issuer in expected_issuers):
                    logger.warning(
                        f"Unexpected ID token issuer from Microsoft",
                        extra={
                            'provider': self.provider_name,
                            'issuer': id_token_payload.get('iss'),
                        }
                    )
                
                # Validate audience (should match client_id)
                if self.config and id_token_payload.get('aud') != self.config.client_id:
                    logger.warning(
                        f"ID token audience mismatch",
                        extra={
                            'provider': self.provider_name,
                            'expected_aud': self.config.client_id,
                            'actual_aud': id_token_payload.get('aud'),
                        }
                    )
                
            except Exception as e:
                logger.warning(
                    f"Failed to validate Microsoft ID token: {e}",
                    extra={'provider': self.provider_name}
                )
        
        return token_data
    
    def _decode_id_token(self, id_token: str) -> Dict[str, Any]:
        """
        Decode Microsoft ID token payload (without signature verification).
        
        Note: In production, you should verify the signature using Microsoft's public keys.
        
        Args:
            id_token: JWT ID token from Microsoft
            
        Returns:
            Decoded token payload
        """
        import base64
        
        try:
            # Split the JWT into parts
            parts = id_token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
            
            # Decode the payload (second part)
            payload = parts[1]
            
            # Add padding if needed
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            
            # Decode base64
            decoded_bytes = base64.urlsafe_b64decode(payload)
            payload_data = json.loads(decoded_bytes.decode('utf-8'))
            
            return payload_data
            
        except Exception as e:
            logger.error(
                f"Failed to decode Microsoft ID token: {e}",
                extra={'provider': self.provider_name}
            )
            return {}
    
    def refresh_access_token(self, refresh_token: str) -> TokenData:
        """
        Refresh Microsoft OAuth access token.
        
        Args:
            refresh_token: OAuth refresh token
            
        Returns:
            New token data
        """
        token_data = super().refresh_access_token(refresh_token)
        
        # Microsoft typically returns a new refresh token
        # If no new refresh token is provided, keep the old one
        if not token_data.refresh_token:
            token_data.refresh_token = refresh_token
            
            logger.debug(
                f"Microsoft did not provide new refresh token, keeping existing one",
                extra={'provider': self.provider_name}
            )
        
        return token_data
    
    def revoke_token(self, token: str, token_type: str = "access_token") -> bool:
        """
        Revoke a Microsoft OAuth token.
        
        Note: Microsoft doesn't provide a standard token revocation endpoint.
        This method logs out the user from all Microsoft sessions.
        
        Args:
            token: Token to revoke
            token_type: Type of token (access_token or refresh_token)
            
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
            # Microsoft doesn't have a standard revocation endpoint
            # Instead, we redirect to the logout URL which invalidates all tokens
            logout_url = f"{self.REVOKE_URL}?post_logout_redirect_uri={self.config.redirect_uri}"
            
            logger.info(
                f"Microsoft token revocation requires user logout",
                extra={
                    'provider': self.provider_name,
                    'token_type': token_type,
                    'logout_url': logout_url,
                }
            )
            
            # Since we can't programmatically revoke tokens, we return True
            # but the application should redirect the user to the logout URL
            return True
            
        except Exception as e:
            logger.error(
                f"Error during Microsoft token revocation: {e}",
                extra={
                    'provider': self.provider_name,
                    'token_type': token_type,
                }
            )
            return False
    
    def get_provider_metadata(self) -> Dict[str, Any]:
        """
        Get Microsoft OAuth provider metadata.
        
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
            'jwks_uri': self.JWKS_URL,
            'supported_scopes': list(self.supported_scopes),
            'default_scopes': self.DEFAULT_SCOPES,
            'required_scopes': self.REQUIRED_SCOPES,
            'supports_pkce': True,
            'supports_refresh_token': True,
            'supports_id_token': True,
            'supports_openid_connect': True,
            'supports_personal_accounts': True,
            'supports_work_school_accounts': True,
            'issuer': 'https://login.microsoftonline.com',
            'graph_api_endpoint': 'https://graph.microsoft.com/v1.0',
            'documentation_url': 'https://docs.microsoft.com/en-us/azure/active-directory/develop/',
            'privacy_policy_url': 'https://privacy.microsoft.com/en-us/privacystatement',
            'terms_of_service_url': 'https://www.microsoft.com/en-us/servicesagreement',
        }