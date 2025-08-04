"""
Example implementations and usage of the OAuth provider abstraction layer.

This module provides examples of how to implement concrete OAuth providers
and use the OAuth abstraction layer for authentication flows.
"""

from typing import Set

from .oauth_provider import BaseOAuthProvider, NormalizedUserData


class GoogleOAuthProvider(BaseOAuthProvider):
    """
    Example Google OAuth provider implementation.
    
    This is a simplified example showing how to implement a concrete
    OAuth provider using the base abstraction layer.
    """
    
    @property
    def provider_name(self) -> str:
        return "google"
    
    @property
    def display_name(self) -> str:
        return "Google"
    
    @property
    def supported_scopes(self) -> Set[str]:
        return {
            "openid",
            "email",
            "profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        }
    
    def get_user_info(self, access_token: str) -> NormalizedUserData:
        """Get user information from Google's userinfo endpoint."""
        if not self.config:
            raise ValueError("Provider not configured")
        
        try:
            # Make request to Google's userinfo endpoint
            user_data = self._make_http_request(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={'Authorization': f'Bearer {access_token}'}
            )
            
            # Normalize Google's user data format
            return NormalizedUserData(
                provider_user_id=user_data['id'],
                email=user_data.get('email'),
                first_name=user_data.get('given_name'),
                last_name=user_data.get('family_name'),
                username=user_data.get('email'),  # Google uses email as username
                profile_picture_url=user_data.get('picture'),
                locale=user_data.get('locale'),
                verified_email=user_data.get('verified_email', False),
                raw_data=user_data
            )
            
        except Exception as e:
            from ..exceptions import OAuthProviderError
            raise OAuthProviderError(
                f"Failed to get user info from Google: {e}",
                provider=self.provider_name
            )


class GitHubOAuthProvider(BaseOAuthProvider):
    """
    Example GitHub OAuth provider implementation.
    
    This is a simplified example showing how to implement a concrete
    OAuth provider using the base abstraction layer.
    """
    
    @property
    def provider_name(self) -> str:
        return "github"
    
    @property
    def display_name(self) -> str:
        return "GitHub"
    
    @property
    def supported_scopes(self) -> Set[str]:
        return {
            "user",
            "user:email",
            "read:user",
            "user:follow",
            "public_repo",
            "repo",
            "repo_deployment",
            "repo:status",
            "delete_repo",
            "notifications",
            "gist",
            "read:repo_hook",
            "write:repo_hook",
            "admin:repo_hook",
            "admin:org_hook",
            "read:org",
            "write:org",
            "admin:org",
            "read:public_key",
            "write:public_key",
            "admin:public_key",
            "read:gpg_key",
            "write:gpg_key",
            "admin:gpg_key"
        }
    
    def get_user_info(self, access_token: str) -> NormalizedUserData:
        """Get user information from GitHub's user endpoint."""
        if not self.config:
            raise ValueError("Provider not configured")
        
        try:
            # Make request to GitHub's user endpoint
            user_data = self._make_http_request(
                "https://api.github.com/user",
                headers={'Authorization': f'Bearer {access_token}'}
            )
            
            # Get user's primary email (requires user:email scope)
            email = user_data.get('email')
            if not email:
                try:
                    emails_data = self._make_http_request(
                        "https://api.github.com/user/emails",
                        headers={'Authorization': f'Bearer {access_token}'}
                    )
                    # Find primary email
                    for email_info in emails_data:
                        if email_info.get('primary', False):
                            email = email_info.get('email')
                            break
                except Exception:
                    # If we can't get emails, continue without email
                    pass
            
            # Parse name into first and last name
            full_name = user_data.get('name', '')
            name_parts = full_name.split(' ', 1) if full_name else ['', '']
            first_name = name_parts[0] if len(name_parts) > 0 else ''
            last_name = name_parts[1] if len(name_parts) > 1 else ''
            
            # Normalize GitHub's user data format
            return NormalizedUserData(
                provider_user_id=str(user_data['id']),
                email=email,
                first_name=first_name,
                last_name=last_name,
                username=user_data.get('login'),
                profile_picture_url=user_data.get('avatar_url'),
                verified_email=bool(email),  # GitHub emails are generally verified
                raw_data=user_data
            )
            
        except Exception as e:
            from ..exceptions import OAuthProviderError
            raise OAuthProviderError(
                f"Failed to get user info from GitHub: {e}",
                provider=self.provider_name
            )


# Example usage functions
def setup_oauth_providers():
    """
    Example function showing how to register OAuth providers.
    
    This would typically be called during application startup.
    """
    from .oauth_registry import oauth_registry
    from .oauth_provider import ProviderConfig
    
    # Register Google OAuth provider
    oauth_registry.register_provider(
        name="google",
        provider_class=GoogleOAuthProvider,
        display_name="Google",
        description="Sign in with your Google account",
        icon_url="https://developers.google.com/identity/images/g-logo.png",
        auto_configure=False
    )
    
    # Configure Google OAuth provider
    google_config = ProviderConfig(
        client_id="your-google-client-id",
        client_secret="your-google-client-secret",
        redirect_uri="https://yourapp.com/auth/google/callback",
        scopes=["openid", "email", "profile"],
        authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        user_info_url="https://www.googleapis.com/oauth2/v2/userinfo",
        revoke_url="https://oauth2.googleapis.com/revoke",
        extra_params={"access_type": "offline", "prompt": "consent"},
        use_pkce=True
    )
    oauth_registry.configure_provider("google", google_config)
    
    # Register GitHub OAuth provider
    oauth_registry.register_provider(
        name="github",
        provider_class=GitHubOAuthProvider,
        display_name="GitHub",
        description="Sign in with your GitHub account",
        icon_url="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
        auto_configure=False
    )
    
    # Configure GitHub OAuth provider
    github_config = ProviderConfig(
        client_id="your-github-client-id",
        client_secret="your-github-client-secret",
        redirect_uri="https://yourapp.com/auth/github/callback",
        scopes=["user:email"],
        authorization_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        user_info_url="https://api.github.com/user",
        use_pkce=False  # GitHub doesn't support PKCE
    )
    oauth_registry.configure_provider("github", github_config)


def example_oauth_flow():
    """
    Example function showing how to use the OAuth service for authentication.
    
    This demonstrates the typical OAuth flow from initiation to user creation.
    """
    from .oauth_service import oauth_service
    
    # Step 1: Initiate OAuth authorization
    auth_request = oauth_service.initiate_authorization(
        provider_name="google",
        state="random-state-string",
        scopes=["openid", "email", "profile"]
    )
    
    print(f"Redirect user to: {auth_request.authorization_url}")
    
    # Step 2: Handle OAuth callback (this would be in your callback view)
    # Assuming you received the authorization code from the callback
    authorization_code = "received-from-callback"
    state = "random-state-string"
    
    token_data, user_data = oauth_service.handle_callback(
        provider_name="google",
        code=authorization_code,
        state=state,
        code_verifier=auth_request.code_verifier
    )
    
    print(f"Access Token: {token_data.access_token}")
    print(f"User Email: {user_data.email}")
    print(f"User Name: {user_data.first_name} {user_data.last_name}")
    
    # Step 3: Link identity to user account (assuming you have a user)
    # user = get_or_create_user_from_oauth_data(user_data)
    # identity = oauth_service.link_user_identity(
    #     user=user,
    #     provider_name="google",
    #     token_data=token_data,
    #     user_data=user_data,
    #     is_primary=True
    # )
    
    return user_data


def example_provider_management():
    """
    Example function showing how to manage OAuth providers dynamically.
    """
    from .oauth_registry import oauth_registry
    
    # List all available providers
    providers = oauth_registry.get_available_providers()
    print("Available OAuth providers:")
    for provider in providers:
        print(f"  - {provider['display_name']} ({provider['name']})")
    
    # Check provider health
    health_status = oauth_registry.health_check()
    print(f"\nProvider Health Status:")
    print(f"  Total providers: {health_status['total_providers']}")
    print(f"  Configured providers: {health_status['configured_providers']}")
    print(f"  Enabled providers: {health_status['enabled_providers']}")
    
    # Disable a provider
    oauth_registry.disable_provider("github")
    print("\nDisabled GitHub provider")
    
    # Re-enable a provider
    oauth_registry.enable_provider("github")
    print("Re-enabled GitHub provider")


if __name__ == "__main__":
    # This would typically be called during Django app initialization
    setup_oauth_providers()
    
    # Example of using the OAuth flow
    print("OAuth Provider Abstraction Layer Examples")
    print("=" * 50)
    
    example_provider_management()