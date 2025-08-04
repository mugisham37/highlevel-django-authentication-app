"""
OAuth providers registration and initialization.

This module handles the registration and initialization of all OAuth providers
in the system, including Google, GitHub, Microsoft, and other providers.
"""

import logging
from typing import Dict, Any

from django.conf import settings

from .oauth_registry import oauth_registry
from .oauth_config import oauth_config_manager
from .providers.google_oauth import GoogleOAuthProvider
from .providers.github_oauth import GitHubOAuthProvider
from .providers.microsoft_oauth import MicrosoftOAuthProvider

logger = logging.getLogger(__name__)


def register_google_oauth_provider() -> None:
    """
    Register and configure the Google OAuth provider.
    
    This function registers the Google OAuth provider with the registry
    and configures it based on Django settings or environment variables.
    """
    try:
        # Register the Google OAuth provider
        oauth_registry.register_provider(
            name="google",
            provider_class=GoogleOAuthProvider,
            display_name="Google",
            description="Sign in with your Google account using OAuth2/OpenID Connect",
            icon_url="https://developers.google.com/identity/images/g-logo.png",
            documentation_url="https://developers.google.com/identity/protocols/oauth2",
            auto_configure=False  # We'll configure manually for better control
        )
        
        # Try to load configuration from settings first
        config = oauth_config_manager.load_config_from_settings("google")
        
        # If not found in settings, try environment variables
        if not config:
            config = oauth_config_manager.load_config_from_env("google")
        
        # If still not found, create a default configuration template
        if not config:
            logger.info(
                "No Google OAuth configuration found, creating default template",
                extra={'provider': 'google'}
            )
            
            # Create default configuration with Google's standard endpoints
            config = oauth_config_manager.create_config(
                provider_name="google",
                client_id=getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', ''),
                client_secret=getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', ''),
                redirect_uri=getattr(settings, 'GOOGLE_OAUTH_REDIRECT_URI', ''),
                scopes=getattr(settings, 'GOOGLE_OAUTH_SCOPES', ['openid', 'email', 'profile']),
                authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
                token_url="https://oauth2.googleapis.com/token",
                user_info_url="https://www.googleapis.com/oauth2/v2/userinfo",
                revoke_url="https://oauth2.googleapis.com/revoke",
                extra_params={
                    'access_type': 'offline',
                    'prompt': 'consent',
                    'include_granted_scopes': 'true',
                },
                timeout=30,
                use_pkce=True
            )
        
        # Configure the provider
        if config:
            oauth_registry.configure_provider("google", config)
            
            # Enable the provider if it has valid configuration
            if config.client_id and config.client_secret:
                oauth_registry.enable_provider("google")
                logger.info(
                    "Google OAuth provider registered and enabled successfully",
                    extra={'provider': 'google'}
                )
            else:
                oauth_registry.disable_provider("google")
                logger.warning(
                    "Google OAuth provider registered but disabled due to missing credentials",
                    extra={'provider': 'google'}
                )
        
    except Exception as e:
        logger.error(
            f"Failed to register Google OAuth provider: {e}",
            extra={'provider': 'google', 'error': str(e)}
        )
        
        # Disable the provider if registration fails
        try:
            oauth_registry.disable_provider("google")
        except Exception:
            pass


def register_github_oauth_provider() -> None:
    """
    Register and configure the GitHub OAuth provider.
    
    This function registers the GitHub OAuth provider with the registry
    and configures it based on Django settings or environment variables.
    """
    try:
        # Register the GitHub OAuth provider
        oauth_registry.register_provider(
            name="github",
            provider_class=GitHubOAuthProvider,
            display_name="GitHub",
            description="Sign in with your GitHub account using OAuth2",
            icon_url="https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
            documentation_url="https://docs.github.com/en/developers/apps/building-oauth-apps",
            auto_configure=False  # We'll configure manually for better control
        )
        
        # Try to load configuration from settings first
        config = oauth_config_manager.load_config_from_settings("github")
        
        # If not found in settings, try environment variables
        if not config:
            config = oauth_config_manager.load_config_from_env("github")
        
        # If still not found, create a default configuration template
        if not config:
            logger.info(
                "No GitHub OAuth configuration found, creating default template",
                extra={'provider': 'github'}
            )
            
            # Create default configuration with GitHub's standard endpoints
            config = oauth_config_manager.create_config(
                provider_name="github",
                client_id=getattr(settings, 'GITHUB_OAUTH_CLIENT_ID', ''),
                client_secret=getattr(settings, 'GITHUB_OAUTH_CLIENT_SECRET', ''),
                redirect_uri=getattr(settings, 'GITHUB_OAUTH_REDIRECT_URI', ''),
                scopes=getattr(settings, 'GITHUB_OAUTH_SCOPES', ['user:email', 'read:user']),
                authorization_url="https://github.com/login/oauth/authorize",
                token_url="https://github.com/login/oauth/access_token",
                user_info_url="https://api.github.com/user",
                revoke_url="https://api.github.com/applications/{client_id}/grant",
                extra_params={
                    'allow_signup': 'true',
                },
                timeout=30,
                use_pkce=True
            )
        
        # Configure the provider
        if config:
            oauth_registry.configure_provider("github", config)
            
            # Enable the provider if it has valid configuration
            if config.client_id and config.client_secret:
                oauth_registry.enable_provider("github")
                logger.info(
                    "GitHub OAuth provider registered and enabled successfully",
                    extra={'provider': 'github'}
                )
            else:
                oauth_registry.disable_provider("github")
                logger.warning(
                    "GitHub OAuth provider registered but disabled due to missing credentials",
                    extra={'provider': 'github'}
                )
        
    except Exception as e:
        logger.error(
            f"Failed to register GitHub OAuth provider: {e}",
            extra={'provider': 'github', 'error': str(e)}
        )
        
        # Disable the provider if registration fails
        try:
            oauth_registry.disable_provider("github")
        except Exception:
            pass


def register_microsoft_oauth_provider() -> None:
    """
    Register and configure the Microsoft OAuth provider.
    
    This function registers the Microsoft OAuth provider with the registry
    and configures it based on Django settings or environment variables.
    """
    try:
        # Register the Microsoft OAuth provider
        oauth_registry.register_provider(
            name="microsoft",
            provider_class=MicrosoftOAuthProvider,
            display_name="Microsoft",
            description="Sign in with your Microsoft account using OAuth2/OpenID Connect",
            icon_url="https://docs.microsoft.com/en-us/azure/active-directory/develop/media/howto-add-branding-in-azure-ad-apps/ms-symbollockup_mssymbol_19.png",
            documentation_url="https://docs.microsoft.com/en-us/azure/active-directory/develop/",
            auto_configure=False  # We'll configure manually for better control
        )
        
        # Try to load configuration from settings first
        config = oauth_config_manager.load_config_from_settings("microsoft")
        
        # If not found in settings, try environment variables
        if not config:
            config = oauth_config_manager.load_config_from_env("microsoft")
        
        # If still not found, create a default configuration template
        if not config:
            logger.info(
                "No Microsoft OAuth configuration found, creating default template",
                extra={'provider': 'microsoft'}
            )
            
            # Create default configuration with Microsoft's standard endpoints
            config = oauth_config_manager.create_config(
                provider_name="microsoft",
                client_id=getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', ''),
                client_secret=getattr(settings, 'MICROSOFT_OAUTH_CLIENT_SECRET', ''),
                redirect_uri=getattr(settings, 'MICROSOFT_OAUTH_REDIRECT_URI', ''),
                scopes=getattr(settings, 'MICROSOFT_OAUTH_SCOPES', ['openid', 'profile', 'email', 'User.Read']),
                authorization_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token",
                user_info_url="https://graph.microsoft.com/v1.0/me",
                revoke_url="https://login.microsoftonline.com/common/oauth2/v2.0/logout",
                extra_params={
                    'response_mode': 'query',
                    'prompt': 'select_account',
                },
                timeout=30,
                use_pkce=True
            )
        
        # Configure the provider
        if config:
            oauth_registry.configure_provider("microsoft", config)
            
            # Enable the provider if it has valid configuration
            if config.client_id and config.client_secret:
                oauth_registry.enable_provider("microsoft")
                logger.info(
                    "Microsoft OAuth provider registered and enabled successfully",
                    extra={'provider': 'microsoft'}
                )
            else:
                oauth_registry.disable_provider("microsoft")
                logger.warning(
                    "Microsoft OAuth provider registered but disabled due to missing credentials",
                    extra={'provider': 'microsoft'}
                )
        
    except Exception as e:
        logger.error(
            f"Failed to register Microsoft OAuth provider: {e}",
            extra={'provider': 'microsoft', 'error': str(e)}
        )
        
        # Disable the provider if registration fails
        try:
            oauth_registry.disable_provider("microsoft")
        except Exception:
            pass


def register_all_oauth_providers() -> None:
    """
    Register all available OAuth providers.
    
    This function should be called during Django app initialization
    to register all OAuth providers with the system.
    """
    logger.info("Registering OAuth providers...")
    
    # Register Google OAuth provider
    register_google_oauth_provider()
    
    # Register GitHub OAuth provider
    register_github_oauth_provider()
    
    # Register Microsoft OAuth provider
    register_microsoft_oauth_provider()
    
    # TODO: Register other providers as they are implemented
    # register_apple_oauth_provider()
    # register_linkedin_oauth_provider()
    
    # Log summary
    providers = oauth_registry.list_providers()
    configured_providers = [p for p in providers if p.is_configured]
    enabled_providers = [p for p in providers if p.is_enabled]
    
    logger.info(
        f"OAuth provider registration complete",
        extra={
            'total_providers': len(providers),
            'configured_providers': len(configured_providers),
            'enabled_providers': len(enabled_providers),
            'provider_names': [p.name for p in providers],
        }
    )


def get_oauth_provider_status() -> Dict[str, Any]:
    """
    Get the status of all OAuth providers.
    
    Returns:
        Dictionary containing provider status information
    """
    return oauth_registry.health_check()


def initialize_oauth_system() -> None:
    """
    Initialize the complete OAuth system.
    
    This function should be called during Django app startup to:
    1. Register all OAuth providers
    2. Initialize configurations
    3. Perform health checks
    """
    try:
        logger.info("Initializing OAuth system...")
        
        # Register all providers
        register_all_oauth_providers()
        
        # Initialize the registry from settings (if any additional config exists)
        oauth_registry.initialize_from_settings()
        
        # Perform health check
        health_status = get_oauth_provider_status()
        
        logger.info(
            "OAuth system initialization complete",
            extra={
                'health_status': health_status,
                'initialization_successful': True,
            }
        )
        
    except Exception as e:
        logger.error(
            f"Failed to initialize OAuth system: {e}",
            extra={'error': str(e), 'initialization_successful': False}
        )
        raise


# Example Django settings for OAuth providers
EXAMPLE_SETTINGS = """
# Add to your Django settings.py

# Google OAuth Configuration
GOOGLE_OAUTH_CLIENT_ID = 'your-google-client-id.apps.googleusercontent.com'
GOOGLE_OAUTH_CLIENT_SECRET = 'your-google-client-secret'
GOOGLE_OAUTH_REDIRECT_URI = 'https://yourdomain.com/auth/google/callback'
GOOGLE_OAUTH_SCOPES = ['openid', 'email', 'profile']

# GitHub OAuth Configuration
GITHUB_OAUTH_CLIENT_ID = 'your-github-client-id'
GITHUB_OAUTH_CLIENT_SECRET = 'your-github-client-secret'
GITHUB_OAUTH_REDIRECT_URI = 'https://yourdomain.com/auth/github/callback'
GITHUB_OAUTH_SCOPES = ['user:email', 'read:user', 'read:org']

# Microsoft OAuth Configuration
MICROSOFT_OAUTH_CLIENT_ID = 'your-microsoft-client-id'
MICROSOFT_OAUTH_CLIENT_SECRET = 'your-microsoft-client-secret'
MICROSOFT_OAUTH_REDIRECT_URI = 'https://yourdomain.com/auth/microsoft/callback'
MICROSOFT_OAUTH_SCOPES = ['openid', 'profile', 'email', 'User.Read']

# Alternative: Configure via OAUTH_PROVIDERS setting
OAUTH_PROVIDERS = {
    'google': {
        'provider_class': 'enterprise_auth.core.services.providers.google_oauth.GoogleOAuthProvider',
        'client_id': 'your-google-client-id.apps.googleusercontent.com',
        'client_secret': 'your-google-client-secret',
        'redirect_uri': 'https://yourdomain.com/auth/google/callback',
        'scopes': ['openid', 'email', 'profile'],
        'authorization_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_url': 'https://oauth2.googleapis.com/token',
        'user_info_url': 'https://www.googleapis.com/oauth2/v2/userinfo',
        'revoke_url': 'https://oauth2.googleapis.com/revoke',
        'extra_params': {
            'access_type': 'offline',
            'prompt': 'consent',
            'include_granted_scopes': 'true',
        },
        'timeout': 30,
        'use_pkce': True,
        'enabled': True,
        'display_name': 'Google',
        'description': 'Sign in with your Google account',
        'icon_url': 'https://developers.google.com/identity/images/g-logo.png',
        'documentation_url': 'https://developers.google.com/identity/protocols/oauth2',
    },
    'github': {
        'provider_class': 'enterprise_auth.core.services.providers.github_oauth.GitHubOAuthProvider',
        'client_id': 'your-github-client-id',
        'client_secret': 'your-github-client-secret',
        'redirect_uri': 'https://yourdomain.com/auth/github/callback',
        'scopes': ['user:email', 'read:user', 'read:org'],
        'authorization_url': 'https://github.com/login/oauth/authorize',
        'token_url': 'https://github.com/login/oauth/access_token',
        'user_info_url': 'https://api.github.com/user',
        'revoke_url': 'https://api.github.com/applications/{client_id}/grant',
        'extra_params': {
            'allow_signup': 'true',
        },
        'timeout': 30,
        'use_pkce': True,
        'enabled': True,
        'display_name': 'GitHub',
        'description': 'Sign in with your GitHub account',
        'icon_url': 'https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png',
        'documentation_url': 'https://docs.github.com/en/developers/apps/building-oauth-apps',
    },
    'microsoft': {
        'provider_class': 'enterprise_auth.core.services.providers.microsoft_oauth.MicrosoftOAuthProvider',
        'client_id': 'your-microsoft-client-id',
        'client_secret': 'your-microsoft-client-secret',
        'redirect_uri': 'https://yourdomain.com/auth/microsoft/callback',
        'scopes': ['openid', 'profile', 'email', 'User.Read'],
        'authorization_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        'token_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        'user_info_url': 'https://graph.microsoft.com/v1.0/me',
        'revoke_url': 'https://login.microsoftonline.com/common/oauth2/v2.0/logout',
        'extra_params': {
            'response_mode': 'query',
            'prompt': 'select_account',
        },
        'timeout': 30,
        'use_pkce': True,
        'enabled': True,
        'display_name': 'Microsoft',
        'description': 'Sign in with your Microsoft account',
        'icon_url': 'https://docs.microsoft.com/en-us/azure/active-directory/develop/media/howto-add-branding-in-azure-ad-apps/ms-symbollockup_mssymbol_19.png',
        'documentation_url': 'https://docs.microsoft.com/en-us/azure/active-directory/develop/',
    }
}

# Environment Variables Alternative
# OAUTH_GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
# OAUTH_GOOGLE_CLIENT_SECRET=your-google-client-secret
# OAUTH_GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/google/callback
# OAUTH_GOOGLE_SCOPES=openid,email,profile
# OAUTH_GOOGLE_AUTHORIZATION_URL=https://accounts.google.com/o/oauth2/v2/auth
# OAUTH_GOOGLE_TOKEN_URL=https://oauth2.googleapis.com/token
# OAUTH_GOOGLE_USER_INFO_URL=https://www.googleapis.com/oauth2/v2/userinfo
# OAUTH_GOOGLE_REVOKE_URL=https://oauth2.googleapis.com/revoke
# OAUTH_GOOGLE_TIMEOUT=30
# OAUTH_GOOGLE_USE_PKCE=true

# GitHub OAuth Environment Variables
# OAUTH_GITHUB_CLIENT_ID=your-github-client-id
# OAUTH_GITHUB_CLIENT_SECRET=your-github-client-secret
# OAUTH_GITHUB_REDIRECT_URI=https://yourdomain.com/auth/github/callback
# OAUTH_GITHUB_SCOPES=user:email,read:user,read:org
# OAUTH_GITHUB_AUTHORIZATION_URL=https://github.com/login/oauth/authorize
# OAUTH_GITHUB_TOKEN_URL=https://github.com/login/oauth/access_token
# OAUTH_GITHUB_USER_INFO_URL=https://api.github.com/user
# OAUTH_GITHUB_REVOKE_URL=https://api.github.com/applications/{client_id}/grant
# OAUTH_GITHUB_TIMEOUT=30
# OAUTH_GITHUB_USE_PKCE=true

# Microsoft OAuth Environment Variables
# OAUTH_MICROSOFT_CLIENT_ID=your-microsoft-client-id
# OAUTH_MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
# OAUTH_MICROSOFT_REDIRECT_URI=https://yourdomain.com/auth/microsoft/callback
# OAUTH_MICROSOFT_SCOPES=openid,profile,email,User.Read
# OAUTH_MICROSOFT_AUTHORIZATION_URL=https://login.microsoftonline.com/common/oauth2/v2.0/authorize
# OAUTH_MICROSOFT_TOKEN_URL=https://login.microsoftonline.com/common/oauth2/v2.0/token
# OAUTH_MICROSOFT_USER_INFO_URL=https://graph.microsoft.com/v1.0/me
# OAUTH_MICROSOFT_REVOKE_URL=https://login.microsoftonline.com/common/oauth2/v2.0/logout
# OAUTH_MICROSOFT_TIMEOUT=30
# OAUTH_MICROSOFT_USE_PKCE=true
"""