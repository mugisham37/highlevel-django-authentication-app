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


def register_all_oauth_providers() -> None:
    """
    Register all available OAuth providers.
    
    This function should be called during Django app initialization
    to register all OAuth providers with the system.
    """
    logger.info("Registering OAuth providers...")
    
    # Register Google OAuth provider
    register_google_oauth_provider()
    
    # TODO: Register other providers as they are implemented
    # register_github_oauth_provider()
    # register_microsoft_oauth_provider()
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


# Example Django settings for Google OAuth
EXAMPLE_SETTINGS = """
# Add to your Django settings.py

# Google OAuth Configuration
GOOGLE_OAUTH_CLIENT_ID = 'your-google-client-id.apps.googleusercontent.com'
GOOGLE_OAUTH_CLIENT_SECRET = 'your-google-client-secret'
GOOGLE_OAUTH_REDIRECT_URI = 'https://yourdomain.com/auth/google/callback'
GOOGLE_OAUTH_SCOPES = ['openid', 'email', 'profile']

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
"""