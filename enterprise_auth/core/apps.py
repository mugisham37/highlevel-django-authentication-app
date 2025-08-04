"""
Django app configuration for enterprise_auth.core.

This module configures the core authentication application.
"""

import logging
from django.apps import AppConfig

logger = logging.getLogger(__name__)


class CoreConfig(AppConfig):
    """Configuration for the core authentication app."""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'enterprise_auth.core'
    label = 'core'
    verbose_name = 'Enterprise Authentication Core'
    
    def ready(self):
        """
        Initialize the application when Django starts.
        
        This method is called when the app is ready and all models are loaded.
        It initializes the OAuth system and registers all OAuth providers.
        """
        try:
            # Import and initialize OAuth system
            from .services.oauth_providers_registry import initialize_oauth_system
            
            # Initialize OAuth providers
            initialize_oauth_system()
            
            logger.info("Enterprise authentication core app initialized successfully")
            
        except Exception as e:
            logger.error(
                f"Failed to initialize enterprise authentication core app: {e}",
                extra={'error': str(e)}
            )
            # Don't raise the exception to prevent Django from failing to start
            # The OAuth system will just be unavailable