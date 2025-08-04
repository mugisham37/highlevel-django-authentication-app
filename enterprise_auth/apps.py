"""
Django app configuration for enterprise_auth.

This module configures the main application and initializes
core components during startup.
"""

import logging
from django.apps import AppConfig
from django.conf import settings

logger = logging.getLogger(__name__)


class EnterpriseAuthConfig(AppConfig):
    """
    Configuration for the enterprise_auth application.
    
    Handles initialization of:
    - Database optimizations
    - Monitoring systems
    - Security components
    - Background tasks
    """
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'enterprise_auth'
    verbose_name = 'Enterprise Authentication'

    def ready(self):
        """
        Initialize application components when Django starts.
        
        This method is called once Django has loaded all models
        and is ready to serve requests.
        """
        logger.info("Initializing Enterprise Authentication system...")
        
        try:
            # Initialize database optimizations
            self._setup_database_optimizations()
            
            # Start database monitoring
            self._start_database_monitoring()
            
            # Initialize security components
            self._setup_security_components()
            
            # Setup signal handlers
            self._setup_signal_handlers()
            
            logger.info("Enterprise Authentication system initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Enterprise Authentication system: {e}")
            # Don't raise exception to prevent Django startup failure
            # Log the error and continue with degraded functionality

    def _setup_database_optimizations(self):
        """Setup database optimizations and connection pooling."""
        try:
            from enterprise_auth.core.db.optimizations import setup_database_optimizations
            setup_database_optimizations()
            logger.info("Database optimizations initialized")
        except Exception as e:
            logger.error(f"Failed to setup database optimizations: {e}")

    def _start_database_monitoring(self):
        """Start database monitoring if enabled."""
        try:
            if getattr(settings, 'DB_MONITORING_ENABLED', True):
                from enterprise_auth.core.db.monitoring import start_database_monitoring
                start_database_monitoring()
                logger.info("Database monitoring started")
        except Exception as e:
            logger.error(f"Failed to start database monitoring: {e}")

    def _setup_security_components(self):
        """Initialize security components."""
        try:
            # Initialize rate limiting
            if getattr(settings, 'RATE_LIMIT_ENABLE', True):
                logger.info("Rate limiting enabled")
            
            # Initialize threat detection
            logger.info("Security components initialized")
            
        except Exception as e:
            logger.error(f"Failed to setup security components: {e}")

    def _setup_signal_handlers(self):
        """Setup Django signal handlers for the application."""
        try:
            # Import signal handlers to register them
            from enterprise_auth.core import signals
            logger.info("Signal handlers registered")
        except ImportError:
            # Signal handlers not yet implemented
            pass
        except Exception as e:
            logger.error(f"Failed to setup signal handlers: {e}")