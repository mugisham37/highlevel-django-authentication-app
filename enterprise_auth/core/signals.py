"""
Django signal handlers for the enterprise authentication system.

This module contains signal handlers for:
- Database connection events
- User authentication events
- Security events
- Performance monitoring
"""

import logging
from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.conf import settings

logger = logging.getLogger(__name__)


@receiver(post_migrate)
def post_migration_handler(sender, **kwargs):
    """
    Handle post-migration tasks.
    
    This signal handler runs after migrations are applied
    to perform any necessary post-migration setup.
    """
    app_config = kwargs.get('app_config')
    verbosity = kwargs.get('verbosity', 1)
    
    if app_config and app_config.name == 'enterprise_auth':
        if verbosity >= 1:
            logger.info("Running post-migration setup for enterprise_auth")
        
        try:
            # Perform any post-migration database setup
            _setup_database_indexes()
            _validate_database_configuration()
            
            if verbosity >= 1:
                logger.info("Post-migration setup completed successfully")
                
        except Exception as e:
            logger.error(f"Post-migration setup failed: {e}")


def _setup_database_indexes():
    """
    Setup any additional database indexes that aren't handled by migrations.
    """
    # This would contain any custom index creation logic
    # that needs to be done after migrations
    pass


def _validate_database_configuration():
    """
    Validate that the database configuration is correct after migrations.
    """
    from enterprise_auth.core.db.optimizations import query_optimizer
    
    try:
        # Perform database health check
        health_status = query_optimizer.health_check()
        
        # Log any issues found
        for db_name, status in health_status.items():
            if status['status'] != 'healthy':
                logger.warning(f"Database {db_name} health check failed: {status.get('error')}")
            else:
                logger.info(f"Database {db_name} is healthy")
                
    except Exception as e:
        logger.error(f"Database validation failed: {e}")