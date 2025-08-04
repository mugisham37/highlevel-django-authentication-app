"""
Django app configuration for enterprise_auth.core.

This module configures the core authentication application.
"""

from django.apps import AppConfig


class CoreConfig(AppConfig):
    """Configuration for the core authentication app."""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'enterprise_auth.core'
    label = 'core'
    verbose_name = 'Enterprise Authentication Core'