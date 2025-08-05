from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'enterprise_auth.api'
    verbose_name = 'API Integration'

    def ready(self):
        """Initialize API components when Django starts."""
        # Import signal handlers
        from . import signals  # noqa