"""
Celery configuration for enterprise_auth project.
"""

import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'enterprise_auth.settings.development')

app = Celery('enterprise_auth')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Celery beat schedule for periodic tasks
app.conf.beat_schedule = {
    'cleanup-expired-tokens': {
        'task': 'enterprise_auth.auth.tasks.cleanup_expired_tokens',
        'schedule': 300.0,  # Run every 5 minutes
    },
    'cleanup-expired-sessions': {
        'task': 'enterprise_auth.sessions.tasks.cleanup_expired_sessions',
        'schedule': 3600.0,  # Run every hour
    },
    'security-analysis': {
        'task': 'enterprise_auth.security.tasks.analyze_security_events',
        'schedule': 900.0,  # Run every 15 minutes
    },
    # JWT token management tasks
    'cleanup-expired-blacklisted-tokens': {
        'task': 'enterprise_auth.core.tasks.jwt_tasks.cleanup_expired_blacklisted_tokens',
        'schedule': 300.0,  # Run every 5 minutes
    },
    'cleanup-old-refresh-tokens': {
        'task': 'enterprise_auth.core.tasks.jwt_tasks.cleanup_old_refresh_tokens',
        'schedule': 86400.0,  # Run daily
        'kwargs': {'days_old': 60},
    },
    'monitor-token-usage-patterns': {
        'task': 'enterprise_auth.core.tasks.jwt_tasks.monitor_token_usage_patterns',
        'schedule': 3600.0,  # Run every hour
    },
    'generate-token-blacklist-report': {
        'task': 'enterprise_auth.core.tasks.jwt_tasks.generate_token_blacklist_report',
        'schedule': 604800.0,  # Run weekly
        'kwargs': {'days_back': 7},
    },
}

app.conf.timezone = settings.TIME_ZONE


@app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery configuration."""
    print(f'Request: {self.request!r}')