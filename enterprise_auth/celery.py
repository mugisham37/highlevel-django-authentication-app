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
}

app.conf.timezone = settings.TIME_ZONE


@app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery configuration."""
    print(f'Request: {self.request!r}')