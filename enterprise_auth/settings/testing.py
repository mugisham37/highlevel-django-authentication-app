"""
Testing settings for enterprise_auth project.
"""

from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['testserver', 'localhost', '127.0.0.1']

# Database for testing (in-memory SQLite for speed)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
        'OPTIONS': {
            'timeout': 20,
        },
    }
}

# Cache configuration for testing (use dummy cache)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    },
    'sessions': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    }
}

# Session configuration for testing
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_SECURE = False

# Email backend for testing
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Celery configuration for testing (synchronous execution)
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

# Password hashers for testing (faster)
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Disable migrations for testing (faster)
class DisableMigrations:
    def __contains__(self, item):
        return True
    
    def __getitem__(self, item):
        return None

MIGRATION_MODULES = DisableMigrations()

# Logging configuration for testing (minimal)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'enterprise_auth': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}

# Security settings for testing (less strict)
SECURE_SSL_REDIRECT = False
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False

# Rate limiting for testing (disabled)
RATE_LIMIT_ENABLE = False

# CORS settings for testing
CORS_ALLOW_ALL_ORIGINS = True

# JWT settings for testing (shorter lifetimes for faster tests)
JWT_ACCESS_TOKEN_LIFETIME = 60  # 1 minute
JWT_REFRESH_TOKEN_LIFETIME = 300  # 5 minutes

# MFA settings for testing
MFA_BACKUP_CODES_COUNT = 5

# OAuth settings for testing (use test credentials)
OAUTH_PROVIDERS = {
    'google': {
        'client_id': 'test_google_client_id',
        'client_secret': 'test_google_client_secret',
        'scope': 'openid email profile',
    },
    'github': {
        'client_id': 'test_github_client_id',
        'client_secret': 'test_github_client_secret',
        'scope': 'user:email',
    },
    'microsoft': {
        'client_id': 'test_microsoft_client_id',
        'client_secret': 'test_microsoft_client_secret',
        'scope': 'openid email profile',
    },
}

# SMS configuration for testing (use test credentials)
TWILIO_ACCOUNT_SID = 'test_twilio_account_sid'
TWILIO_AUTH_TOKEN = 'test_twilio_auth_token'
TWILIO_PHONE_NUMBER = '+1234567890'

# Disable Sentry for testing
SENTRY_DSN = ''