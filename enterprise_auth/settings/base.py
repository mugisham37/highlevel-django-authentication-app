"""
Base settings for enterprise_auth project.
This file contains settings common to all environments.
"""

import os
import uuid
import logging
from pathlib import Path
from decouple import config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-change-me-in-production')

# Application definition
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'corsheaders',
    'django_extensions',
]

LOCAL_APPS = [
    'enterprise_auth.core.apps.CoreConfig',  # Core authentication app
    # Additional apps will be added as we create them
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'enterprise_auth.core.utils.correlation.CorrelationIDMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'enterprise_auth.core.utils.error_handling.ErrorHandlingMiddleware',
]

ROOT_URLCONF = 'enterprise_auth.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'enterprise_auth.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME', default='enterprise_auth'),
        'USER': config('DB_USER', default='postgres'),
        'PASSWORD': config('DB_PASSWORD', default='postgres'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
        'OPTIONS': {
            'connect_timeout': 10,
            'options': '-c default_transaction_isolation=read_committed',
            'sslmode': config('DB_SSL_MODE', default='prefer'),
            'application_name': 'enterprise_auth',
        },
        'CONN_MAX_AGE': config('DB_CONN_MAX_AGE', default=300, cast=int),  # 5 minutes
        'CONN_HEALTH_CHECKS': True,
        'ATOMIC_REQUESTS': True,
    }
}

# Database router for read/write splitting
DATABASE_ROUTERS = ['enterprise_auth.core.db.router.DatabaseRouter']

# Connection pooling settings
DB_POOL_SIZE = config('DB_POOL_SIZE', default=20, cast=int)
DB_MAX_OVERFLOW = config('DB_MAX_OVERFLOW', default=30, cast=int)
DB_POOL_TIMEOUT = config('DB_POOL_TIMEOUT', default=30, cast=int)
DB_POOL_RECYCLE = config('DB_POOL_RECYCLE', default=3600, cast=int)  # 1 hour

# Database optimization settings
SLOW_QUERY_THRESHOLD = config('SLOW_QUERY_THRESHOLD', default=1.0, cast=float)  # seconds
DB_QUERY_CACHE_TIMEOUT = config('DB_QUERY_CACHE_TIMEOUT', default=300, cast=int)  # 5 minutes
DB_HEALTH_CHECK_INTERVAL = config('DB_HEALTH_CHECK_INTERVAL', default=60, cast=int)  # 1 minute

# ORM optimization settings
DEFAULT_AUTO_FIELD = 'django.db.models.UUIDField'  # Use UUID as default primary key
USE_TZ = True  # Always use timezone-aware datetimes
ATOMIC_REQUESTS = True  # Wrap each request in a transaction by default

# Enhanced Redis cache configuration with high availability support
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_URL', default='redis://localhost:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'SERIALIZER': 'django_redis.serializers.json.JSONSerializer',
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 100,
                'retry_on_timeout': True,
                'health_check_interval': 30,
                'socket_timeout': 5,
                'socket_connect_timeout': 5,
            },
            'IGNORE_EXCEPTIONS': True,  # Fail gracefully on Redis errors
        },
        'KEY_PREFIX': 'enterprise_auth',
        'TIMEOUT': 300,
        'VERSION': 1,
    },
    'sessions': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_SESSION_URL', default='redis://localhost:6379/2'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'SERIALIZER': 'django_redis.serializers.json.JSONSerializer',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50,
                'retry_on_timeout': True,
                'health_check_interval': 30,
                'socket_timeout': 5,
                'socket_connect_timeout': 5,
            },
            'IGNORE_EXCEPTIONS': True,
        },
        'KEY_PREFIX': 'enterprise_auth_session',
        'TIMEOUT': 3600,
    },
    'rate_limit': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_RATE_LIMIT_URL', default='redis://localhost:6379/3'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 30,
                'retry_on_timeout': True,
                'health_check_interval': 30,
            },
            'IGNORE_EXCEPTIONS': True,
        },
        'KEY_PREFIX': 'enterprise_auth_rate_limit',
        'TIMEOUT': 3600,
    },
    'cache_warming': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_CACHE_WARMING_URL', default='redis://localhost:6379/4'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 20,
                'retry_on_timeout': True,
            },
            'IGNORE_EXCEPTIONS': True,
        },
        'KEY_PREFIX': 'enterprise_auth_warming',
        'TIMEOUT': 7200,  # 2 hours for warmed cache
    }
}

# Enhanced session configuration with Redis backend
SESSION_ENGINE = 'enterprise_auth.core.cache.session_storage'
SESSION_CACHE_ALIAS = 'sessions'
SESSION_COOKIE_AGE = config('SESSION_COOKIE_AGE', default=3600, cast=int)  # 1 hour
SESSION_COOKIE_SECURE = config('SESSION_COOKIE_SECURE', default=False, cast=bool)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = False

# Redis session configuration
SESSION_REDIS_PREFIX = 'enterprise_auth_session'
SESSION_REDIS_SERIALIZER = 'enterprise_auth.core.cache.session_storage.SecureSessionSerializer'

# Session security settings
SESSION_COOKIE_NAME = 'enterprise_auth_sessionid'
SESSION_COOKIE_DOMAIN = config('SESSION_COOKIE_DOMAIN', default=None)
SESSION_COOKIE_PATH = '/'

# Advanced session settings
SESSION_CONCURRENT_LIMIT = config('SESSION_CONCURRENT_LIMIT', default=5, cast=int)
SESSION_CLEANUP_INTERVAL = config('SESSION_CLEANUP_INTERVAL', default=3600, cast=int)  # 1 hour
SESSION_METADATA_ENABLED = True

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Password hashing with optimized Argon2 parameters
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]

# Argon2 optimal parameters for enterprise security
ARGON2_TIME_COST = config('ARGON2_TIME_COST', default=3, cast=int)  # Number of iterations
ARGON2_MEMORY_COST = config('ARGON2_MEMORY_COST', default=65536, cast=int)  # Memory usage in KB (64MB)
ARGON2_PARALLELISM = config('ARGON2_PARALLELISM', default=2, cast=int)  # Number of parallel threads
ARGON2_HASH_LEN = config('ARGON2_HASH_LEN', default=32, cast=int)  # Hash length in bytes
ARGON2_SALT_LEN = config('ARGON2_SALT_LEN', default=16, cast=int)  # Salt length in bytes

# Password policy configuration
PASSWORD_MIN_LENGTH = config('PASSWORD_MIN_LENGTH', default=12, cast=int)
PASSWORD_MAX_LENGTH = config('PASSWORD_MAX_LENGTH', default=128, cast=int)
PASSWORD_REQUIRE_UPPERCASE = config('PASSWORD_REQUIRE_UPPERCASE', default=True, cast=bool)
PASSWORD_REQUIRE_LOWERCASE = config('PASSWORD_REQUIRE_LOWERCASE', default=True, cast=bool)
PASSWORD_REQUIRE_DIGITS = config('PASSWORD_REQUIRE_DIGITS', default=True, cast=bool)
PASSWORD_REQUIRE_SPECIAL_CHARS = config('PASSWORD_REQUIRE_SPECIAL_CHARS', default=True, cast=bool)
PASSWORD_MIN_UPPERCASE = config('PASSWORD_MIN_UPPERCASE', default=1, cast=int)
PASSWORD_MIN_LOWERCASE = config('PASSWORD_MIN_LOWERCASE', default=1, cast=int)
PASSWORD_MIN_DIGITS = config('PASSWORD_MIN_DIGITS', default=1, cast=int)
PASSWORD_MIN_SPECIAL_CHARS = config('PASSWORD_MIN_SPECIAL_CHARS', default=1, cast=int)
PASSWORD_SPECIAL_CHARS = config('PASSWORD_SPECIAL_CHARS', default='!@#$%^&*()_+-=[]{}|;:,.<>?')
PASSWORD_MAX_CONSECUTIVE_CHARS = config('PASSWORD_MAX_CONSECUTIVE_CHARS', default=3, cast=int)
PASSWORD_MAX_REPEATED_CHARS = config('PASSWORD_MAX_REPEATED_CHARS', default=3, cast=int)
PASSWORD_CHECK_COMMON_PASSWORDS = config('PASSWORD_CHECK_COMMON_PASSWORDS', default=True, cast=bool)
PASSWORD_CHECK_USER_ATTRIBUTES = config('PASSWORD_CHECK_USER_ATTRIBUTES', default=True, cast=bool)
PASSWORD_MIN_UNIQUE_CHARS = config('PASSWORD_MIN_UNIQUE_CHARS', default=8, cast=int)
PASSWORD_ENTROPY_THRESHOLD = config('PASSWORD_ENTROPY_THRESHOLD', default=50, cast=int)

# Password management settings
PASSWORD_MAX_FAILED_ATTEMPTS = config('PASSWORD_MAX_FAILED_ATTEMPTS', default=5, cast=int)
PASSWORD_LOCKOUT_DURATION_MINUTES = config('PASSWORD_LOCKOUT_DURATION_MINUTES', default=30, cast=int)
PASSWORD_RESET_TOKEN_LENGTH = config('PASSWORD_RESET_TOKEN_LENGTH', default=32, cast=int)
PASSWORD_RESET_TOKEN_EXPIRY_HOURS = config('PASSWORD_RESET_TOKEN_EXPIRY_HOURS', default=1, cast=int)
PASSWORD_HISTORY_COUNT = config('PASSWORD_HISTORY_COUNT', default=5, cast=int)
PASSWORD_MIN_AGE_HOURS = config('PASSWORD_MIN_AGE_HOURS', default=1, cast=int)

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = config('TIME_ZONE', default='UTC')
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Django REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'enterprise_auth.core.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    }
}

# CORS settings
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='http://localhost:3000,http://127.0.0.1:3000',
    cast=lambda v: [s.strip() for s in v.split(',')]
)

CORS_ALLOW_CREDENTIALS = True

# Security settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Celery Configuration
CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://localhost:6379/3')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default='redis://localhost:6379/4')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# Celery Beat Schedule for periodic tasks
CELERY_BEAT_SCHEDULE = {
    # Cache warming tasks
    'warm-user-cache': {
        'task': 'enterprise_auth.core.tasks.cache_tasks.warm_user_cache',
        'schedule': 1800.0,  # Every 30 minutes
        'options': {'queue': 'cache_warming'}
    },
    'warm-oauth-providers-cache': {
        'task': 'enterprise_auth.core.tasks.cache_tasks.warm_oauth_providers_cache',
        'schedule': 3600.0,  # Every hour
        'options': {'queue': 'cache_warming'}
    },
    'warm-role-permissions-cache': {
        'task': 'enterprise_auth.core.tasks.cache_tasks.warm_role_permissions_cache',
        'schedule': 3600.0,  # Every hour
        'options': {'queue': 'cache_warming'}
    },
    
    # Cache cleanup tasks
    'cleanup-expired-sessions': {
        'task': 'enterprise_auth.core.tasks.cache_tasks.cleanup_expired_sessions',
        'schedule': 3600.0,  # Every hour
        'options': {'queue': 'maintenance'}
    },
    'cleanup-rate-limit-counters': {
        'task': 'enterprise_auth.core.tasks.cache_tasks.cleanup_rate_limit_counters',
        'schedule': 7200.0,  # Every 2 hours
        'options': {'queue': 'maintenance'}
    },
    
    # Comprehensive cache warming (less frequent)
    'comprehensive-cache-warming': {
        'task': 'enterprise_auth.core.tasks.cache_tasks.comprehensive_cache_warming',
        'schedule': 21600.0,  # Every 6 hours
        'options': {'queue': 'cache_warming'}
    },
    
    # SMS-related tasks
    'cleanup-expired-sms-codes': {
        'task': 'enterprise_auth.core.tasks.sms_tasks.cleanup_expired_sms_codes',
        'schedule': 3600.0,  # Every hour
        'options': {'queue': 'maintenance'}
    },
    'bulk-sms-status-check': {
        'task': 'enterprise_auth.core.tasks.sms_tasks.bulk_sms_delivery_status_check',
        'schedule': 1800.0,  # Every 30 minutes
        'options': {'queue': 'sms_processing'}
    },
}

# Celery task routing
CELERY_TASK_ROUTES = {
    'enterprise_auth.core.tasks.cache_tasks.*': {'queue': 'cache_warming'},
    'enterprise_auth.core.tasks.cache_tasks.cleanup_*': {'queue': 'maintenance'},
    'enterprise_auth.core.tasks.sms_tasks.*': {'queue': 'sms_processing'},
}

# Celery worker configuration
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000

# Email configuration
EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = config('EMAIL_HOST', default='localhost')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@enterprise-auth.com')

# Custom settings for the authentication system
AUTH_USER_MODEL = 'core.UserProfile'

# JWT Configuration (will be implemented later)
JWT_SECRET_KEY = config('JWT_SECRET_KEY', default=SECRET_KEY)
JWT_ACCESS_TOKEN_LIFETIME = config('JWT_ACCESS_TOKEN_LIFETIME', default=900, cast=int)  # 15 minutes
JWT_REFRESH_TOKEN_LIFETIME = config('JWT_REFRESH_TOKEN_LIFETIME', default=2592000, cast=int)  # 30 days

# Rate limiting configuration
RATE_LIMIT_ENABLE = config('RATE_LIMIT_ENABLE', default=True, cast=bool)
RATE_LIMIT_PER_IP = config('RATE_LIMIT_PER_IP', default='100/hour')
RATE_LIMIT_PER_USER = config('RATE_LIMIT_PER_USER', default='1000/hour')

# MFA Configuration
MFA_TOTP_ISSUER = config('MFA_TOTP_ISSUER', default='Enterprise Auth')
MFA_TOTP_WINDOW = config('MFA_TOTP_WINDOW', default=1, cast=int)  # 30-second windows
MFA_BACKUP_CODES_COUNT = config('MFA_BACKUP_CODES_COUNT', default=10, cast=int)
MFA_RATE_LIMIT_WINDOW = config('MFA_RATE_LIMIT_WINDOW', default=300, cast=int)  # 5 minutes
MFA_MAX_ATTEMPTS_PER_WINDOW = config('MFA_MAX_ATTEMPTS_PER_WINDOW', default=5, cast=int)

# SMS MFA Configuration
MFA_SMS_CODE_LENGTH = config('MFA_SMS_CODE_LENGTH', default=6, cast=int)
MFA_SMS_CODE_EXPIRY_MINUTES = config('MFA_SMS_CODE_EXPIRY_MINUTES', default=5, cast=int)
MFA_SMS_RATE_LIMIT_WINDOW = config('MFA_SMS_RATE_LIMIT_WINDOW', default=3600, cast=int)  # 1 hour
MFA_MAX_SMS_PER_WINDOW = config('MFA_MAX_SMS_PER_WINDOW', default=5, cast=int)
MFA_SMS_RETRY_ATTEMPTS = config('MFA_SMS_RETRY_ATTEMPTS', default=3, cast=int)
MFA_SMS_RETRY_DELAY_SECONDS = config('MFA_SMS_RETRY_DELAY_SECONDS', default=30, cast=int)

# Email MFA Configuration
MFA_EMAIL_CODE_LENGTH = config('MFA_EMAIL_CODE_LENGTH', default=6, cast=int)
MFA_EMAIL_CODE_EXPIRY_MINUTES = config('MFA_EMAIL_CODE_EXPIRY_MINUTES', default=10, cast=int)
MFA_EMAIL_RATE_LIMIT_WINDOW = config('MFA_EMAIL_RATE_LIMIT_WINDOW', default=3600, cast=int)  # 1 hour
MFA_MAX_EMAILS_PER_WINDOW = config('MFA_MAX_EMAILS_PER_WINDOW', default=10, cast=int)
MFA_EMAIL_RETRY_ATTEMPTS = config('MFA_EMAIL_RETRY_ATTEMPTS', default=3, cast=int)
MFA_EMAIL_RETRY_DELAY_SECONDS = config('MFA_EMAIL_RETRY_DELAY_SECONDS', default=30, cast=int)
MFA_EMAIL_TEMPLATE_NAME = config('MFA_EMAIL_TEMPLATE_NAME', default='emails/mfa_verification_email.html')
MFA_EMAIL_SUBJECT_TEMPLATE = config('MFA_EMAIL_SUBJECT_TEMPLATE', default='Your verification code: {code}')
MFA_EMAIL_USE_HTML = config('MFA_EMAIL_USE_HTML', default=True, cast=bool)
MFA_EMAIL_ENABLE_SMS_FALLBACK = config('MFA_EMAIL_ENABLE_SMS_FALLBACK', default=True, cast=bool)
MFA_EMAIL_FALLBACK_THRESHOLD = config('MFA_EMAIL_FALLBACK_THRESHOLD', default=3, cast=int)

# OAuth Configuration
OAUTH_PROVIDERS = {
    'google': {
        'client_id': config('GOOGLE_OAUTH_CLIENT_ID', default=''),
        'client_secret': config('GOOGLE_OAUTH_CLIENT_SECRET', default=''),
        'scope': 'openid email profile',
    },
    'github': {
        'client_id': config('GITHUB_OAUTH_CLIENT_ID', default=''),
        'client_secret': config('GITHUB_OAUTH_CLIENT_SECRET', default=''),
        'scope': 'user:email',
    },
    'microsoft': {
        'client_id': config('MICROSOFT_OAUTH_CLIENT_ID', default=''),
        'client_secret': config('MICROSOFT_OAUTH_CLIENT_SECRET', default=''),
        'scope': 'openid email profile',
    },
}

# SMS Configuration (Twilio)
TWILIO_ACCOUNT_SID = config('TWILIO_ACCOUNT_SID', default='')
TWILIO_AUTH_TOKEN = config('TWILIO_AUTH_TOKEN', default='')
TWILIO_PHONE_NUMBER = config('TWILIO_PHONE_NUMBER', default='')

# Logging configuration with correlation ID support
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {name} {process:d} {thread:d} [{correlation_id}] {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {name} [{correlation_id}] {message}',
            'style': '{',
        },
        'json': {
            'format': '{"level": "{levelname}", "time": "{asctime}", "name": "{name}", "correlation_id": "{correlation_id}", "message": "{message}"}',
            'style': '{',
        },
    },
    'filters': {
        'correlation_id': {
            '()': 'enterprise_auth.core.utils.correlation.CorrelationIDFilter',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'filters': ['correlation_id'],
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'application.log',
            'maxBytes': 1024*1024*10,  # 10MB
            'backupCount': 5,
            'formatter': 'json',
            'filters': ['correlation_id'],
        },
        'security': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'security.log',
            'maxBytes': 1024*1024*10,  # 10MB
            'backupCount': 10,
            'formatter': 'json',
            'filters': ['correlation_id'],
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'enterprise_auth': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'enterprise_auth.security': {
            'handlers': ['console', 'security'],
            'level': 'WARNING',
            'propagate': False,
        },
        'enterprise_auth.core.utils.error_handling': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
}

# Monitoring and observability
SENTRY_DSN = config('SENTRY_DSN', default='')
if SENTRY_DSN:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.celery import CeleryIntegration
    from sentry_sdk.integrations.logging import LoggingIntegration
    
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(auto_enabling=True),
            CeleryIntegration(monitor_beat_tasks=True),
            LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
        ],
        traces_sample_rate=0.1,
        send_default_pii=True,
        before_send=lambda event, hint: {
            **event,
            'extra': {
                **event.get('extra', {}),
                'correlation_id': get_correlation_id(),
            }
        } if 'get_correlation_id' in globals() else event,
    )