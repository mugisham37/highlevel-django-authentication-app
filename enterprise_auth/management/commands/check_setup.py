"""
Management command to check the Django setup and configuration.
"""

from django.core.management.base import BaseCommand
from django.conf import settings
from django.db import connection
from django.core.cache import cache
import structlog


class Command(BaseCommand):
    help = 'Check Django setup and configuration'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Checking Django setup...'))
        
        # Check basic configuration
        self.stdout.write(f'Django version: {self.get_django_version()}')
        self.stdout.write(f'Settings module: {settings.SETTINGS_MODULE}')
        self.stdout.write(f'Debug mode: {settings.DEBUG}')
        self.stdout.write(f'Secret key configured: {"Yes" if settings.SECRET_KEY else "No"}')
        
        # Check database
        self.check_database()
        
        # Check cache
        self.check_cache()
        
        # Check logging
        self.check_logging()
        
        # Check middleware
        self.check_middleware()
        
        # Check CORS
        self.check_cors()
        
        self.stdout.write(self.style.SUCCESS('Setup check completed!'))
    
    def get_django_version(self):
        import django
        return django.get_version()
    
    def check_database(self):
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            self.stdout.write(self.style.SUCCESS('✓ Database connection: OK'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Database connection: {e}'))
    
    def check_cache(self):
        try:
            cache.set('setup_check', 'test', 1)
            value = cache.get('setup_check')
            if value == 'test':
                self.stdout.write(self.style.SUCCESS('✓ Cache connection: OK'))
            else:
                self.stdout.write(self.style.ERROR('✗ Cache connection: Value mismatch'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Cache connection: {e}'))
    
    def check_logging(self):
        try:
            logger = structlog.get_logger('setup_check')
            logger.info("Setup check log message")
            self.stdout.write(self.style.SUCCESS('✓ Structured logging: OK'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Structured logging: {e}'))
    
    def check_middleware(self):
        try:
            from enterprise_auth.core.middleware import (
                CorrelationIdMiddleware, 
                SecurityHeadersMiddleware,
                RateLimitMiddleware
            )
            self.stdout.write(self.style.SUCCESS('✓ Custom middleware: OK'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'✗ Custom middleware: {e}'))
    
    def check_cors(self):
        if 'corsheaders' in settings.INSTALLED_APPS:
            self.stdout.write(self.style.SUCCESS('✓ CORS headers: Configured'))
        else:
            self.stdout.write(self.style.WARNING('⚠ CORS headers: Not configured'))