"""
Django management command for Redis cache management operations.
Provides cache warming, invalidation, and maintenance functionality.
"""

import logging
import time
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from enterprise_auth.core.cache.cache_manager import cache_manager
from enterprise_auth.core.cache.session_storage import session_manager
from enterprise_auth.core.cache.rate_limiter import rate_limiter
from enterprise_auth.core.cache.redis_config import redis_manager

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Manage Redis cache operations including warming, invalidation, and maintenance'

    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            choices=[
                'warm', 'invalidate', 'cleanup', 'stats', 'health', 
                'reset_rate_limits', 'session_cleanup'
            ],
            help='Action to perform'
        )
        
        parser.add_argument(
            '--scope',
            type=str,
            help='Scope for the action (user, session, role, etc.)'
        )
        
        parser.add_argument(
            '--key',
            type=str,
            help='Specific key or identifier for the action'
        )
        
        parser.add_argument(
            '--pattern',
            type=str,
            help='Pattern for bulk operations'
        )
        
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force the operation without confirmation'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without actually doing it'
        )

    def handle(self, *args, **options):
        action = options['action']
        
        try:
            if action == 'warm':
                self.handle_cache_warming(options)
            elif action == 'invalidate':
                self.handle_cache_invalidation(options)
            elif action == 'cleanup':
                self.handle_cache_cleanup(options)
            elif action == 'stats':
                self.handle_cache_stats(options)
            elif action == 'health':
                self.handle_health_check(options)
            elif action == 'reset_rate_limits':
                self.handle_reset_rate_limits(options)
            elif action == 'session_cleanup':
                self.handle_session_cleanup(options)
            else:
                raise CommandError(f"Unknown action: {action}")
                
        except Exception as e:
            logger.error(f"Cache management command failed: {e}")
            raise CommandError(f"Command failed: {e}")

    def handle_cache_warming(self, options):
        """Handle cache warming operations."""
        self.stdout.write("Starting cache warming...")
        
        start_time = time.time()
        
        try:
            # Run all registered warming tasks
            cache_manager.warmer.run_warming_tasks()
            
            # Warm specific data if requested
            if options.get('scope') == 'user' and options.get('key'):
                user_ids = [options['key']]
                cache_manager.warmer.warm_user_data(user_ids)
                self.stdout.write(f"Warmed cache for user: {options['key']}")
            
            elif options.get('scope') == 'oauth':
                cache_manager.warmer.warm_oauth_providers()
                self.stdout.write("Warmed OAuth provider cache")
            
            elif options.get('scope') == 'roles':
                cache_manager.warmer.warm_role_permissions()
                self.stdout.write("Warmed role permissions cache")
            
            else:
                # Run all warming tasks
                cache_manager.warmer.warm_user_data()
                cache_manager.warmer.warm_oauth_providers()
                cache_manager.warmer.warm_role_permissions()
                self.stdout.write("Completed full cache warming")
            
            elapsed_time = time.time() - start_time
            self.stdout.write(
                self.style.SUCCESS(f"Cache warming completed in {elapsed_time:.2f} seconds")
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Cache warming failed: {e}")
            )
            raise

    def handle_cache_invalidation(self, options):
        """Handle cache invalidation operations."""
        scope = options.get('scope')
        key = options.get('key')
        pattern = options.get('pattern')
        
        if not any([scope, pattern]):
            raise CommandError("Either --scope or --pattern must be specified for invalidation")
        
        if not options.get('force') and not options.get('dry_run'):
            confirm = input("Are you sure you want to invalidate cache entries? [y/N]: ")
            if confirm.lower() != 'y':
                self.stdout.write("Cache invalidation cancelled")
                return
        
        try:
            if options.get('dry_run'):
                self.stdout.write("DRY RUN - No actual invalidation will be performed")
            
            if scope == 'user' and key:
                if not options.get('dry_run'):
                    cache_manager.invalidator.invalidate_user_cache(key)
                self.stdout.write(f"{'Would invalidate' if options.get('dry_run') else 'Invalidated'} user cache: {key}")
            
            elif scope == 'session' and key:
                if not options.get('dry_run'):
                    cache_manager.invalidator.invalidate_session_cache(key)
                self.stdout.write(f"{'Would invalidate' if options.get('dry_run') else 'Invalidated'} session cache: {key}")
            
            elif scope == 'role':
                if not options.get('dry_run'):
                    cache_manager.invalidator.invalidate_role_cache(key)
                self.stdout.write(f"{'Would invalidate' if options.get('dry_run') else 'Invalidated'} role cache")
            
            elif pattern:
                if not options.get('dry_run'):
                    cache_manager.invalidator.invalidate_by_pattern(pattern)
                self.stdout.write(f"{'Would invalidate' if options.get('dry_run') else 'Invalidated'} cache pattern: {pattern}")
            
            else:
                raise CommandError("Invalid scope or missing key for invalidation")
            
            if not options.get('dry_run'):
                self.stdout.write(self.style.SUCCESS("Cache invalidation completed"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Cache invalidation failed: {e}"))
            raise

    def handle_cache_cleanup(self, options):
        """Handle cache cleanup operations."""
        self.stdout.write("Starting cache cleanup...")
        
        try:
            # Clean up expired sessions
            expired_sessions = session_manager.cleanup_expired_sessions()
            self.stdout.write(f"Cleaned up {expired_sessions} expired sessions")
            
            # Additional cleanup operations can be added here
            
            self.stdout.write(self.style.SUCCESS("Cache cleanup completed"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Cache cleanup failed: {e}"))
            raise

    def handle_cache_stats(self, options):
        """Display cache statistics."""
        try:
            # Get general cache stats
            cache_stats = cache_manager.get_cache_stats()
            
            self.stdout.write(self.style.SUCCESS("=== Cache Statistics ==="))
            for key, value in cache_stats.items():
                self.stdout.write(f"{key}: {value}")
            
            # Get session stats
            session_stats = session_manager.get_session_stats()
            
            self.stdout.write(self.style.SUCCESS("\n=== Session Statistics ==="))
            for key, value in session_stats.items():
                self.stdout.write(f"{key}: {value}")
            
            # Get rate limiting stats if key is provided
            if options.get('scope') and options.get('key'):
                rate_stats = rate_limiter.get_rate_limit_stats(
                    options['scope'], options['key']
                )
                
                self.stdout.write(self.style.SUCCESS(f"\n=== Rate Limit Stats ({options['scope']}:{options['key']}) ==="))
                for key, value in rate_stats.items():
                    self.stdout.write(f"{key}: {value}")
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to get cache stats: {e}"))
            raise

    def handle_health_check(self, options):
        """Perform Redis health check."""
        try:
            from enterprise_auth.core.cache.redis_config import redis_health_check
            
            health_result = redis_health_check()
            
            self.stdout.write(self.style.SUCCESS("=== Redis Health Check ==="))
            
            if health_result['status'] == 'healthy':
                self.stdout.write(self.style.SUCCESS(f"Status: {health_result['status']}"))
                self.stdout.write(f"Response Time: {health_result['response_time_ms']}ms")
                self.stdout.write(f"Redis Version: {health_result.get('redis_version', 'Unknown')}")
                self.stdout.write(f"Connected Clients: {health_result.get('connected_clients', 'Unknown')}")
                self.stdout.write(f"Used Memory: {health_result.get('used_memory_human', 'Unknown')}")
                
                # Connection health
                connections = health_result.get('connections', {})
                self.stdout.write("\n=== Connection Health ===")
                for conn_name, is_healthy in connections.items():
                    status_style = self.style.SUCCESS if is_healthy else self.style.ERROR
                    status_text = "Healthy" if is_healthy else "Unhealthy"
                    self.stdout.write(status_style(f"{conn_name}: {status_text}"))
            else:
                self.stdout.write(self.style.ERROR(f"Status: {health_result['status']}"))
                self.stdout.write(self.style.ERROR(f"Error: {health_result.get('error', 'Unknown error')}"))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Health check failed: {e}"))
            raise

    def handle_reset_rate_limits(self, options):
        """Reset rate limiting counters."""
        scope = options.get('scope')
        key = options.get('key')
        
        if not scope or not key:
            raise CommandError("Both --scope and --key must be specified for rate limit reset")
        
        if not options.get('force'):
            confirm = input(f"Are you sure you want to reset rate limits for {scope}:{key}? [y/N]: ")
            if confirm.lower() != 'y':
                self.stdout.write("Rate limit reset cancelled")
                return
        
        try:
            rate_limiter.reset_rate_limit(scope, key)
            self.stdout.write(
                self.style.SUCCESS(f"Reset rate limits for {scope}:{key}")
            )
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Rate limit reset failed: {e}"))
            raise

    def handle_session_cleanup(self, options):
        """Clean up user sessions."""
        key = options.get('key')  # user_id
        
        if not key:
            raise CommandError("--key (user_id) must be specified for session cleanup")
        
        if not options.get('force'):
            confirm = input(f"Are you sure you want to terminate all sessions for user {key}? [y/N]: ")
            if confirm.lower() != 'y':
                self.stdout.write("Session cleanup cancelled")
                return
        
        try:
            terminated_count = session_manager.terminate_user_sessions(key)
            self.stdout.write(
                self.style.SUCCESS(f"Terminated {terminated_count} sessions for user {key}")
            )
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Session cleanup failed: {e}"))
            raise