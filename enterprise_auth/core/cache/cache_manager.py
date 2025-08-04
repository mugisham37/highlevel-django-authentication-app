"""
Advanced cache management with warming and invalidation strategies.
Provides intelligent caching patterns for the enterprise authentication system.
"""

import logging
import json
import time
import hashlib
from typing import Any, Dict, List, Optional, Callable, Union
from datetime import datetime, timedelta
from django.core.cache import cache
from django.core.cache import cache
from django.conf import settings
from .redis_config import get_redis_connection
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading

logger = logging.getLogger(__name__)


class CacheKeyManager:
    """
    Manages cache key generation and organization with consistent naming patterns.
    """
    
    # Cache key prefixes for different data types
    PREFIXES = {
        'user': 'user',
        'session': 'session',
        'token': 'token',
        'oauth': 'oauth',
        'mfa': 'mfa',
        'role': 'role',
        'permission': 'permission',
        'rate_limit': 'rate_limit',
        'security': 'security',
        'audit': 'audit'
    }
    
    @classmethod
    def generate_key(cls, prefix: str, identifier: str, suffix: str = None) -> str:
        """
        Generate consistent cache key with optional suffix.
        
        Args:
            prefix: Cache key prefix from PREFIXES
            identifier: Unique identifier (user_id, session_id, etc.)
            suffix: Optional suffix for key variation
            
        Returns:
            Formatted cache key
        """
        if prefix not in cls.PREFIXES:
            raise ValueError(f"Invalid prefix: {prefix}. Must be one of {list(cls.PREFIXES.keys())}")
        
        key_parts = [cls.PREFIXES[prefix], str(identifier)]
        if suffix:
            key_parts.append(str(suffix))
        
        return ':'.join(key_parts)
    
    @classmethod
    def generate_pattern_key(cls, prefix: str, pattern: str = '*') -> str:
        """
        Generate cache key pattern for bulk operations.
        
        Args:
            prefix: Cache key prefix
            pattern: Pattern for matching keys (default: '*')
            
        Returns:
            Cache key pattern
        """
        return f"{cls.PREFIXES[prefix]}:{pattern}"
    
    @classmethod
    def hash_key(cls, data: Union[str, dict, list]) -> str:
        """
        Generate hash-based cache key for complex data structures.
        
        Args:
            data: Data to hash
            
        Returns:
            SHA256 hash of the data
        """
        if isinstance(data, (dict, list)):
            data = json.dumps(data, sort_keys=True)
        
        return hashlib.sha256(str(data).encode()).hexdigest()[:16]


class CacheWarmer:
    """
    Implements cache warming strategies to preload frequently accessed data.
    """
    
    def __init__(self):
        self.redis_conn = get_redis_connection('cache')
        self.warming_tasks = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
    
    def register_warming_task(self, name: str, task_func: Callable, 
                            schedule_minutes: int = 60, priority: int = 1):
        """
        Register a cache warming task.
        
        Args:
            name: Task name
            task_func: Function to execute for warming
            schedule_minutes: How often to run the task
            priority: Task priority (1=high, 2=medium, 3=low)
        """
        self.warming_tasks[name] = {
            'function': task_func,
            'schedule_minutes': schedule_minutes,
            'priority': priority,
            'last_run': None,
            'next_run': datetime.now()
        }
        logger.info(f"Registered cache warming task: {name}")
    
    def warm_user_data(self, user_ids: List[str] = None):
        """
        Warm cache with frequently accessed user data.
        
        Args:
            user_ids: Specific user IDs to warm, or None for all active users
        """
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            
            if user_ids:
                users = User.objects.filter(id__in=user_ids)
            else:
                # Get recently active users (last 7 days)
                cutoff_date = datetime.now() - timedelta(days=7)
                users = User.objects.filter(last_login__gte=cutoff_date)[:1000]
            
            warmed_count = 0
            for user in users:
                try:
                    # Cache user profile data
                    cache_key = CacheKeyManager.generate_key('user', user.id, 'profile')
                    user_data = {
                        'id': str(user.id),
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'is_active': user.is_active,
                        'last_login': user.last_login.isoformat() if user.last_login else None
                    }
                    cache.set(cache_key, user_data, timeout=3600)  # 1 hour
                    
                    # Cache user permissions
                    permissions_key = CacheKeyManager.generate_key('user', user.id, 'permissions')
                    permissions = list(user.get_all_permissions())
                    cache.set(permissions_key, permissions, timeout=1800)  # 30 minutes
                    
                    warmed_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to warm cache for user {user.id}: {e}")
            
            logger.info(f"Warmed cache for {warmed_count} users")
            
        except Exception as e:
            logger.error(f"Cache warming failed for user data: {e}")
    
    def warm_role_permissions(self):
        """Warm cache with role and permission data."""
        try:
            # This will be implemented when RBAC models are created
            # For now, we'll prepare the structure
            
            cache_key = CacheKeyManager.generate_key('role', 'all', 'permissions')
            # Placeholder for role-permission mapping
            role_permissions = {}
            cache.set(cache_key, role_permissions, timeout=7200)  # 2 hours
            
            logger.info("Warmed cache for role permissions")
            
        except Exception as e:
            logger.error(f"Cache warming failed for role permissions: {e}")
    
    def warm_oauth_providers(self):
        """Warm cache with OAuth provider configurations."""
        try:
            providers_key = CacheKeyManager.generate_key('oauth', 'providers', 'config')
            providers_config = getattr(settings, 'OAUTH_PROVIDERS', {})
            
            # Remove sensitive data before caching
            safe_config = {}
            for provider, config in providers_config.items():
                safe_config[provider] = {
                    'client_id': config.get('client_id', ''),
                    'scope': config.get('scope', ''),
                    'enabled': bool(config.get('client_id') and config.get('client_secret'))
                }
            
            cache.set(providers_key, safe_config, timeout=3600)  # 1 hour
            logger.info("Warmed cache for OAuth providers")
            
        except Exception as e:
            logger.error(f"Cache warming failed for OAuth providers: {e}")
    
    def run_warming_tasks(self):
        """Execute all registered warming tasks based on their schedule."""
        current_time = datetime.now()
        
        for task_name, task_info in self.warming_tasks.items():
            if current_time >= task_info['next_run']:
                try:
                    logger.info(f"Running cache warming task: {task_name}")
                    
                    # Run task in thread pool
                    future = self.executor.submit(task_info['function'])
                    
                    # Update task timing
                    task_info['last_run'] = current_time
                    task_info['next_run'] = current_time + timedelta(
                        minutes=task_info['schedule_minutes']
                    )
                    
                    logger.info(f"Scheduled next run for {task_name}: {task_info['next_run']}")
                    
                except Exception as e:
                    logger.error(f"Cache warming task {task_name} failed: {e}")


class CacheInvalidator:
    """
    Implements intelligent cache invalidation strategies.
    """
    
    def __init__(self):
        self.redis_conn = get_redis_connection('cache')
        self.invalidation_patterns = {}
    
    def register_invalidation_pattern(self, trigger: str, patterns: List[str]):
        """
        Register cache invalidation patterns for specific triggers.
        
        Args:
            trigger: Event that triggers invalidation (user_update, role_change, etc.)
            patterns: List of cache key patterns to invalidate
        """
        self.invalidation_patterns[trigger] = patterns
        logger.info(f"Registered invalidation pattern for trigger: {trigger}")
    
    def invalidate_user_cache(self, user_id: str):
        """
        Invalidate all cache entries related to a specific user.
        
        Args:
            user_id: User ID to invalidate cache for
        """
        try:
            patterns_to_invalidate = [
                CacheKeyManager.generate_key('user', user_id, '*'),
                CacheKeyManager.generate_key('session', f"user:{user_id}", '*'),
                CacheKeyManager.generate_key('token', f"user:{user_id}", '*'),
                CacheKeyManager.generate_key('mfa', user_id, '*')
            ]
            
            invalidated_count = 0
            for pattern in patterns_to_invalidate:
                keys = self.redis_conn.keys(pattern)
                if keys:
                    self.redis_conn.delete(*keys)
                    invalidated_count += len(keys)
            
            logger.info(f"Invalidated {invalidated_count} cache entries for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to invalidate user cache for {user_id}: {e}")
    
    def invalidate_session_cache(self, session_id: str):
        """
        Invalidate cache entries related to a specific session.
        
        Args:
            session_id: Session ID to invalidate cache for
        """
        try:
            pattern = CacheKeyManager.generate_key('session', session_id, '*')
            keys = self.redis_conn.keys(pattern)
            
            if keys:
                self.redis_conn.delete(*keys)
                logger.info(f"Invalidated {len(keys)} cache entries for session {session_id}")
            
        except Exception as e:
            logger.error(f"Failed to invalidate session cache for {session_id}: {e}")
    
    def invalidate_role_cache(self, role_id: str = None):
        """
        Invalidate role and permission related cache entries.
        
        Args:
            role_id: Specific role ID, or None to invalidate all role cache
        """
        try:
            if role_id:
                patterns = [
                    CacheKeyManager.generate_key('role', role_id, '*'),
                    CacheKeyManager.generate_key('permission', f"role:{role_id}", '*')
                ]
            else:
                patterns = [
                    CacheKeyManager.generate_pattern_key('role'),
                    CacheKeyManager.generate_pattern_key('permission')
                ]
            
            invalidated_count = 0
            for pattern in patterns:
                keys = self.redis_conn.keys(pattern)
                if keys:
                    self.redis_conn.delete(*keys)
                    invalidated_count += len(keys)
            
            logger.info(f"Invalidated {invalidated_count} role/permission cache entries")
            
        except Exception as e:
            logger.error(f"Failed to invalidate role cache: {e}")
    
    def invalidate_by_pattern(self, pattern: str):
        """
        Invalidate cache entries matching a specific pattern.
        
        Args:
            pattern: Redis key pattern to match
        """
        try:
            keys = self.redis_conn.keys(pattern)
            if keys:
                self.redis_conn.delete(*keys)
                logger.info(f"Invalidated {len(keys)} cache entries matching pattern: {pattern}")
            
        except Exception as e:
            logger.error(f"Failed to invalidate cache by pattern {pattern}: {e}")
    
    def trigger_invalidation(self, trigger: str, context: Dict[str, Any] = None):
        """
        Trigger cache invalidation based on registered patterns.
        
        Args:
            trigger: Trigger event name
            context: Additional context for pattern substitution
        """
        if trigger not in self.invalidation_patterns:
            logger.warning(f"No invalidation patterns registered for trigger: {trigger}")
            return
        
        try:
            patterns = self.invalidation_patterns[trigger]
            context = context or {}
            
            for pattern in patterns:
                # Substitute context variables in pattern
                formatted_pattern = pattern.format(**context)
                self.invalidate_by_pattern(formatted_pattern)
            
            logger.info(f"Triggered cache invalidation for: {trigger}")
            
        except Exception as e:
            logger.error(f"Failed to trigger cache invalidation for {trigger}: {e}")


class SmartCacheManager:
    """
    High-level cache manager that combines warming and invalidation strategies.
    """
    
    def __init__(self):
        self.warmer = CacheWarmer()
        self.invalidator = CacheInvalidator()
        self.redis_conn = get_redis_connection('cache')
        self._setup_default_patterns()
    
    def _setup_default_patterns(self):
        """Setup default cache warming and invalidation patterns."""
        # Register warming tasks
        self.warmer.register_warming_task(
            'user_data', 
            self.warmer.warm_user_data, 
            schedule_minutes=30, 
            priority=1
        )
        
        self.warmer.register_warming_task(
            'role_permissions', 
            self.warmer.warm_role_permissions, 
            schedule_minutes=60, 
            priority=2
        )
        
        self.warmer.register_warming_task(
            'oauth_providers', 
            self.warmer.warm_oauth_providers, 
            schedule_minutes=120, 
            priority=3
        )
        
        # Register invalidation patterns
        self.invalidator.register_invalidation_pattern(
            'user_update', 
            ['user:{user_id}:*', 'session:user:{user_id}:*']
        )
        
        self.invalidator.register_invalidation_pattern(
            'role_update', 
            ['role:*', 'permission:*', 'user:*:permissions']
        )
        
        self.invalidator.register_invalidation_pattern(
            'oauth_config_update', 
            ['oauth:*']
        )
    
    def get_or_set(self, key: str, callable_func: Callable, timeout: int = 300, 
                   version: int = None) -> Any:
        """
        Get value from cache or set it using the provided callable.
        
        Args:
            key: Cache key
            callable_func: Function to call if cache miss
            timeout: Cache timeout in seconds
            version: Cache version
            
        Returns:
            Cached or computed value
        """
        try:
            # Try to get from cache first
            value = cache.get(key, version=version)
            if value is not None:
                return value
            
            # Cache miss - compute value
            value = callable_func()
            cache.set(key, value, timeout=timeout, version=version)
            
            return value
            
        except Exception as e:
            logger.error(f"Cache get_or_set failed for key {key}: {e}")
            # Fallback to direct computation
            return callable_func()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive cache statistics.
        
        Returns:
            Dictionary with cache performance metrics
        """
        try:
            info = self.redis_conn.info()
            
            return {
                'connected_clients': info.get('connected_clients', 0),
                'used_memory_human': info.get('used_memory_human', '0B'),
                'used_memory_peak_human': info.get('used_memory_peak_human', '0B'),
                'keyspace_hits': info.get('keyspace_hits', 0),
                'keyspace_misses': info.get('keyspace_misses', 0),
                'hit_rate': self._calculate_hit_rate(
                    info.get('keyspace_hits', 0), 
                    info.get('keyspace_misses', 0)
                ),
                'total_commands_processed': info.get('total_commands_processed', 0),
                'instantaneous_ops_per_sec': info.get('instantaneous_ops_per_sec', 0),
                'uptime_in_seconds': info.get('uptime_in_seconds', 0)
            }
            
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {}
    
    def _calculate_hit_rate(self, hits: int, misses: int) -> float:
        """Calculate cache hit rate percentage."""
        total = hits + misses
        if total == 0:
            return 0.0
        return round((hits / total) * 100, 2)


# Global cache manager instance
cache_manager = SmartCacheManager()