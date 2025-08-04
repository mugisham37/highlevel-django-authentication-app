"""
Database optimization utilities and configurations.

This module provides utilities for optimizing database performance:
- Query optimization helpers
- Index management utilities
- Connection pool monitoring
- Performance metrics collection
"""

import logging
import time
from functools import wraps
from django.db import connections, transaction
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


class QueryOptimizer:
    """
    Utility class for database query optimization.
    
    Provides methods for:
    - Query performance monitoring
    - Automatic query optimization
    - Connection pool management
    - Database health checks
    """

    @staticmethod
    def monitor_query_performance(func):
        """
        Decorator to monitor query performance and log slow queries.
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            
            # Log slow queries (configurable threshold)
            slow_query_threshold = getattr(settings, 'SLOW_QUERY_THRESHOLD', 1.0)
            if execution_time > slow_query_threshold:
                logger.warning(
                    f"Slow query detected: {func.__name__} took {execution_time:.2f}s",
                    extra={
                        'function': func.__name__,
                        'execution_time': execution_time,
                        'args': str(args)[:200],  # Truncate for logging
                        'kwargs': str(kwargs)[:200]
                    }
                )
            
            return result
        return wrapper

    @staticmethod
    def get_connection_stats():
        """
        Get connection pool statistics for monitoring.
        """
        stats = {}
        for db_name in settings.DATABASES.keys():
            try:
                connection = connections[db_name]
                stats[db_name] = {
                    'queries_count': len(connection.queries),
                    'is_usable': connection.is_usable(),
                    'vendor': connection.vendor,
                    'settings_dict': {
                        'NAME': connection.settings_dict.get('NAME'),
                        'HOST': connection.settings_dict.get('HOST'),
                        'PORT': connection.settings_dict.get('PORT'),
                    }
                }
            except Exception as e:
                stats[db_name] = {'error': str(e)}
        
        return stats

    @staticmethod
    def health_check():
        """
        Perform database health checks for all configured databases.
        """
        health_status = {}
        
        for db_name in settings.DATABASES.keys():
            try:
                connection = connections[db_name]
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    
                health_status[db_name] = {
                    'status': 'healthy' if result[0] == 1 else 'unhealthy',
                    'response_time': time.time()
                }
            except Exception as e:
                health_status[db_name] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
                logger.error(f"Database health check failed for {db_name}: {e}")
        
        return health_status

    @staticmethod
    def optimize_connection_settings():
        """
        Apply runtime optimizations to database connections.
        """
        optimizations_applied = []
        
        for db_name, db_config in settings.DATABASES.items():
            try:
                connection = connections[db_name]
                
                # Apply PostgreSQL-specific optimizations
                if connection.vendor == 'postgresql':
                    with connection.cursor() as cursor:
                        # Set optimal work_mem for this session
                        cursor.execute("SET work_mem = '256MB'")
                        
                        # Enable parallel query execution
                        cursor.execute("SET max_parallel_workers_per_gather = 4")
                        
                        # Optimize for OLTP workloads
                        cursor.execute("SET random_page_cost = 1.1")
                        
                        optimizations_applied.append(f"{db_name}: PostgreSQL optimizations applied")
                
            except Exception as e:
                logger.warning(f"Failed to apply optimizations to {db_name}: {e}")
        
        return optimizations_applied


class ConnectionPoolManager:
    """
    Manager for database connection pools with monitoring and optimization.
    """

    def __init__(self):
        self.pool_stats = {}
        self.last_check = time.time()

    def get_pool_status(self):
        """
        Get current connection pool status for all databases.
        """
        current_time = time.time()
        
        # Update stats every 30 seconds
        if current_time - self.last_check > 30:
            self._update_pool_stats()
            self.last_check = current_time
        
        return self.pool_stats

    def _update_pool_stats(self):
        """
        Update connection pool statistics.
        """
        for db_name in settings.DATABASES.keys():
            try:
                connection = connections[db_name]
                
                # Get connection pool information
                pool_info = {
                    'database': db_name,
                    'is_usable': connection.is_usable(),
                    'queries_count': len(connection.queries) if hasattr(connection, 'queries') else 0,
                    'vendor': connection.vendor,
                    'autocommit': connection.get_autocommit(),
                    'in_atomic_block': connection.in_atomic_block,
                }
                
                # Add PostgreSQL-specific pool information
                if connection.vendor == 'postgresql':
                    try:
                        with connection.cursor() as cursor:
                            # Get connection count
                            cursor.execute("""
                                SELECT count(*) 
                                FROM pg_stat_activity 
                                WHERE datname = current_database()
                            """)
                            pool_info['active_connections'] = cursor.fetchone()[0]
                            
                            # Get connection limits
                            cursor.execute("SHOW max_connections")
                            pool_info['max_connections'] = int(cursor.fetchone()[0])
                            
                    except Exception as e:
                        pool_info['pool_error'] = str(e)
                
                self.pool_stats[db_name] = pool_info
                
            except Exception as e:
                self.pool_stats[db_name] = {
                    'database': db_name,
                    'error': str(e),
                    'status': 'unavailable'
                }

    def cleanup_idle_connections(self):
        """
        Clean up idle database connections to free resources.
        """
        cleaned_connections = []
        
        for db_name in settings.DATABASES.keys():
            try:
                connection = connections[db_name]
                
                # Close connection if it's not in use
                if not connection.in_atomic_block and connection.is_usable():
                    connection.close()
                    cleaned_connections.append(db_name)
                    logger.info(f"Cleaned up idle connection for {db_name}")
                    
            except Exception as e:
                logger.warning(f"Failed to cleanup connection for {db_name}: {e}")
        
        return cleaned_connections


# Global instances
query_optimizer = QueryOptimizer()
connection_pool_manager = ConnectionPoolManager()


def setup_database_optimizations():
    """
    Setup database optimizations during application startup.
    """
    logger.info("Setting up database optimizations...")
    
    try:
        # Apply connection optimizations
        optimizations = query_optimizer.optimize_connection_settings()
        for optimization in optimizations:
            logger.info(optimization)
        
        # Perform initial health check
        health_status = query_optimizer.health_check()
        for db_name, status in health_status.items():
            if status['status'] == 'healthy':
                logger.info(f"Database {db_name} is healthy")
            else:
                logger.error(f"Database {db_name} health check failed: {status.get('error', 'Unknown error')}")
        
        logger.info("Database optimizations setup completed")
        
    except Exception as e:
        logger.error(f"Failed to setup database optimizations: {e}")


def get_database_metrics():
    """
    Get comprehensive database metrics for monitoring.
    """
    return {
        'connection_stats': query_optimizer.get_connection_stats(),
        'pool_status': connection_pool_manager.get_pool_status(),
        'health_status': query_optimizer.health_check(),
        'timestamp': time.time()
    }