"""
Database monitoring and health check utilities.

This module provides comprehensive database monitoring:
- Connection pool monitoring
- Query performance tracking
- Replication lag monitoring
- Database health checks
- Automated failover detection
"""

import logging
import time
import threading
from datetime import datetime, timedelta
from django.db import connections
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)


class DatabaseMonitor:
    """
    Comprehensive database monitoring system.
    """

    def __init__(self):
        self.monitoring_active = False
        self.monitoring_thread = None
        self.last_check = {}
        self.health_status = {}
        self.performance_metrics = {}

    def start_monitoring(self, interval=60):
        """
        Start continuous database monitoring.
        
        Args:
            interval (int): Monitoring interval in seconds
        """
        if self.monitoring_active:
            logger.warning("Database monitoring is already active")
            return

        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self.monitoring_thread.start()
        logger.info(f"Database monitoring started with {interval}s interval")

    def stop_monitoring(self):
        """Stop database monitoring."""
        self.monitoring_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        logger.info("Database monitoring stopped")

    def _monitoring_loop(self, interval):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                self._perform_health_checks()
                self._collect_performance_metrics()
                self._check_replication_lag()
                self._monitor_connection_pools()
                
                # Cache results for API access
                cache.set('db_health_status', self.health_status, timeout=interval * 2)
                cache.set('db_performance_metrics', self.performance_metrics, timeout=interval * 2)
                
            except Exception as e:
                logger.error(f"Error in database monitoring loop: {e}")
            
            time.sleep(interval)

    def _perform_health_checks(self):
        """Perform health checks on all configured databases."""
        for db_name in settings.DATABASES.keys():
            start_time = time.time()
            health_info = {
                'database': db_name,
                'timestamp': timezone.now().isoformat(),
                'status': 'unknown',
                'response_time': None,
                'error': None
            }
            
            try:
                connection = connections[db_name]
                
                # Test basic connectivity
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    
                    if result and result[0] == 1:
                        health_info['status'] = 'healthy'
                        health_info['response_time'] = time.time() - start_time
                        
                        # Additional PostgreSQL-specific checks
                        if connection.vendor == 'postgresql':
                            self._postgresql_health_checks(cursor, health_info)
                    else:
                        health_info['status'] = 'unhealthy'
                        health_info['error'] = 'Unexpected query result'
                        
            except Exception as e:
                health_info['status'] = 'unhealthy'
                health_info['error'] = str(e)
                health_info['response_time'] = time.time() - start_time
                logger.error(f"Health check failed for {db_name}: {e}")
            
            self.health_status[db_name] = health_info

    def _postgresql_health_checks(self, cursor, health_info):
        """Perform PostgreSQL-specific health checks."""
        try:
            # Check connection count
            cursor.execute("""
                SELECT count(*) as active_connections,
                       (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') as max_connections
                FROM pg_stat_activity 
                WHERE datname = current_database()
            """)
            conn_result = cursor.fetchone()
            health_info['active_connections'] = conn_result[0]
            health_info['max_connections'] = conn_result[1]
            health_info['connection_usage'] = (conn_result[0] / conn_result[1]) * 100
            
            # Check for long-running queries
            cursor.execute("""
                SELECT count(*) as long_running_queries
                FROM pg_stat_activity 
                WHERE state = 'active' 
                AND query_start < now() - interval '5 minutes'
                AND query NOT LIKE '%pg_stat_activity%'
            """)
            long_queries = cursor.fetchone()[0]
            health_info['long_running_queries'] = long_queries
            
            # Check database size
            cursor.execute("""
                SELECT pg_size_pretty(pg_database_size(current_database())) as database_size,
                       pg_database_size(current_database()) as database_size_bytes
            """)
            size_result = cursor.fetchone()
            health_info['database_size'] = size_result[0]
            health_info['database_size_bytes'] = size_result[1]
            
            # Check for locks
            cursor.execute("""
                SELECT count(*) as exclusive_locks
                FROM pg_locks 
                WHERE mode LIKE '%ExclusiveLock%'
            """)
            locks = cursor.fetchone()[0]
            health_info['exclusive_locks'] = locks
            
        except Exception as e:
            logger.warning(f"PostgreSQL health checks failed: {e}")
            health_info['postgresql_checks_error'] = str(e)

    def _collect_performance_metrics(self):
        """Collect performance metrics from all databases."""
        for db_name in settings.DATABASES.keys():
            metrics = {
                'database': db_name,
                'timestamp': timezone.now().isoformat(),
                'queries_per_second': 0,
                'average_query_time': 0,
                'slow_queries': 0,
                'error': None
            }
            
            try:
                connection = connections[db_name]
                
                if connection.vendor == 'postgresql':
                    with connection.cursor() as cursor:
                        # Get query statistics
                        cursor.execute("""
                            SELECT 
                                sum(calls) as total_calls,
                                sum(total_time) as total_time,
                                sum(mean_time * calls) / sum(calls) as avg_time,
                                count(*) filter (where mean_time > 1000) as slow_queries
                            FROM pg_stat_statements
                            WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
                        """)
                        
                        result = cursor.fetchone()
                        if result and result[0]:
                            # Calculate QPS based on time since last check
                            last_check_time = self.last_check.get(db_name, time.time() - 60)
                            time_diff = time.time() - last_check_time
                            
                            metrics['total_queries'] = result[0]
                            metrics['total_time'] = result[1]
                            metrics['average_query_time'] = result[2] or 0
                            metrics['slow_queries'] = result[3] or 0
                            
                            if time_diff > 0:
                                metrics['queries_per_second'] = result[0] / time_diff
                        
                        # Get cache hit ratio
                        cursor.execute("""
                            SELECT 
                                sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read)) * 100 as cache_hit_ratio
                            FROM pg_statio_user_tables
                        """)
                        cache_result = cursor.fetchone()
                        if cache_result and cache_result[0]:
                            metrics['cache_hit_ratio'] = float(cache_result[0])
                        
            except Exception as e:
                metrics['error'] = str(e)
                logger.warning(f"Failed to collect performance metrics for {db_name}: {e}")
            
            self.performance_metrics[db_name] = metrics
            self.last_check[db_name] = time.time()

    def _check_replication_lag(self):
        """Check replication lag for read replicas."""
        primary_db = 'default'
        
        # Get current LSN from primary
        primary_lsn = None
        try:
            connection = connections[primary_db]
            if connection.vendor == 'postgresql':
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_current_wal_lsn()")
                    primary_lsn = cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Failed to get primary LSN: {e}")
            return
        
        # Check lag on each replica
        for db_name in settings.DATABASES.keys():
            if db_name.startswith('read_replica'):
                try:
                    connection = connections[db_name]
                    if connection.vendor == 'postgresql':
                        with connection.cursor() as cursor:
                            cursor.execute("SELECT pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()")
                            receive_lsn, replay_lsn = cursor.fetchone()
                            
                            # Calculate lag in bytes
                            if primary_lsn and replay_lsn:
                                cursor.execute(
                                    "SELECT %s::pg_lsn - %s::pg_lsn",
                                    [primary_lsn, replay_lsn]
                                )
                                lag_bytes = cursor.fetchone()[0]
                                
                                # Update health status with replication info
                                if db_name in self.health_status:
                                    self.health_status[db_name]['replication_lag_bytes'] = lag_bytes
                                    self.health_status[db_name]['replication_lag_mb'] = lag_bytes / (1024 * 1024)
                                    self.health_status[db_name]['primary_lsn'] = primary_lsn
                                    self.health_status[db_name]['replica_lsn'] = replay_lsn
                                    
                                    # Flag high lag
                                    if lag_bytes > 100 * 1024 * 1024:  # 100MB
                                        self.health_status[db_name]['high_replication_lag'] = True
                                        logger.warning(f"High replication lag detected on {db_name}: {lag_bytes / (1024 * 1024):.2f}MB")
                
                except Exception as e:
                    logger.error(f"Failed to check replication lag for {db_name}: {e}")

    def _monitor_connection_pools(self):
        """Monitor connection pool status."""
        for db_name in settings.DATABASES.keys():
            try:
                connection = connections[db_name]
                
                pool_info = {
                    'database': db_name,
                    'is_usable': connection.is_usable(),
                    'vendor': connection.vendor,
                    'autocommit': connection.get_autocommit(),
                    'in_atomic_block': connection.in_atomic_block,
                    'queries_count': len(getattr(connection, 'queries', [])),
                }
                
                # Add to health status
                if db_name in self.health_status:
                    self.health_status[db_name]['connection_pool'] = pool_info
                
            except Exception as e:
                logger.error(f"Failed to monitor connection pool for {db_name}: {e}")

    def get_health_summary(self):
        """Get a summary of database health status."""
        summary = {
            'timestamp': timezone.now().isoformat(),
            'overall_status': 'healthy',
            'databases': {},
            'alerts': []
        }
        
        for db_name, health_info in self.health_status.items():
            db_summary = {
                'status': health_info.get('status', 'unknown'),
                'response_time': health_info.get('response_time'),
                'connection_usage': health_info.get('connection_usage', 0),
                'replication_lag_mb': health_info.get('replication_lag_mb', 0),
            }
            
            # Check for alerts
            if health_info.get('status') != 'healthy':
                summary['overall_status'] = 'unhealthy'
                summary['alerts'].append(f"{db_name}: {health_info.get('error', 'Unknown error')}")
            
            if health_info.get('connection_usage', 0) > 80:
                summary['alerts'].append(f"{db_name}: High connection usage ({health_info['connection_usage']:.1f}%)")
            
            if health_info.get('replication_lag_mb', 0) > 100:
                summary['alerts'].append(f"{db_name}: High replication lag ({health_info['replication_lag_mb']:.1f}MB)")
            
            if health_info.get('long_running_queries', 0) > 5:
                summary['alerts'].append(f"{db_name}: {health_info['long_running_queries']} long-running queries")
            
            summary['databases'][db_name] = db_summary
        
        return summary

    def get_performance_summary(self):
        """Get a summary of database performance metrics."""
        summary = {
            'timestamp': timezone.now().isoformat(),
            'databases': {}
        }
        
        for db_name, metrics in self.performance_metrics.items():
            summary['databases'][db_name] = {
                'queries_per_second': metrics.get('queries_per_second', 0),
                'average_query_time': metrics.get('average_query_time', 0),
                'slow_queries': metrics.get('slow_queries', 0),
                'cache_hit_ratio': metrics.get('cache_hit_ratio', 0),
            }
        
        return summary


# Global monitor instance
db_monitor = DatabaseMonitor()


def start_database_monitoring():
    """Start database monitoring (called during app startup)."""
    if getattr(settings, 'DB_MONITORING_ENABLED', True):
        interval = getattr(settings, 'DB_MONITORING_INTERVAL', 60)
        db_monitor.start_monitoring(interval)


def stop_database_monitoring():
    """Stop database monitoring (called during app shutdown)."""
    db_monitor.stop_monitoring()


def get_database_health():
    """Get current database health status."""
    return db_monitor.get_health_summary()


def get_database_performance():
    """Get current database performance metrics."""
    return db_monitor.get_performance_summary()