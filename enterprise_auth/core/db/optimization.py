"""
Database optimization and performance monitoring.
Provides query optimization, index management, and connection pooling.
"""

import logging
import time
import threading
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from django.db import connection, connections
from django.db.models import QuerySet
from django.conf import settings
from django.core.management.color import no_style
from django.db.models.sql import Query
import json
import re

logger = logging.getLogger(__name__)


class QueryAnalyzer:
    """
    Analyzes database queries for performance optimization.
    """
    
    def __init__(self):
        self.slow_queries = deque(maxlen=1000)
        self.query_stats = defaultdict(lambda: {
            'count': 0,
            'total_time': 0,
            'avg_time': 0,
            'max_time': 0,
            'min_time': float('inf')
        })
        self._lock = threading.Lock()
        self.slow_query_threshold = getattr(settings, 'SLOW_QUERY_THRESHOLD', 1.0)  # seconds
    
    def analyze_query(self, sql: str, duration: float, params: tuple = None):
        """
        Analyze a database query for performance issues.
        
        Args:
            sql: SQL query string
            duration: Query execution time in seconds
            params: Query parameters
        """
        # Normalize SQL for grouping similar queries
        normalized_sql = self._normalize_sql(sql)
        
        with self._lock:
            # Update query statistics
            stats = self.query_stats[normalized_sql]
            stats['count'] += 1
            stats['total_time'] += duration
            stats['avg_time'] = stats['total_time'] / stats['count']
            stats['max_time'] = max(stats['max_time'], duration)
            stats['min_time'] = min(stats['min_time'], duration)
            
            # Record slow queries
            if duration >= self.slow_query_threshold:
                slow_query = {
                    'sql': sql,
                    'normalized_sql': normalized_sql,
                    'duration': duration,
                    'params': params,
                    'timestamp': datetime.now(),
                    'analysis': self._analyze_query_issues(sql, duration)
                }
                self.slow_queries.append(slow_query)
                logger.warning(f"Slow query detected: {duration:.3f}s - {sql[:100]}...")
    
    def _normalize_sql(self, sql: str) -> str:
        """Normalize SQL query for grouping similar queries."""
        # Remove extra whitespace
        sql = re.sub(r'\s+', ' ', sql.strip())
        
        # Replace parameter placeholders with generic markers
        sql = re.sub(r'%s', '?', sql)
        sql = re.sub(r'\$\d+', '?', sql)
        
        # Replace IN clauses with generic form
        sql = re.sub(r'IN \([^)]+\)', 'IN (?)', sql)
        
        # Replace numeric literals
        sql = re.sub(r'\b\d+\b', '?', sql)
        
        # Replace string literals
        sql = re.sub(r"'[^']*'", '?', sql)
        sql = re.sub(r'"[^"]*"', '?', sql)
        
        return sql
    
    def _analyze_query_issues(self, sql: str, duration: float) -> Dict[str, Any]:
        """Analyze query for common performance issues."""
        issues = []
        recommendations = []
        
        sql_upper = sql.upper()
        
        # Check for missing WHERE clause
        if 'SELECT' in sql_upper and 'WHERE' not in sql_upper and 'LIMIT' not in sql_upper:
            issues.append('missing_where_clause')
            recommendations.append('Add WHERE clause to limit result set')
        
        # Check for SELECT *
        if 'SELECT *' in sql_upper:
            issues.append('select_all_columns')
            recommendations.append('Select only needed columns instead of *')
        
        # Check for N+1 queries (multiple similar queries)
        normalized = self._normalize_sql(sql)
        if self.query_stats[normalized]['count'] > 10:
            issues.append('potential_n_plus_one')
            recommendations.append('Consider using select_related() or prefetch_related()')
        
        # Check for missing LIMIT
        if 'SELECT' in sql_upper and 'LIMIT' not in sql_upper and duration > 0.5:
            issues.append('missing_limit')
            recommendations.append('Add LIMIT clause for large result sets')
        
        # Check for complex JOINs
        join_count = sql_upper.count('JOIN')
        if join_count > 3:
            issues.append('complex_joins')
            recommendations.append('Consider denormalization or query splitting')
        
        # Check for subqueries
        if 'SELECT' in sql_upper and sql_upper.count('SELECT') > 1:
            issues.append('subqueries')
            recommendations.append('Consider using JOINs instead of subqueries')
        
        return {
            'issues': issues,
            'recommendations': recommendations,
            'severity': 'high' if duration > 2.0 else 'medium' if duration > 1.0 else 'low'
        }
    
    def get_slow_queries_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generate report of slow queries."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self._lock:
            recent_slow_queries = [
                q for q in self.slow_queries 
                if q['timestamp'] >= cutoff_time
            ]
        
        # Group by normalized SQL
        grouped_queries = defaultdict(list)
        for query in recent_slow_queries:
            grouped_queries[query['normalized_sql']].append(query)
        
        # Generate summary
        query_summaries = []
        for normalized_sql, queries in grouped_queries.items():
            durations = [q['duration'] for q in queries]
            query_summaries.append({
                'normalized_sql': normalized_sql,
                'count': len(queries),
                'avg_duration': sum(durations) / len(durations),
                'max_duration': max(durations),
                'total_time': sum(durations),
                'common_issues': self._get_common_issues(queries),
                'sample_query': queries[0]['sql']
            })
        
        # Sort by total time impact
        query_summaries.sort(key=lambda x: x['total_time'], reverse=True)
        
        return {
            'report_period_hours': hours,
            'total_slow_queries': len(recent_slow_queries),
            'unique_query_patterns': len(query_summaries),
            'total_slow_query_time': sum(q['duration'] for q in recent_slow_queries),
            'queries': query_summaries[:20]  # Top 20 by impact
        }
    
    def _get_common_issues(self, queries: List[Dict]) -> List[str]:
        """Get most common issues across similar queries."""
        issue_counts = defaultdict(int)
        for query in queries:
            for issue in query['analysis']['issues']:
                issue_counts[issue] += 1
        
        return [issue for issue, count in issue_counts.items() if count >= len(queries) * 0.5]
    
    def get_query_statistics(self) -> Dict[str, Any]:
        """Get overall query statistics."""
        with self._lock:
            total_queries = sum(stats['count'] for stats in self.query_stats.values())
            total_time = sum(stats['total_time'] for stats in self.query_stats.values())
            
            if total_queries == 0:
                return {'total_queries': 0, 'avg_query_time': 0}
            
            # Find top queries by various metrics
            top_by_count = sorted(
                self.query_stats.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )[:10]
            
            top_by_avg_time = sorted(
                self.query_stats.items(),
                key=lambda x: x[1]['avg_time'],
                reverse=True
            )[:10]
            
            top_by_total_time = sorted(
                self.query_stats.items(),
                key=lambda x: x[1]['total_time'],
                reverse=True
            )[:10]
            
            return {
                'total_queries': total_queries,
                'total_time': total_time,
                'avg_query_time': total_time / total_queries,
                'unique_query_patterns': len(self.query_stats),
                'slow_query_count': len(self.slow_queries),
                'top_by_count': [(sql, stats) for sql, stats in top_by_count],
                'top_by_avg_time': [(sql, stats) for sql, stats in top_by_avg_time],
                'top_by_total_time': [(sql, stats) for sql, stats in top_by_total_time]
            }


class IndexOptimizer:
    """
    Manages database index optimization and recommendations.
    """
    
    def __init__(self):
        self.index_usage_stats = defaultdict(lambda: {
            'scans': 0,
            'tup_read': 0,
            'tup_fetched': 0,
            'last_used': None
        })
    
    def analyze_missing_indexes(self, connection_name: str = 'default') -> List[Dict[str, Any]]:
        """
        Analyze database for missing indexes based on query patterns.
        
        Args:
            connection_name: Database connection name
            
        Returns:
            List of index recommendations
        """
        recommendations = []
        
        try:
            with connections[connection_name].cursor() as cursor:
                # PostgreSQL-specific query to find missing indexes
                if 'postgresql' in settings.DATABASES[connection_name]['ENGINE']:
                    recommendations.extend(self._analyze_postgresql_missing_indexes(cursor))
                
        except Exception as e:
            logger.error(f"Failed to analyze missing indexes: {e}")
        
        return recommendations
    
    def _analyze_postgresql_missing_indexes(self, cursor) -> List[Dict[str, Any]]:
        """Analyze missing indexes for PostgreSQL."""
        recommendations = []
        
        # Query to find tables with high sequential scan ratios
        cursor.execute("""
            SELECT 
                schemaname,
                tablename,
                seq_scan,
                seq_tup_read,
                idx_scan,
                idx_tup_fetch,
                CASE 
                    WHEN seq_scan + idx_scan > 0 
                    THEN seq_scan::float / (seq_scan + idx_scan) 
                    ELSE 0 
                END as seq_scan_ratio
            FROM pg_stat_user_tables
            WHERE seq_scan + idx_scan > 100  -- Only tables with significant activity
            ORDER BY seq_scan_ratio DESC, seq_tup_read DESC
            LIMIT 20;
        """)
        
        for row in cursor.fetchall():
            schema, table, seq_scan, seq_tup_read, idx_scan, idx_tup_fetch, seq_scan_ratio = row
            
            if seq_scan_ratio > 0.8 and seq_tup_read > 1000:  # High sequential scan ratio
                recommendations.append({
                    'type': 'missing_index',
                    'table': f"{schema}.{table}",
                    'reason': 'High sequential scan ratio',
                    'seq_scan_ratio': round(seq_scan_ratio, 3),
                    'seq_tup_read': seq_tup_read,
                    'priority': 'high' if seq_scan_ratio > 0.9 else 'medium',
                    'recommendation': f"Consider adding indexes to frequently queried columns in {table}"
                })
        
        # Query to find unused indexes
        cursor.execute("""
            SELECT 
                schemaname,
                tablename,
                indexname,
                idx_scan,
                pg_size_pretty(pg_relation_size(indexrelid)) as size
            FROM pg_stat_user_indexes
            WHERE idx_scan < 10  -- Very low usage
            AND pg_relation_size(indexrelid) > 1024 * 1024  -- Larger than 1MB
            ORDER BY pg_relation_size(indexrelid) DESC
            LIMIT 10;
        """)
        
        for row in cursor.fetchall():
            schema, table, index, scans, size = row
            
            recommendations.append({
                'type': 'unused_index',
                'table': f"{schema}.{table}",
                'index': index,
                'scans': scans,
                'size': size,
                'priority': 'medium',
                'recommendation': f"Consider dropping unused index {index} to save space and improve write performance"
            })
        
        return recommendations
    
    def get_index_usage_stats(self, connection_name: str = 'default') -> Dict[str, Any]:
        """Get index usage statistics."""
        try:
            with connections[connection_name].cursor() as cursor:
                if 'postgresql' in settings.DATABASES[connection_name]['ENGINE']:
                    return self._get_postgresql_index_stats(cursor)
        except Exception as e:
            logger.error(f"Failed to get index usage stats: {e}")
            return {}
    
    def _get_postgresql_index_stats(self, cursor) -> Dict[str, Any]:
        """Get PostgreSQL index usage statistics."""
        cursor.execute("""
            SELECT 
                schemaname,
                tablename,
                indexname,
                idx_scan,
                idx_tup_read,
                idx_tup_fetch,
                pg_size_pretty(pg_relation_size(indexrelid)) as size
            FROM pg_stat_user_indexes
            ORDER BY idx_scan DESC
            LIMIT 50;
        """)
        
        indexes = []
        for row in cursor.fetchall():
            schema, table, index, scans, tup_read, tup_fetch, size = row
            indexes.append({
                'schema': schema,
                'table': table,
                'index': index,
                'scans': scans,
                'tuples_read': tup_read,
                'tuples_fetched': tup_fetch,
                'size': size,
                'efficiency': round(tup_fetch / tup_read, 3) if tup_read > 0 else 0
            })
        
        return {
            'indexes': indexes,
            'total_indexes': len(indexes),
            'generated_at': datetime.now().isoformat()
        }


class ConnectionPoolMonitor:
    """
    Monitors database connection pool performance and health.
    """
    
    def __init__(self):
        self.connection_stats = defaultdict(lambda: {
            'active_connections': 0,
            'idle_connections': 0,
            'total_connections': 0,
            'connection_errors': 0,
            'avg_connection_time': 0,
            'max_connections_used': 0
        })
        self._lock = threading.Lock()
    
    def record_connection_event(self, connection_name: str, event_type: str, duration: float = None):
        """
        Record connection pool event.
        
        Args:
            connection_name: Database connection name
            event_type: Type of event (acquire, release, error, etc.)
            duration: Event duration in seconds
        """
        with self._lock:
            stats = self.connection_stats[connection_name]
            
            if event_type == 'acquire':
                stats['active_connections'] += 1
                stats['total_connections'] = max(stats['total_connections'], stats['active_connections'])
                stats['max_connections_used'] = max(stats['max_connections_used'], stats['active_connections'])
                
                if duration:
                    # Update average connection time
                    current_avg = stats['avg_connection_time']
                    stats['avg_connection_time'] = (current_avg + duration) / 2
            
            elif event_type == 'release':
                stats['active_connections'] = max(0, stats['active_connections'] - 1)
                stats['idle_connections'] += 1
            
            elif event_type == 'error':
                stats['connection_errors'] += 1
    
    def get_connection_pool_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics for all databases."""
        with self._lock:
            pool_stats = {}
            
            for connection_name, stats in self.connection_stats.items():
                try:
                    # Get current connection info from Django
                    conn = connections[connection_name]
                    
                    pool_stats[connection_name] = {
                        **stats,
                        'database_name': conn.settings_dict.get('NAME', 'unknown'),
                        'engine': conn.settings_dict.get('ENGINE', 'unknown'),
                        'host': conn.settings_dict.get('HOST', 'localhost'),
                        'port': conn.settings_dict.get('PORT', 'unknown'),
                        'conn_max_age': conn.settings_dict.get('CONN_MAX_AGE', 0),
                        'is_usable': conn.is_usable() if hasattr(conn, 'is_usable') else True
                    }
                    
                except Exception as e:
                    logger.error(f"Failed to get connection info for {connection_name}: {e}")
                    pool_stats[connection_name] = stats
            
            return {
                'connections': pool_stats,
                'total_databases': len(pool_stats),
                'generated_at': datetime.now().isoformat()
            }
    
    def check_connection_health(self, connection_name: str = 'default') -> Dict[str, Any]:
        """Check health of database connection."""
        try:
            start_time = time.time()
            
            with connections[connection_name].cursor() as cursor:
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
            
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            return {
                'connection_name': connection_name,
                'status': 'healthy' if result and result[0] == 1 else 'unhealthy',
                'response_time_ms': round(response_time, 2),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'connection_name': connection_name,
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }


class DatabasePerformanceMonitor:
    """
    Comprehensive database performance monitoring.
    """
    
    def __init__(self):
        self.query_analyzer = QueryAnalyzer()
        self.index_optimizer = IndexOptimizer()
        self.connection_monitor = ConnectionPoolMonitor()
        self.performance_history = deque(maxlen=1440)  # 24 hours of minute-by-minute data
        self._monitoring_active = False
        self._monitor_thread = None
    
    def start_monitoring(self):
        """Start continuous database performance monitoring."""
        if self._monitoring_active:
            return
        
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Database performance monitoring started")
    
    def stop_monitoring(self):
        """Stop database performance monitoring."""
        self._monitoring_active = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Database performance monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop."""
        while self._monitoring_active:
            try:
                # Collect performance metrics
                metrics = self._collect_performance_metrics()
                self.performance_history.append({
                    'timestamp': datetime.now(),
                    'metrics': metrics
                })
                
                # Sleep for 1 minute
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in database monitoring loop: {e}")
                time.sleep(60)  # Continue monitoring even if there's an error
    
    def _collect_performance_metrics(self) -> Dict[str, Any]:
        """Collect current database performance metrics."""
        metrics = {}
        
        try:
            # Get connection pool stats
            metrics['connection_pools'] = self.connection_monitor.get_connection_pool_stats()
            
            # Get query statistics
            metrics['query_stats'] = self.query_analyzer.get_query_statistics()
            
            # Get index usage stats
            metrics['index_stats'] = self.index_optimizer.get_index_usage_stats()
            
            # Check connection health
            metrics['connection_health'] = self.connection_monitor.check_connection_health()
            
        except Exception as e:
            logger.error(f"Failed to collect database performance metrics: {e}")
            metrics['error'] = str(e)
        
        return metrics
    
    def get_performance_report(self, hours: int = 1) -> Dict[str, Any]:
        """Generate comprehensive database performance report."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Filter recent performance data
        recent_data = [
            entry for entry in self.performance_history
            if entry['timestamp'] >= cutoff_time
        ]
        
        if not recent_data:
            return {'error': 'No performance data available for the specified period'}
        
        # Generate report
        report = {
            'report_period_hours': hours,
            'data_points': len(recent_data),
            'generated_at': datetime.now().isoformat(),
            'slow_queries': self.query_analyzer.get_slow_queries_report(hours),
            'index_recommendations': self.index_optimizer.analyze_missing_indexes(),
            'connection_pool_stats': self.connection_monitor.get_connection_pool_stats(),
            'query_statistics': self.query_analyzer.get_query_statistics(),
            'performance_trends': self._analyze_performance_trends(recent_data)
        }
        
        return report
    
    def _analyze_performance_trends(self, data: List[Dict]) -> Dict[str, Any]:
        """Analyze performance trends from historical data."""
        if len(data) < 2:
            return {'error': 'Insufficient data for trend analysis'}
        
        # Extract metrics over time
        query_times = []
        connection_counts = []
        
        for entry in data:
            metrics = entry['metrics']
            
            # Query performance trends
            query_stats = metrics.get('query_stats', {})
            if 'avg_query_time' in query_stats:
                query_times.append(query_stats['avg_query_time'])
            
            # Connection pool trends
            conn_stats = metrics.get('connection_pools', {})
            total_connections = sum(
                pool.get('active_connections', 0) 
                for pool in conn_stats.get('connections', {}).values()
            )
            connection_counts.append(total_connections)
        
        trends = {}
        
        # Analyze query time trends
        if len(query_times) >= 2:
            trends['query_time'] = {
                'current': query_times[-1] if query_times else 0,
                'previous': query_times[0] if query_times else 0,
                'trend': 'improving' if query_times[-1] < query_times[0] else 'degrading',
                'change_percent': ((query_times[-1] - query_times[0]) / query_times[0] * 100) if query_times[0] > 0 else 0
            }
        
        # Analyze connection trends
        if len(connection_counts) >= 2:
            trends['connections'] = {
                'current': connection_counts[-1],
                'previous': connection_counts[0],
                'trend': 'increasing' if connection_counts[-1] > connection_counts[0] else 'decreasing',
                'change_percent': ((connection_counts[-1] - connection_counts[0]) / connection_counts[0] * 100) if connection_counts[0] > 0 else 0
            }
        
        return trends


# Global database performance monitor instance
db_performance_monitor = DatabasePerformanceMonitor()