"""
Cache analytics and performance monitoring for enterprise authentication system.
Provides comprehensive metrics collection, analysis, and reporting for cache performance.
"""

import logging
import time
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from django.conf import settings
from django.core.cache import cache
from .redis_config import get_redis_connection
import threading
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class CacheMetrics:
    """Data class for cache performance metrics."""
    hits: int = 0
    misses: int = 0
    sets: int = 0
    deletes: int = 0
    evictions: int = 0
    memory_usage: int = 0
    response_time_avg: float = 0.0
    response_time_p95: float = 0.0
    response_time_p99: float = 0.0
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate percentage."""
        total = self.hits + self.misses
        return (self.hits / total * 100) if total > 0 else 0.0
    
    @property
    def miss_rate(self) -> float:
        """Calculate cache miss rate percentage."""
        return 100.0 - self.hit_rate


class CacheAnalytics:
    """
    Comprehensive cache analytics and monitoring system.
    Tracks performance metrics, identifies bottlenecks, and provides insights.
    """
    
    def __init__(self, max_history_size: int = 1000):
        self.redis_conn = get_redis_connection('cache')
        self.max_history_size = max_history_size
        self.metrics_history = deque(maxlen=max_history_size)
        self.operation_times = defaultdict(lambda: deque(maxlen=100))
        self.key_access_patterns = defaultdict(int)
        self.slow_operations = deque(maxlen=50)
        self.lock = threading.Lock()
        
        # Performance thresholds
        self.slow_operation_threshold = 0.1  # 100ms
        self.high_miss_rate_threshold = 20.0  # 20%
        self.memory_warning_threshold = 0.8  # 80% of max memory
    
    def record_operation(self, operation: str, key: str, duration: float, 
                        hit: bool = None, size: int = None):
        """
        Record cache operation metrics.
        
        Args:
            operation: Type of operation (get, set, delete, etc.)
            key: Cache key
            duration: Operation duration in seconds
            hit: Whether operation was a cache hit (for get operations)
            size: Size of cached data in bytes
        """
        with self.lock:
            # Record operation timing
            self.operation_times[operation].append(duration)
            
            # Track key access patterns
            if operation == 'get':
                self.key_access_patterns[key] += 1
            
            # Record slow operations
            if duration > self.slow_operation_threshold:
                self.slow_operations.append({
                    'operation': operation,
                    'key': key,
                    'duration': duration,
                    'timestamp': datetime.now(),
                    'size': size
                })
                logger.warning(f"Slow cache operation: {operation} on {key} took {duration:.3f}s")
    
    def collect_redis_metrics(self) -> CacheMetrics:
        """
        Collect comprehensive metrics from Redis.
        
        Returns:
            CacheMetrics object with current performance data
        """
        try:
            info = self.redis_conn.info()
            
            # Calculate response time percentiles
            get_times = list(self.operation_times.get('get', []))
            if get_times:
                get_times.sort()
                p95_idx = int(len(get_times) * 0.95)
                p99_idx = int(len(get_times) * 0.99)
                avg_time = sum(get_times) / len(get_times)
                p95_time = get_times[p95_idx] if p95_idx < len(get_times) else 0
                p99_time = get_times[p99_idx] if p99_idx < len(get_times) else 0
            else:
                avg_time = p95_time = p99_time = 0.0
            
            metrics = CacheMetrics(
                hits=info.get('keyspace_hits', 0),
                misses=info.get('keyspace_misses', 0),
                memory_usage=info.get('used_memory', 0),
                response_time_avg=avg_time * 1000,  # Convert to milliseconds
                response_time_p95=p95_time * 1000,
                response_time_p99=p99_time * 1000,
                evictions=info.get('evicted_keys', 0)
            )
            
            # Store in history
            with self.lock:
                self.metrics_history.append(metrics)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to collect Redis metrics: {e}")
            return CacheMetrics()
    
    def get_performance_summary(self, hours_back: int = 24) -> Dict[str, Any]:
        """
        Get comprehensive performance summary for the specified time period.
        
        Args:
            hours_back: Number of hours to look back for metrics
            
        Returns:
            Dictionary with performance summary
        """
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        with self.lock:
            recent_metrics = [
                m for m in self.metrics_history 
                if m.timestamp >= cutoff_time
            ]
        
        if not recent_metrics:
            return {'error': 'No metrics available for the specified time period'}
        
        # Calculate aggregated metrics
        total_hits = sum(m.hits for m in recent_metrics)
        total_misses = sum(m.misses for m in recent_metrics)
        avg_hit_rate = sum(m.hit_rate for m in recent_metrics) / len(recent_metrics)
        avg_response_time = sum(m.response_time_avg for m in recent_metrics) / len(recent_metrics)
        max_memory = max(m.memory_usage for m in recent_metrics)
        
        # Identify performance issues
        issues = self._identify_performance_issues(recent_metrics)
        
        # Get top accessed keys
        top_keys = sorted(
            self.key_access_patterns.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        return {
            'time_period': f'{hours_back} hours',
            'total_operations': total_hits + total_misses,
            'total_hits': total_hits,
            'total_misses': total_misses,
            'average_hit_rate': round(avg_hit_rate, 2),
            'average_response_time_ms': round(avg_response_time, 2),
            'peak_memory_usage_mb': round(max_memory / 1024 / 1024, 2),
            'performance_issues': issues,
            'top_accessed_keys': [{'key': k, 'accesses': v} for k, v in top_keys],
            'slow_operations_count': len(self.slow_operations),
            'metrics_collected': len(recent_metrics)
        }
    
    def _identify_performance_issues(self, metrics: List[CacheMetrics]) -> List[Dict[str, Any]]:
        """
        Identify performance issues from metrics data.
        
        Args:
            metrics: List of CacheMetrics objects
            
        Returns:
            List of identified issues with details
        """
        issues = []
        
        if not metrics:
            return issues
        
        # Check for high miss rates
        high_miss_rate_count = sum(
            1 for m in metrics if m.miss_rate > self.high_miss_rate_threshold
        )
        if high_miss_rate_count > len(metrics) * 0.5:  # More than 50% of samples
            avg_miss_rate = sum(m.miss_rate for m in metrics) / len(metrics)
            issues.append({
                'type': 'high_miss_rate',
                'severity': 'warning',
                'description': f'High cache miss rate detected: {avg_miss_rate:.1f}%',
                'recommendation': 'Consider cache warming or reviewing cache keys'
            })
        
        # Check for slow response times
        slow_response_count = sum(
            1 for m in metrics if m.response_time_p95 > 50  # 50ms
        )
        if slow_response_count > len(metrics) * 0.3:  # More than 30% of samples
            avg_p95 = sum(m.response_time_p95 for m in metrics) / len(metrics)
            issues.append({
                'type': 'slow_response_time',
                'severity': 'warning',
                'description': f'Slow cache response times: P95 = {avg_p95:.1f}ms',
                'recommendation': 'Check Redis server performance and network latency'
            })
        
        # Check for memory pressure
        max_memory = max(m.memory_usage for m in metrics)
        try:
            redis_info = self.redis_conn.info()
            max_memory_limit = redis_info.get('maxmemory', 0)
            if max_memory_limit > 0:
                memory_usage_ratio = max_memory / max_memory_limit
                if memory_usage_ratio > self.memory_warning_threshold:
                    issues.append({
                        'type': 'high_memory_usage',
                        'severity': 'critical' if memory_usage_ratio > 0.95 else 'warning',
                        'description': f'High memory usage: {memory_usage_ratio:.1%} of limit',
                        'recommendation': 'Consider increasing memory limit or implementing cache eviction'
                    })
        except Exception as e:
            logger.error(f"Failed to check memory limits: {e}")
        
        # Check for frequent evictions
        recent_evictions = [m.evictions for m in metrics[-10:]]  # Last 10 samples
        if recent_evictions and max(recent_evictions) > 0:
            total_evictions = sum(recent_evictions)
            issues.append({
                'type': 'cache_evictions',
                'severity': 'warning',
                'description': f'Cache evictions detected: {total_evictions} in recent samples',
                'recommendation': 'Increase cache memory or review cache TTL settings'
            })
        
        return issues
    
    def get_key_access_report(self, top_n: int = 20) -> Dict[str, Any]:
        """
        Generate report on cache key access patterns.
        
        Args:
            top_n: Number of top keys to include in report
            
        Returns:
            Dictionary with key access analysis
        """
        with self.lock:
            sorted_keys = sorted(
                self.key_access_patterns.items(),
                key=lambda x: x[1],
                reverse=True
            )
        
        total_accesses = sum(count for _, count in sorted_keys)
        top_keys = sorted_keys[:top_n]
        
        # Calculate access distribution
        if total_accesses > 0:
            top_keys_accesses = sum(count for _, count in top_keys)
            top_keys_percentage = (top_keys_accesses / total_accesses) * 100
        else:
            top_keys_percentage = 0
        
        return {
            'total_unique_keys': len(sorted_keys),
            'total_accesses': total_accesses,
            'top_keys_count': len(top_keys),
            'top_keys_access_percentage': round(top_keys_percentage, 2),
            'top_keys': [
                {
                    'key': key,
                    'accesses': count,
                    'percentage': round((count / total_accesses) * 100, 2) if total_accesses > 0 else 0
                }
                for key, count in top_keys
            ],
            'access_distribution': self._calculate_access_distribution(sorted_keys)
        }
    
    def _calculate_access_distribution(self, sorted_keys: List[Tuple[str, int]]) -> Dict[str, int]:
        """Calculate distribution of key access patterns."""
        if not sorted_keys:
            return {}
        
        total_keys = len(sorted_keys)
        access_counts = [count for _, count in sorted_keys]
        
        # Define access frequency buckets
        buckets = {
            'very_high': 0,  # Top 1%
            'high': 0,       # Top 5%
            'medium': 0,     # Top 20%
            'low': 0,        # Top 50%
            'very_low': 0    # Bottom 50%
        }
        
        # Calculate bucket thresholds
        very_high_threshold = int(total_keys * 0.01)
        high_threshold = int(total_keys * 0.05)
        medium_threshold = int(total_keys * 0.20)
        low_threshold = int(total_keys * 0.50)
        
        for i, (_, count) in enumerate(sorted_keys):
            if i < very_high_threshold:
                buckets['very_high'] += 1
            elif i < high_threshold:
                buckets['high'] += 1
            elif i < medium_threshold:
                buckets['medium'] += 1
            elif i < low_threshold:
                buckets['low'] += 1
            else:
                buckets['very_low'] += 1
        
        return buckets
    
    def get_slow_operations_report(self) -> Dict[str, Any]:
        """
        Generate report on slow cache operations.
        
        Returns:
            Dictionary with slow operations analysis
        """
        with self.lock:
            slow_ops = list(self.slow_operations)
        
        if not slow_ops:
            return {'message': 'No slow operations recorded'}
        
        # Group by operation type
        ops_by_type = defaultdict(list)
        for op in slow_ops:
            ops_by_type[op['operation']].append(op)
        
        # Calculate statistics for each operation type
        type_stats = {}
        for op_type, ops in ops_by_type.items():
            durations = [op['duration'] for op in ops]
            type_stats[op_type] = {
                'count': len(ops),
                'avg_duration_ms': round(sum(durations) / len(durations) * 1000, 2),
                'max_duration_ms': round(max(durations) * 1000, 2),
                'min_duration_ms': round(min(durations) * 1000, 2)
            }
        
        return {
            'total_slow_operations': len(slow_ops),
            'threshold_ms': self.slow_operation_threshold * 1000,
            'operations_by_type': type_stats,
            'recent_slow_operations': [
                {
                    'operation': op['operation'],
                    'key': op['key'][:50] + '...' if len(op['key']) > 50 else op['key'],
                    'duration_ms': round(op['duration'] * 1000, 2),
                    'timestamp': op['timestamp'].isoformat(),
                    'size_bytes': op.get('size', 'unknown')
                }
                for op in slow_ops[-10:]  # Last 10 slow operations
            ]
        }
    
    def export_metrics(self, format_type: str = 'json') -> str:
        """
        Export collected metrics in specified format.
        
        Args:
            format_type: Export format ('json', 'csv')
            
        Returns:
            Formatted metrics data
        """
        current_metrics = self.collect_redis_metrics()
        performance_summary = self.get_performance_summary()
        key_access_report = self.get_key_access_report()
        slow_ops_report = self.get_slow_operations_report()
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'current_metrics': asdict(current_metrics),
            'performance_summary': performance_summary,
            'key_access_report': key_access_report,
            'slow_operations_report': slow_ops_report
        }
        
        if format_type == 'json':
            return json.dumps(export_data, indent=2, default=str)
        elif format_type == 'csv':
            # Simplified CSV export for metrics history
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow([
                'timestamp', 'hits', 'misses', 'hit_rate', 'memory_usage_mb',
                'response_time_avg_ms', 'response_time_p95_ms', 'evictions'
            ])
            
            # Write metrics data
            with self.lock:
                for metric in self.metrics_history:
                    writer.writerow([
                        metric.timestamp.isoformat(),
                        metric.hits,
                        metric.misses,
                        round(metric.hit_rate, 2),
                        round(metric.memory_usage / 1024 / 1024, 2),
                        round(metric.response_time_avg, 2),
                        round(metric.response_time_p95, 2),
                        metric.evictions
                    ])
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format_type}")


# Global analytics instance
cache_analytics = CacheAnalytics()