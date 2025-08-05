"""
Performance monitoring middleware.
Tracks request performance, database queries, and cache operations.
"""

import logging
import time
import threading
from typing import Dict, Any, Optional
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpRequest, HttpResponse
from django.db import connection
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from ..monitoring.performance import performance_collector, sla_monitor, performance_alerting, monitor_performance
from ..utils.correlation import get_correlation_id

logger = logging.getLogger(__name__)


class PerformanceMonitoringMiddleware(MiddlewareMixin):
    """
    Middleware to monitor request performance and collect metrics.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        self._local = threading.local()
        
        # Performance thresholds
        self.slow_request_threshold = getattr(settings, 'SLOW_REQUEST_THRESHOLD', 1.0)  # seconds
        self.very_slow_request_threshold = getattr(settings, 'VERY_SLOW_REQUEST_THRESHOLD', 5.0)  # seconds
        
        # Enable/disable monitoring
        self.monitoring_enabled = getattr(settings, 'PERFORMANCE_MONITORING_ENABLED', True)
        
        # Endpoints to exclude from monitoring
        self.excluded_paths = getattr(settings, 'PERFORMANCE_MONITORING_EXCLUDED_PATHS', [
            '/health/', '/metrics/', '/static/', '/media/'
        ])
    
    def process_request(self, request: HttpRequest):
        """Process incoming request and start performance monitoring."""
        if not self.monitoring_enabled or self._should_exclude_path(request.path):
            return None
        
        # Initialize request tracking
        self._local.start_time = time.time()
        self._local.db_queries_start = len(connection.queries)
        self._local.request_path = request.path
        self._local.request_method = request.method
        self._local.correlation_id = get_correlation_id()
        
        # Track request start
        logger.debug(f"Request started: {request.method} {request.path} [{self._local.correlation_id}]")
        
        return None
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Process response and record performance metrics."""
        if not self.monitoring_enabled or not hasattr(self._local, 'start_time'):
            return response
        
        try:
            # Calculate request duration
            duration = time.time() - self._local.start_time
            
            # Get database query count
            db_queries_count = len(connection.queries) - self._local.db_queries_start
            
            # Extract endpoint information
            endpoint = self._extract_endpoint_name(request)
            method = self._local.request_method
            status_code = response.status_code
            
            # Record metrics
            self._record_request_metrics(method, endpoint, status_code, duration, db_queries_count)
            
            # Check for performance issues
            self._check_performance_issues(request, duration, db_queries_count, status_code)
            
            # Add performance headers (if enabled)
            if getattr(settings, 'ADD_PERFORMANCE_HEADERS', False):
                response['X-Response-Time'] = f"{duration:.3f}s"
                response['X-DB-Queries'] = str(db_queries_count)
                response['X-Correlation-ID'] = self._local.correlation_id
            
            logger.debug(f"Request completed: {method} {endpoint} - {duration:.3f}s, "
                        f"{db_queries_count} queries, status {status_code}")
            
        except Exception as e:
            logger.error(f"Error in performance monitoring middleware: {e}")
        
        return response
    
    def process_exception(self, request: HttpRequest, exception: Exception) -> Optional[HttpResponse]:
        """Process exceptions and record error metrics."""
        if not self.monitoring_enabled or not hasattr(self._local, 'start_time'):
            return None
        
        try:
            duration = time.time() - self._local.start_time
            endpoint = self._extract_endpoint_name(request)
            method = self._local.request_method
            
            # Record error metrics
            performance_collector.record_request_duration(method, endpoint, 500, duration)
            
            # Log performance data for failed requests
            logger.error(f"Request failed: {method} {endpoint} - {duration:.3f}s, "
                        f"Exception: {type(exception).__name__}: {exception}")
            
        except Exception as e:
            logger.error(f"Error recording exception metrics: {e}")
        
        return None
    
    def _should_exclude_path(self, path: str) -> bool:
        """Check if path should be excluded from monitoring."""
        return any(path.startswith(excluded) for excluded in self.excluded_paths)
    
    def _extract_endpoint_name(self, request: HttpRequest) -> str:
        """Extract a normalized endpoint name from the request."""
        path = request.path
        
        # Remove trailing slash
        if path.endswith('/') and len(path) > 1:
            path = path[:-1]
        
        # Replace dynamic segments with placeholders
        path_parts = path.split('/')
        normalized_parts = []
        
        for part in path_parts:
            if not part:
                continue
            
            # Replace UUIDs with placeholder
            if self._is_uuid(part):
                normalized_parts.append('{uuid}')
            # Replace numeric IDs with placeholder
            elif part.isdigit():
                normalized_parts.append('{id}')
            # Replace other dynamic segments (heuristic)
            elif len(part) > 20 and not part.isalpha():
                normalized_parts.append('{dynamic}')
            else:
                normalized_parts.append(part)
        
        return '/' + '/'.join(normalized_parts) if normalized_parts else '/'
    
    def _is_uuid(self, value: str) -> bool:
        """Check if a string looks like a UUID."""
        import re
        uuid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        return bool(uuid_pattern.match(value))
    
    def _record_request_metrics(self, method: str, endpoint: str, status_code: int, 
                               duration: float, db_queries_count: int):
        """Record request performance metrics."""
        # Record basic request metrics
        performance_collector.record_request_duration(method, endpoint, status_code, duration)
        
        # Record database query metrics if significant
        if db_queries_count > 0:
            avg_query_time = duration / db_queries_count if db_queries_count > 0 else 0
            performance_collector.record_db_query('mixed', 'multiple', avg_query_time)
        
        # Check SLA compliance
        duration_ms = duration * 1000
        sla_monitor.check_sla_compliance('api_response_time', duration_ms, {
            'endpoint': endpoint,
            'method': method
        })
        
        # Update SLA compliance metrics
        is_compliant = duration_ms < 100  # 100ms SLA
        compliance_percent = 100 if is_compliant else 0
        performance_collector.update_sla_compliance(endpoint, compliance_percent)
        
        # Check alert conditions
        performance_alerting.check_alert_conditions('response_time', duration_ms, {
            'endpoint': endpoint,
            'method': method,
            'status_code': str(status_code)
        })
    
    def _check_performance_issues(self, request: HttpRequest, duration: float, 
                                 db_queries_count: int, status_code: int):
        """Check for various performance issues and log warnings."""
        issues = []
        
        # Slow request detection
        if duration > self.very_slow_request_threshold:
            issues.append(f"Very slow request: {duration:.3f}s (threshold: {self.very_slow_request_threshold}s)")
        elif duration > self.slow_request_threshold:
            issues.append(f"Slow request: {duration:.3f}s (threshold: {self.slow_request_threshold}s)")
        
        # N+1 query detection
        if db_queries_count > 10:
            issues.append(f"High database query count: {db_queries_count} queries (potential N+1 problem)")
        
        # Large response detection (if content-length is available)
        content_length = request.META.get('CONTENT_LENGTH')
        if content_length and int(content_length) > 1024 * 1024:  # 1MB
            issues.append(f"Large request body: {int(content_length) / 1024 / 1024:.1f}MB")
        
        # Error status codes
        if status_code >= 500:
            issues.append(f"Server error: HTTP {status_code}")
        elif status_code >= 400:
            issues.append(f"Client error: HTTP {status_code}")
        
        # Log issues if any found
        if issues:
            endpoint = self._extract_endpoint_name(request)
            logger.warning(f"Performance issues detected for {request.method} {endpoint}: {'; '.join(issues)}")
            
            # Record performance issue metrics
            for issue in issues:
                if 'slow' in issue.lower():
                    performance_collector.record_security_event('slow_request', 'medium')
                elif 'query' in issue.lower():
                    performance_collector.record_security_event('high_db_usage', 'low')


class DatabaseQueryMonitoringMiddleware(MiddlewareMixin):
    """
    Middleware specifically for monitoring database query performance.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        self._local = threading.local()
        
        # Query monitoring settings
        self.slow_query_threshold = getattr(settings, 'SLOW_QUERY_THRESHOLD', 1.0)  # seconds
        self.monitor_all_queries = getattr(settings, 'MONITOR_ALL_DB_QUERIES', False)
    
    def process_request(self, request: HttpRequest):
        """Initialize query monitoring for the request."""
        if not self.monitor_all_queries:
            return None
        
        self._local.initial_queries = len(connection.queries)
        self._local.query_start_time = time.time()
        
        return None
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Analyze database queries executed during the request."""
        if not self.monitor_all_queries or not hasattr(self._local, 'initial_queries'):
            return response
        
        try:
            # Get queries executed during this request
            current_queries = connection.queries[self._local.initial_queries:]
            
            # Analyze each query
            for query_data in current_queries:
                query_time = float(query_data['time'])
                sql = query_data['sql']
                
                # Record query metrics
                self._analyze_query(sql, query_time)
                
                # Log slow queries
                if query_time >= self.slow_query_threshold:
                    logger.warning(f"Slow query detected: {query_time:.3f}s - {sql[:200]}...")
            
            # Record overall query statistics
            total_query_time = sum(float(q['time']) for q in current_queries)
            query_count = len(current_queries)
            
            if query_count > 0:
                avg_query_time = total_query_time / query_count
                performance_collector.record_db_query('request_batch', 'multiple', avg_query_time)
            
        except Exception as e:
            logger.error(f"Error in database query monitoring: {e}")
        
        return response
    
    def _analyze_query(self, sql: str, duration: float):
        """Analyze individual database query."""
        # Determine query type
        sql_upper = sql.upper().strip()
        if sql_upper.startswith('SELECT'):
            query_type = 'SELECT'
        elif sql_upper.startswith('INSERT'):
            query_type = 'INSERT'
        elif sql_upper.startswith('UPDATE'):
            query_type = 'UPDATE'
        elif sql_upper.startswith('DELETE'):
            query_type = 'DELETE'
        else:
            query_type = 'OTHER'
        
        # Extract table name (simplified)
        table_name = self._extract_table_name(sql)
        
        # Record query metrics
        performance_collector.record_db_query(query_type, table_name, duration)
        
        # Analyze query for common issues
        issues = self._detect_query_issues(sql, duration)
        if issues:
            logger.debug(f"Query issues detected: {', '.join(issues)} - {sql[:100]}...")
    
    def _extract_table_name(self, sql: str) -> str:
        """Extract primary table name from SQL query."""
        import re
        
        # Simple regex to extract table name (this could be more sophisticated)
        patterns = [
            r'FROM\s+([`"]?)(\w+)\1',  # SELECT ... FROM table
            r'UPDATE\s+([`"]?)(\w+)\1',  # UPDATE table
            r'INSERT\s+INTO\s+([`"]?)(\w+)\1',  # INSERT INTO table
            r'DELETE\s+FROM\s+([`"]?)(\w+)\1',  # DELETE FROM table
        ]
        
        sql_upper = sql.upper()
        for pattern in patterns:
            match = re.search(pattern, sql_upper)
            if match:
                return match.group(2).lower()
        
        return 'unknown'
    
    def _detect_query_issues(self, sql: str, duration: float) -> list:
        """Detect common query performance issues."""
        issues = []
        sql_upper = sql.upper()
        
        # Check for SELECT *
        if 'SELECT *' in sql_upper:
            issues.append('select_all_columns')
        
        # Check for missing WHERE clause in SELECT
        if sql_upper.startswith('SELECT') and 'WHERE' not in sql_upper and 'LIMIT' not in sql_upper:
            issues.append('missing_where_clause')
        
        # Check for missing LIMIT in potentially large result sets
        if sql_upper.startswith('SELECT') and 'LIMIT' not in sql_upper and duration > 0.1:
            issues.append('missing_limit')
        
        # Check for complex JOINs
        join_count = sql_upper.count('JOIN')
        if join_count > 3:
            issues.append('complex_joins')
        
        # Check for subqueries
        if sql_upper.count('SELECT') > 1:
            issues.append('subqueries')
        
        return issues


class CacheMonitoringMiddleware(MiddlewareMixin):
    """
    Middleware to monitor cache operations during request processing.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        self._local = threading.local()
        
        # Monkey patch cache operations to track them
        self._patch_cache_operations()
    
    def _patch_cache_operations(self):
        """Patch cache operations to monitor them."""
        # This is a simplified approach - in production you might use a more sophisticated method
        original_get = cache.get
        original_set = cache.set
        original_delete = cache.delete
        
        def monitored_get(key, default=None, version=None):
            start_time = time.time()
            result = original_get(key, default, version)
            duration = time.time() - start_time
            
            status = 'hit' if result is not None else 'miss'
            performance_collector.record_cache_operation('get', 'default', status)
            
            if hasattr(self._local, 'cache_operations'):
                self._local.cache_operations.append({
                    'operation': 'get',
                    'key': key,
                    'status': status,
                    'duration': duration
                })
            
            return result
        
        def monitored_set(key, value, timeout=None, version=None):
            start_time = time.time()
            result = original_set(key, value, timeout, version)
            duration = time.time() - start_time
            
            performance_collector.record_cache_operation('set', 'default', 'success')
            
            if hasattr(self._local, 'cache_operations'):
                self._local.cache_operations.append({
                    'operation': 'set',
                    'key': key,
                    'status': 'success',
                    'duration': duration
                })
            
            return result
        
        def monitored_delete(key, version=None):
            start_time = time.time()
            result = original_delete(key, version)
            duration = time.time() - start_time
            
            performance_collector.record_cache_operation('delete', 'default', 'success')
            
            if hasattr(self._local, 'cache_operations'):
                self._local.cache_operations.append({
                    'operation': 'delete',
                    'key': key,
                    'status': 'success',
                    'duration': duration
                })
            
            return result
        
        # Apply patches
        cache.get = monitored_get
        cache.set = monitored_set
        cache.delete = monitored_delete
    
    def process_request(self, request: HttpRequest):
        """Initialize cache operation tracking."""
        self._local.cache_operations = []
        return None
    
    def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
        """Analyze cache operations performed during the request."""
        if not hasattr(self._local, 'cache_operations'):
            return response
        
        try:
            operations = self._local.cache_operations
            
            if operations:
                # Calculate cache statistics for this request
                total_operations = len(operations)
                cache_hits = sum(1 for op in operations if op['status'] == 'hit')
                cache_misses = sum(1 for op in operations if op['status'] == 'miss')
                
                hit_rate = (cache_hits / (cache_hits + cache_misses) * 100) if (cache_hits + cache_misses) > 0 else 0
                
                # Log cache performance for this request
                if total_operations > 10:  # Only log for requests with significant cache usage
                    endpoint = self._extract_endpoint_name(request)
                    logger.debug(f"Cache usage for {request.method} {endpoint}: "
                               f"{total_operations} operations, {hit_rate:.1f}% hit rate")
                
                # Update cache hit rate metric
                performance_collector.update_cache_hit_rate('request_level', hit_rate)
        
        except Exception as e:
            logger.error(f"Error in cache monitoring middleware: {e}")
        
        return response
    
    def _extract_endpoint_name(self, request: HttpRequest) -> str:
        """Extract endpoint name (simplified version)."""
        path = request.path
        if path.endswith('/') and len(path) > 1:
            path = path[:-1]
        return path or '/'