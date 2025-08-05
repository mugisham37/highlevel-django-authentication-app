"""
Application performance monitoring with Prometheus metrics and SLA tracking.
Provides comprehensive performance metrics collection, analysis, and alerting.
"""

import logging
import time
import threading
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from django.conf import settings
from django.utils import timezone
import json
import statistics
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Try to import Prometheus client, fall back to mock if not available
try:
    from prometheus_client import Counter, Histogram, Gauge, Summary, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
    PROMETHEUS_AVAILABLE = True
except ImportError:
    logger.warning("Prometheus client not available. Install with: pip install prometheus-client")
    PROMETHEUS_AVAILABLE = False
    
    # Mock classes for when Prometheus is not available
    class MockTimer:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    
    class Counter:
        def __init__(self, *args, **kwargs): pass
        def inc(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    class Histogram:
        def __init__(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
        def time(self): return MockTimer()
    
    class Gauge:
        def __init__(self, *args, **kwargs): pass
        def set(self, *args, **kwargs): pass
        def inc(self, *args, **kwargs): pass
        def dec(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    class Summary:
        def __init__(self, *args, **kwargs): pass
        def observe(self, *args, **kwargs): pass
        def labels(self, *args, **kwargs): return self
    
    def generate_latest(*args, **kwargs): return b""
    CONTENT_TYPE_LATEST = "text/plain"


@dataclass
class PerformanceMetric:
    """Data class for storing performance metrics."""
    name: str
    value: float
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    unit: str = "ms"


@dataclass
class SLATarget:
    """Data class for SLA target configuration."""
    name: str
    target_value: float
    comparison: str  # 'lt', 'gt', 'eq'
    unit: str = "ms"
    description: str = ""


class PerformanceCollector:
    """
    Collects and manages performance metrics with Prometheus integration.
    """
    
    def __init__(self):
        self.registry = CollectorRegistry() if PROMETHEUS_AVAILABLE else None
        self._setup_metrics()
        self._metrics_buffer = deque(maxlen=10000)
        self._lock = threading.Lock()
        
    def _setup_metrics(self):
        """Initialize Prometheus metrics."""
        if not PROMETHEUS_AVAILABLE:
            return
            
        # Request metrics
        self.request_duration = Histogram(
            'django_request_duration_seconds',
            'Time spent processing requests',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry,
            buckets=[0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0]
        )
        
        self.request_count = Counter(
            'django_requests_total',
            'Total number of requests',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry
        )
        
        # Authentication metrics
        self.auth_duration = Histogram(
            'auth_operation_duration_seconds',
            'Time spent on authentication operations',
            ['operation', 'provider', 'status'],
            registry=self.registry
        )
        
        self.auth_count = Counter(
            'auth_operations_total',
            'Total number of authentication operations',
            ['operation', 'provider', 'status'],
            registry=self.registry
        )
        
        # Database metrics
        self.db_query_duration = Histogram(
            'database_query_duration_seconds',
            'Time spent on database queries',
            ['query_type', 'table'],
            registry=self.registry
        )
        
        self.db_connection_pool = Gauge(
            'database_connection_pool_size',
            'Current database connection pool size',
            ['pool_name'],
            registry=self.registry
        )
        
        # Cache metrics
        self.cache_operations = Counter(
            'cache_operations_total',
            'Total number of cache operations',
            ['operation', 'cache_name', 'status'],
            registry=self.registry
        )
        
        self.cache_hit_rate = Gauge(
            'cache_hit_rate_percent',
            'Cache hit rate percentage',
            ['cache_name'],
            registry=self.registry
        )
        
        # Session metrics
        self.active_sessions = Gauge(
            'active_sessions_total',
            'Number of active user sessions',
            registry=self.registry
        )
        
        self.session_duration = Histogram(
            'session_duration_seconds',
            'User session duration',
            ['termination_reason'],
            registry=self.registry
        )
        
        # Security metrics
        self.security_events = Counter(
            'security_events_total',
            'Total number of security events',
            ['event_type', 'severity'],
            registry=self.registry
        )
        
        self.failed_auth_attempts = Counter(
            'failed_auth_attempts_total',
            'Total number of failed authentication attempts',
            ['reason', 'ip_address'],
            registry=self.registry
        )
        
        # System metrics
        self.system_health = Gauge(
            'system_health_score',
            'Overall system health score (0-100)',
            registry=self.registry
        )
        
        self.response_time_sla = Gauge(
            'response_time_sla_compliance_percent',
            'SLA compliance percentage for response times',
            ['endpoint'],
            registry=self.registry
        )
    
    def record_request_duration(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record HTTP request duration."""
        if PROMETHEUS_AVAILABLE:
            self.request_duration.labels(
                method=method, 
                endpoint=endpoint, 
                status_code=str(status_code)
            ).observe(duration)
            
            self.request_count.labels(
                method=method, 
                endpoint=endpoint, 
                status_code=str(status_code)
            ).inc()
        
        # Store in buffer for analysis
        with self._lock:
            self._metrics_buffer.append(PerformanceMetric(
                name='request_duration',
                value=duration * 1000,  # Convert to ms
                timestamp=timezone.now(),
                labels={
                    'method': method,
                    'endpoint': endpoint,
                    'status_code': str(status_code)
                }
            ))
    
    def record_auth_operation(self, operation: str, provider: str, status: str, duration: float):
        """Record authentication operation metrics."""
        if PROMETHEUS_AVAILABLE:
            self.auth_duration.labels(
                operation=operation,
                provider=provider,
                status=status
            ).observe(duration)
            
            self.auth_count.labels(
                operation=operation,
                provider=provider,
                status=status
            ).inc()
    
    def record_db_query(self, query_type: str, table: str, duration: float):
        """Record database query metrics."""
        if PROMETHEUS_AVAILABLE:
            self.db_query_duration.labels(
                query_type=query_type,
                table=table
            ).observe(duration)
    
    def record_cache_operation(self, operation: str, cache_name: str, status: str):
        """Record cache operation metrics."""
        if PROMETHEUS_AVAILABLE:
            self.cache_operations.labels(
                operation=operation,
                cache_name=cache_name,
                status=status
            ).inc()
    
    def update_cache_hit_rate(self, cache_name: str, hit_rate: float):
        """Update cache hit rate metric."""
        if PROMETHEUS_AVAILABLE:
            self.cache_hit_rate.labels(cache_name=cache_name).set(hit_rate)
    
    def update_active_sessions(self, count: int):
        """Update active sessions count."""
        if PROMETHEUS_AVAILABLE:
            self.active_sessions.set(count)
    
    def record_security_event(self, event_type: str, severity: str):
        """Record security event."""
        if PROMETHEUS_AVAILABLE:
            self.security_events.labels(
                event_type=event_type,
                severity=severity
            ).inc()
    
    def record_failed_auth(self, reason: str, ip_address: str):
        """Record failed authentication attempt."""
        if PROMETHEUS_AVAILABLE:
            self.failed_auth_attempts.labels(
                reason=reason,
                ip_address=ip_address
            ).inc()
    
    def update_system_health(self, score: float):
        """Update system health score."""
        if PROMETHEUS_AVAILABLE:
            self.system_health.set(score)
    
    def update_sla_compliance(self, endpoint: str, compliance_percent: float):
        """Update SLA compliance percentage."""
        if PROMETHEUS_AVAILABLE:
            self.response_time_sla.labels(endpoint=endpoint).set(compliance_percent)
    
    def get_metrics_data(self) -> bytes:
        """Get Prometheus metrics data."""
        if PROMETHEUS_AVAILABLE:
            return generate_latest(self.registry)
        return b""
    
    def get_recent_metrics(self, minutes: int = 5) -> List[PerformanceMetric]:
        """Get recent metrics from buffer."""
        cutoff_time = timezone.now() - timedelta(minutes=minutes)
        with self._lock:
            return [m for m in self._metrics_buffer if m.timestamp >= cutoff_time]


class SLAMonitor:
    """
    Monitors SLA compliance and generates alerts.
    """
    
    def __init__(self, collector: PerformanceCollector):
        self.collector = collector
        self.sla_targets = {}
        self.violations = deque(maxlen=1000)
        self._setup_default_slas()
    
    def _setup_default_slas(self):
        """Setup default SLA targets."""
        self.add_sla_target(SLATarget(
            name='api_response_time',
            target_value=100.0,  # 100ms
            comparison='lt',
            unit='ms',
            description='API endpoints should respond within 100ms'
        ))
        
        self.add_sla_target(SLATarget(
            name='auth_response_time',
            target_value=200.0,  # 200ms
            comparison='lt',
            unit='ms',
            description='Authentication operations should complete within 200ms'
        ))
        
        self.add_sla_target(SLATarget(
            name='cache_hit_rate',
            target_value=85.0,  # 85%
            comparison='gt',
            unit='%',
            description='Cache hit rate should be above 85%'
        ))
        
        self.add_sla_target(SLATarget(
            name='system_availability',
            target_value=99.9,  # 99.9%
            comparison='gt',
            unit='%',
            description='System availability should be above 99.9%'
        ))
    
    def add_sla_target(self, target: SLATarget):
        """Add SLA target for monitoring."""
        self.sla_targets[target.name] = target
        logger.info(f"Added SLA target: {target.name} - {target.description}")
    
    def check_sla_compliance(self, metric_name: str, value: float, labels: Dict[str, str] = None) -> bool:
        """
        Check if a metric value meets SLA requirements.
        
        Args:
            metric_name: Name of the metric to check
            value: Current metric value
            labels: Additional labels for context
            
        Returns:
            True if SLA is met, False otherwise
        """
        if metric_name not in self.sla_targets:
            return True  # No SLA defined, assume compliant
        
        target = self.sla_targets[metric_name]
        
        if target.comparison == 'lt':
            compliant = value < target.target_value
        elif target.comparison == 'gt':
            compliant = value > target.target_value
        elif target.comparison == 'eq':
            compliant = abs(value - target.target_value) < 0.01
        else:
            logger.error(f"Unknown comparison operator: {target.comparison}")
            return True
        
        if not compliant:
            violation = {
                'metric_name': metric_name,
                'target_value': target.target_value,
                'actual_value': value,
                'comparison': target.comparison,
                'labels': labels or {},
                'timestamp': timezone.now(),
                'description': target.description
            }
            self.violations.append(violation)
            logger.warning(f"SLA violation: {metric_name} = {value}{target.unit}, target: {target.comparison} {target.target_value}{target.unit}")
        
        return compliant
    
    def get_sla_compliance_report(self, hours: int = 24) -> Dict[str, Any]:
        """
        Generate SLA compliance report for the specified time period.
        
        Args:
            hours: Number of hours to analyze
            
        Returns:
            Dictionary with compliance statistics
        """
        cutoff_time = timezone.now() - timedelta(hours=hours)
        recent_violations = [v for v in self.violations if v['timestamp'] >= cutoff_time]
        
        # Group violations by metric
        violations_by_metric = defaultdict(list)
        for violation in recent_violations:
            violations_by_metric[violation['metric_name']].append(violation)
        
        # Calculate compliance percentages
        compliance_report = {}
        for metric_name, target in self.sla_targets.items():
            violations = violations_by_metric.get(metric_name, [])
            
            # Get recent metrics for this SLA
            recent_metrics = self.collector.get_recent_metrics(minutes=hours * 60)
            relevant_metrics = [m for m in recent_metrics if m.name == metric_name]
            
            total_measurements = len(relevant_metrics)
            violation_count = len(violations)
            
            if total_measurements > 0:
                compliance_percent = ((total_measurements - violation_count) / total_measurements) * 100
            else:
                compliance_percent = 100.0  # No data means no violations
            
            compliance_report[metric_name] = {
                'target': target.target_value,
                'unit': target.unit,
                'comparison': target.comparison,
                'description': target.description,
                'compliance_percent': round(compliance_percent, 2),
                'total_measurements': total_measurements,
                'violations': violation_count,
                'recent_violations': violations[-5:] if violations else []  # Last 5 violations
            }
        
        return {
            'report_period_hours': hours,
            'generated_at': timezone.now().isoformat(),
            'overall_compliance': round(
                sum(r['compliance_percent'] for r in compliance_report.values()) / len(compliance_report)
                if compliance_report else 100.0, 2
            ),
            'metrics': compliance_report
        }


class PerformanceBenchmark:
    """
    Handles performance benchmarking and load testing coordination.
    """
    
    def __init__(self, collector: PerformanceCollector):
        self.collector = collector
        self.benchmark_results = {}
        self.baseline_metrics = {}
    
    def set_baseline(self, metric_name: str, value: float, labels: Dict[str, str] = None):
        """Set baseline performance metric."""
        self.baseline_metrics[metric_name] = {
            'value': value,
            'labels': labels or {},
            'timestamp': timezone.now()
        }
        logger.info(f"Set baseline for {metric_name}: {value}")
    
    def run_benchmark(self, name: str, test_function: Callable, iterations: int = 100) -> Dict[str, Any]:
        """
        Run performance benchmark test.
        
        Args:
            name: Benchmark name
            test_function: Function to benchmark
            iterations: Number of iterations to run
            
        Returns:
            Benchmark results
        """
        logger.info(f"Running benchmark: {name} ({iterations} iterations)")
        
        durations = []
        errors = 0
        
        for i in range(iterations):
            start_time = time.time()
            try:
                test_function()
                duration = (time.time() - start_time) * 1000  # Convert to ms
                durations.append(duration)
            except Exception as e:
                errors += 1
                logger.error(f"Benchmark iteration {i} failed: {e}")
        
        if durations:
            results = {
                'name': name,
                'iterations': iterations,
                'successful_iterations': len(durations),
                'errors': errors,
                'min_duration_ms': min(durations),
                'max_duration_ms': max(durations),
                'avg_duration_ms': statistics.mean(durations),
                'median_duration_ms': statistics.median(durations),
                'p95_duration_ms': self._percentile(durations, 95),
                'p99_duration_ms': self._percentile(durations, 99),
                'std_deviation_ms': statistics.stdev(durations) if len(durations) > 1 else 0,
                'timestamp': timezone.now().isoformat()
            }
        else:
            results = {
                'name': name,
                'iterations': iterations,
                'successful_iterations': 0,
                'errors': errors,
                'error': 'All iterations failed',
                'timestamp': timezone.now().isoformat()
            }
        
        self.benchmark_results[name] = results
        logger.info(f"Benchmark {name} completed: avg={results.get('avg_duration_ms', 'N/A')}ms")
        
        return results
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile value."""
        if not data:
            return 0.0
        
        sorted_data = sorted(data)
        index = (percentile / 100) * (len(sorted_data) - 1)
        
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))
    
    def compare_with_baseline(self, metric_name: str, current_value: float) -> Dict[str, Any]:
        """Compare current metric with baseline."""
        if metric_name not in self.baseline_metrics:
            return {'error': f'No baseline set for {metric_name}'}
        
        baseline = self.baseline_metrics[metric_name]
        difference = current_value - baseline['value']
        percent_change = (difference / baseline['value']) * 100 if baseline['value'] != 0 else 0
        
        return {
            'metric_name': metric_name,
            'baseline_value': baseline['value'],
            'current_value': current_value,
            'difference': difference,
            'percent_change': round(percent_change, 2),
            'performance_trend': 'improved' if difference < 0 else 'degraded' if difference > 0 else 'stable',
            'baseline_timestamp': baseline['timestamp'].isoformat(),
            'comparison_timestamp': timezone.now().isoformat()
        }


class PerformanceAlerting:
    """
    Handles performance alerting and notifications.
    """
    
    def __init__(self, sla_monitor: SLAMonitor):
        self.sla_monitor = sla_monitor
        self.alert_thresholds = {}
        self.alert_history = deque(maxlen=1000)
        self.alert_cooldowns = {}  # Prevent alert spam
    
    def set_alert_threshold(self, metric_name: str, threshold: float, comparison: str = 'gt'):
        """Set alert threshold for a metric."""
        self.alert_thresholds[metric_name] = {
            'threshold': threshold,
            'comparison': comparison
        }
        logger.info(f"Set alert threshold for {metric_name}: {comparison} {threshold}")
    
    def check_alert_conditions(self, metric_name: str, value: float, labels: Dict[str, str] = None):
        """Check if metric value triggers an alert."""
        if metric_name not in self.alert_thresholds:
            return
        
        threshold_config = self.alert_thresholds[metric_name]
        threshold = threshold_config['threshold']
        comparison = threshold_config['comparison']
        
        should_alert = False
        if comparison == 'gt' and value > threshold:
            should_alert = True
        elif comparison == 'lt' and value < threshold:
            should_alert = True
        elif comparison == 'eq' and abs(value - threshold) < 0.01:
            should_alert = True
        
        if should_alert:
            # Check cooldown to prevent spam
            cooldown_key = f"{metric_name}:{json.dumps(labels or {}, sort_keys=True)}"
            now = timezone.now()
            
            if cooldown_key in self.alert_cooldowns:
                last_alert = self.alert_cooldowns[cooldown_key]
                if now - last_alert < timedelta(minutes=5):  # 5-minute cooldown
                    return
            
            self.alert_cooldowns[cooldown_key] = now
            self._send_alert(metric_name, value, threshold, comparison, labels)
    
    def _send_alert(self, metric_name: str, value: float, threshold: float, 
                   comparison: str, labels: Dict[str, str] = None):
        """Send performance alert."""
        alert = {
            'metric_name': metric_name,
            'current_value': value,
            'threshold': threshold,
            'comparison': comparison,
            'labels': labels or {},
            'timestamp': timezone.now(),
            'severity': self._determine_severity(metric_name, value, threshold)
        }
        
        self.alert_history.append(alert)
        
        # Log the alert
        logger.warning(
            f"Performance alert: {metric_name} = {value}, threshold: {comparison} {threshold}"
        )
        
        # Here you would integrate with your alerting system (email, Slack, PagerDuty, etc.)
        self._notify_alert_channels(alert)
    
    def _determine_severity(self, metric_name: str, value: float, threshold: float) -> str:
        """Determine alert severity based on how far the value exceeds the threshold."""
        if metric_name in ['response_time', 'auth_duration']:
            if value > threshold * 2:
                return 'critical'
            elif value > threshold * 1.5:
                return 'high'
            else:
                return 'medium'
        
        return 'medium'  # Default severity
    
    def _notify_alert_channels(self, alert: Dict[str, Any]):
        """Send alert to configured notification channels."""
        # This would integrate with your notification system
        # For now, we'll just log it
        logger.error(f"PERFORMANCE ALERT: {alert}")


# Global performance monitoring instances
performance_collector = PerformanceCollector()
sla_monitor = SLAMonitor(performance_collector)
performance_benchmark = PerformanceBenchmark(performance_collector)
performance_alerting = PerformanceAlerting(sla_monitor)


@contextmanager
def monitor_performance(operation_name: str, labels: Dict[str, str] = None):
    """Context manager for monitoring operation performance."""
    start_time = time.time()
    labels = labels or {}
    
    try:
        yield
        duration = time.time() - start_time
        
        # Record the metric
        performance_collector.record_auth_operation(
            operation=operation_name,
            provider=labels.get('provider', 'unknown'),
            status='success',
            duration=duration
        )
        
        # Check SLA compliance
        sla_monitor.check_sla_compliance(
            f"{operation_name}_duration",
            duration * 1000,  # Convert to ms
            labels
        )
        
        # Check alert conditions
        performance_alerting.check_alert_conditions(
            f"{operation_name}_duration",
            duration * 1000,
            labels
        )
        
    except Exception as e:
        duration = time.time() - start_time
        
        # Record failed operation
        performance_collector.record_auth_operation(
            operation=operation_name,
            provider=labels.get('provider', 'unknown'),
            status='error',
            duration=duration
        )
        
        raise