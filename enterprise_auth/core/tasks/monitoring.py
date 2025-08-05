"""
Celery task monitoring and failure handling.
Provides comprehensive task monitoring, retry logic, and failure analysis.
"""

import logging
import time
import json
import threading
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict, deque
from celery import Task
from celery.signals import (
    task_prerun, task_postrun, task_failure, task_retry, task_success,
    worker_ready, worker_shutdown
)
from celery.exceptions import Retry, WorkerLostError
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache

logger = logging.getLogger(__name__)


class TaskMetrics:
    """
    Collects and manages Celery task metrics.
    """
    
    def __init__(self):
        self.task_stats = defaultdict(lambda: {
            'total_runs': 0,
            'successful_runs': 0,
            'failed_runs': 0,
            'retry_runs': 0,
            'total_runtime': 0,
            'avg_runtime': 0,
            'max_runtime': 0,
            'min_runtime': float('inf'),
            'last_run': None,
            'last_success': None,
            'last_failure': None,
            'failure_rate': 0.0
        })
        self.recent_tasks = deque(maxlen=1000)
        self.failed_tasks = deque(maxlen=500)
        self.slow_tasks = deque(maxlen=200)
        self._lock = threading.Lock()
        
        # Connect to Celery signals
        self._connect_signals()
    
    def _connect_signals(self):
        """Connect to Celery signals for automatic monitoring."""
        task_prerun.connect(self._on_task_prerun)
        task_postrun.connect(self._on_task_postrun)
        task_failure.connect(self._on_task_failure)
        task_retry.connect(self._on_task_retry)
        task_success.connect(self._on_task_success)
    
    def _on_task_prerun(self, sender=None, task_id=None, task=None, args=None, kwargs=None, **kwds):
        """Handle task prerun signal."""
        task_info = {
            'task_id': task_id,
            'task_name': task.name if task else sender,
            'start_time': time.time(),
            'args': args,
            'kwargs': kwargs,
            'status': 'running'
        }
        
        # Store task start info in cache for duration calculation
        cache.set(f"task_start:{task_id}", task_info, timeout=3600)
    
    def _on_task_postrun(self, sender=None, task_id=None, task=None, args=None, kwargs=None, 
                        retval=None, state=None, **kwds):
        """Handle task postrun signal."""
        task_start_info = cache.get(f"task_start:{task_id}")
        if not task_start_info:
            return
        
        duration = time.time() - task_start_info['start_time']
        task_name = task.name if task else sender
        
        # Update task statistics
        with self._lock:
            stats = self.task_stats[task_name]
            stats['total_runs'] += 1
            stats['total_runtime'] += duration
            stats['avg_runtime'] = stats['total_runtime'] / stats['total_runs']
            stats['max_runtime'] = max(stats['max_runtime'], duration)
            stats['min_runtime'] = min(stats['min_runtime'], duration)
            stats['last_run'] = timezone.now()
            
            # Calculate failure rate
            if stats['total_runs'] > 0:
                stats['failure_rate'] = (stats['failed_runs'] / stats['total_runs']) * 100
        
        # Record task execution
        task_record = {
            'task_id': task_id,
            'task_name': task_name,
            'duration': duration,
            'state': state,
            'timestamp': timezone.now(),
            'args_count': len(args) if args else 0,
            'kwargs_count': len(kwargs) if kwargs else 0
        }
        
        self.recent_tasks.append(task_record)
        
        # Check for slow tasks
        slow_threshold = getattr(settings, 'CELERY_SLOW_TASK_THRESHOLD', 30.0)  # 30 seconds
        if duration > slow_threshold:
            slow_task = {
                **task_record,
                'threshold': slow_threshold,
                'analysis': self._analyze_slow_task(task_name, duration, args, kwargs)
            }
            self.slow_tasks.append(slow_task)
            logger.warning(f"Slow task detected: {task_name} took {duration:.2f}s")
        
        # Clean up cache
        cache.delete(f"task_start:{task_id}")
    
    def _on_task_success(self, sender=None, result=None, **kwds):
        """Handle task success signal."""
        task_name = sender
        with self._lock:
            stats = self.task_stats[task_name]
            stats['successful_runs'] += 1
            stats['last_success'] = timezone.now()
    
    def _on_task_failure(self, sender=None, task_id=None, exception=None, traceback=None, einfo=None, **kwds):
        """Handle task failure signal."""
        task_name = sender
        
        with self._lock:
            stats = self.task_stats[task_name]
            stats['failed_runs'] += 1
            stats['last_failure'] = timezone.now()
        
        # Record failure details
        failure_record = {
            'task_id': task_id,
            'task_name': task_name,
            'exception': str(exception) if exception else 'Unknown error',
            'exception_type': type(exception).__name__ if exception else 'Unknown',
            'traceback': str(traceback) if traceback else None,
            'timestamp': timezone.now(),
            'analysis': self._analyze_task_failure(task_name, exception, traceback)
        }
        
        self.failed_tasks.append(failure_record)
        logger.error(f"Task failed: {task_name} - {exception}")
    
    def _on_task_retry(self, sender=None, task_id=None, reason=None, einfo=None, **kwds):
        """Handle task retry signal."""
        task_name = sender
        
        with self._lock:
            stats = self.task_stats[task_name]
            stats['retry_runs'] += 1
        
        logger.info(f"Task retry: {task_name} - {reason}")
    
    def _analyze_slow_task(self, task_name: str, duration: float, args: tuple, kwargs: dict) -> Dict[str, Any]:
        """Analyze why a task was slow."""
        analysis = {
            'potential_causes': [],
            'recommendations': []
        }
        
        # Check for large argument sizes
        if args and len(str(args)) > 10000:  # Large arguments
            analysis['potential_causes'].append('large_arguments')
            analysis['recommendations'].append('Consider passing object IDs instead of full objects')
        
        if kwargs and len(str(kwargs)) > 10000:  # Large keyword arguments
            analysis['potential_causes'].append('large_kwargs')
            analysis['recommendations'].append('Reduce the size of task arguments')
        
        # Check task history for patterns
        stats = self.task_stats[task_name]
        if stats['avg_runtime'] > 0 and duration > stats['avg_runtime'] * 3:
            analysis['potential_causes'].append('performance_regression')
            analysis['recommendations'].append('Investigate recent changes to this task')
        
        # Check for database-heavy tasks
        if 'database' in task_name.lower() or 'db' in task_name.lower():
            analysis['potential_causes'].append('database_operations')
            analysis['recommendations'].append('Consider optimizing database queries or using connection pooling')
        
        return analysis
    
    def _analyze_task_failure(self, task_name: str, exception: Exception, traceback: str) -> Dict[str, Any]:
        """Analyze task failure for common patterns."""
        analysis = {
            'failure_category': 'unknown',
            'is_retryable': True,
            'recommendations': []
        }
        
        if not exception:
            return analysis
        
        exception_str = str(exception).lower()
        exception_type = type(exception).__name__
        
        # Categorize failure types
        if 'connection' in exception_str or 'timeout' in exception_str:
            analysis['failure_category'] = 'network_connectivity'
            analysis['is_retryable'] = True
            analysis['recommendations'].append('Implement exponential backoff retry strategy')
        
        elif 'database' in exception_str or 'sql' in exception_str:
            analysis['failure_category'] = 'database_error'
            analysis['is_retryable'] = True
            analysis['recommendations'].append('Check database connectivity and query optimization')
        
        elif 'memory' in exception_str or 'memoryerror' in exception_type.lower():
            analysis['failure_category'] = 'memory_error'
            analysis['is_retryable'] = False
            analysis['recommendations'].append('Reduce task memory usage or increase worker memory limits')
        
        elif 'permission' in exception_str or 'access' in exception_str:
            analysis['failure_category'] = 'permission_error'
            analysis['is_retryable'] = False
            analysis['recommendations'].append('Check file/resource permissions')
        
        elif 'keyerror' in exception_type.lower() or 'attributeerror' in exception_type.lower():
            analysis['failure_category'] = 'data_error'
            analysis['is_retryable'] = False
            analysis['recommendations'].append('Validate input data and handle missing attributes')
        
        return analysis
    
    def get_task_statistics(self) -> Dict[str, Any]:
        """Get comprehensive task statistics."""
        with self._lock:
            total_tasks = sum(stats['total_runs'] for stats in self.task_stats.values())
            total_failures = sum(stats['failed_runs'] for stats in self.task_stats.values())
            total_successes = sum(stats['successful_runs'] for stats in self.task_stats.values())
            
            # Calculate overall metrics
            overall_failure_rate = (total_failures / total_tasks * 100) if total_tasks > 0 else 0
            overall_success_rate = (total_successes / total_tasks * 100) if total_tasks > 0 else 0
            
            # Find problematic tasks
            high_failure_tasks = [
                (name, stats) for name, stats in self.task_stats.items()
                if stats['failure_rate'] > 10 and stats['total_runs'] > 5
            ]
            
            slow_task_types = defaultdict(int)
            for task in self.slow_tasks:
                slow_task_types[task['task_name']] += 1
            
            return {
                'overview': {
                    'total_tasks_executed': total_tasks,
                    'total_successes': total_successes,
                    'total_failures': total_failures,
                    'overall_success_rate': round(overall_success_rate, 2),
                    'overall_failure_rate': round(overall_failure_rate, 2),
                    'unique_task_types': len(self.task_stats)
                },
                'task_details': dict(self.task_stats),
                'problematic_tasks': high_failure_tasks,
                'slow_task_summary': dict(slow_task_types),
                'recent_failures': len(self.failed_tasks),
                'recent_slow_tasks': len(self.slow_tasks),
                'generated_at': timezone.now().isoformat()
            }
    
    def get_failure_analysis(self, hours: int = 24) -> Dict[str, Any]:
        """Get detailed failure analysis."""
        cutoff_time = timezone.now() - timedelta(hours=hours)
        
        recent_failures = [
            f for f in self.failed_tasks
            if f['timestamp'] >= cutoff_time
        ]
        
        # Group failures by type and task
        failures_by_task = defaultdict(list)
        failures_by_category = defaultdict(int)
        failures_by_exception = defaultdict(int)
        
        for failure in recent_failures:
            failures_by_task[failure['task_name']].append(failure)
            failures_by_category[failure['analysis']['failure_category']] += 1
            failures_by_exception[failure['exception_type']] += 1
        
        # Find patterns
        recurring_failures = {
            task_name: failures for task_name, failures in failures_by_task.items()
            if len(failures) > 3
        }
        
        return {
            'period_hours': hours,
            'total_failures': len(recent_failures),
            'failures_by_task': dict(failures_by_task),
            'failures_by_category': dict(failures_by_category),
            'failures_by_exception': dict(failures_by_exception),
            'recurring_failures': recurring_failures,
            'recommendations': self._generate_failure_recommendations(recent_failures),
            'generated_at': timezone.now().isoformat()
        }
    
    def _generate_failure_recommendations(self, failures: List[Dict]) -> List[str]:
        """Generate recommendations based on failure patterns."""
        recommendations = []
        
        if not failures:
            return recommendations
        
        # Analyze failure categories
        categories = defaultdict(int)
        for failure in failures:
            categories[failure['analysis']['failure_category']] += 1
        
        total_failures = len(failures)
        
        # Network connectivity issues
        if categories['network_connectivity'] > total_failures * 0.3:
            recommendations.append(
                "High number of network connectivity failures detected. "
                "Consider implementing circuit breaker pattern and increasing retry delays."
            )
        
        # Database errors
        if categories['database_error'] > total_failures * 0.2:
            recommendations.append(
                "Frequent database errors detected. "
                "Review database connection pooling and query optimization."
            )
        
        # Memory errors
        if categories['memory_error'] > 0:
            recommendations.append(
                "Memory errors detected. "
                "Consider reducing task payload size or increasing worker memory limits."
            )
        
        # Data errors
        if categories['data_error'] > total_failures * 0.15:
            recommendations.append(
                "Data validation errors detected. "
                "Implement stricter input validation and error handling."
            )
        
        return recommendations


class TaskRetryManager:
    """
    Manages intelligent task retry strategies.
    """
    
    def __init__(self):
        self.retry_strategies = {}
        self.retry_history = deque(maxlen=1000)
        self._setup_default_strategies()
    
    def _setup_default_strategies(self):
        """Setup default retry strategies for different failure types."""
        self.retry_strategies = {
            'network_connectivity': {
                'max_retries': 5,
                'countdown': [60, 120, 300, 600, 1200],  # Exponential backoff
                'retry_jitter': True
            },
            'database_error': {
                'max_retries': 3,
                'countdown': [30, 90, 180],
                'retry_jitter': True
            },
            'memory_error': {
                'max_retries': 1,
                'countdown': [300],  # 5 minutes
                'retry_jitter': False
            },
            'permission_error': {
                'max_retries': 0,  # Don't retry permission errors
                'countdown': [],
                'retry_jitter': False
            },
            'data_error': {
                'max_retries': 1,
                'countdown': [60],
                'retry_jitter': False
            },
            'default': {
                'max_retries': 3,
                'countdown': [60, 180, 360],
                'retry_jitter': True
            }
        }
    
    def get_retry_strategy(self, failure_category: str, retry_count: int) -> Optional[Dict[str, Any]]:
        """
        Get retry strategy for a specific failure category.
        
        Args:
            failure_category: Category of failure
            retry_count: Current retry attempt number
            
        Returns:
            Retry strategy or None if no more retries
        """
        strategy = self.retry_strategies.get(failure_category, self.retry_strategies['default'])
        
        if retry_count >= strategy['max_retries']:
            return None
        
        countdown = strategy['countdown'][min(retry_count, len(strategy['countdown']) - 1)]
        
        # Add jitter to prevent thundering herd
        if strategy['retry_jitter']:
            import random
            jitter = random.uniform(0.8, 1.2)
            countdown = int(countdown * jitter)
        
        return {
            'countdown': countdown,
            'max_retries': strategy['max_retries'],
            'retry_count': retry_count
        }
    
    def record_retry_attempt(self, task_name: str, task_id: str, failure_category: str, 
                           retry_count: int, success: bool):
        """Record retry attempt for analysis."""
        retry_record = {
            'task_name': task_name,
            'task_id': task_id,
            'failure_category': failure_category,
            'retry_count': retry_count,
            'success': success,
            'timestamp': timezone.now()
        }
        
        self.retry_history.append(retry_record)
    
    def get_retry_statistics(self) -> Dict[str, Any]:
        """Get retry statistics and effectiveness."""
        if not self.retry_history:
            return {'message': 'No retry data available'}
        
        # Analyze retry effectiveness
        retry_by_category = defaultdict(lambda: {'attempts': 0, 'successes': 0})
        retry_by_task = defaultdict(lambda: {'attempts': 0, 'successes': 0})
        
        for record in self.retry_history:
            category_stats = retry_by_category[record['failure_category']]
            task_stats = retry_by_task[record['task_name']]
            
            category_stats['attempts'] += 1
            task_stats['attempts'] += 1
            
            if record['success']:
                category_stats['successes'] += 1
                task_stats['successes'] += 1
        
        # Calculate success rates
        for stats in retry_by_category.values():
            stats['success_rate'] = (stats['successes'] / stats['attempts'] * 100) if stats['attempts'] > 0 else 0
        
        for stats in retry_by_task.values():
            stats['success_rate'] = (stats['successes'] / stats['attempts'] * 100) if stats['attempts'] > 0 else 0
        
        return {
            'total_retry_attempts': len(self.retry_history),
            'retry_by_category': dict(retry_by_category),
            'retry_by_task': dict(retry_by_task),
            'overall_retry_success_rate': round(
                sum(r['success'] for r in self.retry_history) / len(self.retry_history) * 100, 2
            ),
            'generated_at': timezone.now().isoformat()
        }


class EnhancedTask(Task):
    """
    Enhanced Celery task with automatic monitoring and intelligent retry.
    """
    
    def __init__(self):
        super().__init__()
        self.task_metrics = task_metrics
        self.retry_manager = retry_manager
    
    def retry(self, args=None, kwargs=None, exc=None, throw=True, eta=None, countdown=None, max_retries=None, **options):
        """Enhanced retry with intelligent strategy selection."""
        if exc:
            # Analyze the exception to determine failure category
            failure_analysis = self.task_metrics._analyze_task_failure(self.name, exc, None)
            failure_category = failure_analysis['failure_category']
            
            # Get intelligent retry strategy
            retry_strategy = self.retry_manager.get_retry_strategy(failure_category, self.request.retries)
            
            if retry_strategy:
                countdown = retry_strategy['countdown']
                max_retries = retry_strategy['max_retries']
                
                logger.info(f"Retrying task {self.name} (attempt {self.request.retries + 1}/{max_retries}) "
                          f"in {countdown}s due to {failure_category}")
            else:
                logger.error(f"Task {self.name} exceeded max retries for {failure_category}")
                # Record final failure
                self.retry_manager.record_retry_attempt(
                    self.name, self.request.id, failure_category, self.request.retries, False
                )
                raise exc
        
        return super().retry(args, kwargs, exc, throw, eta, countdown, max_retries, **options)
    
    def apply_async(self, args=None, kwargs=None, task_id=None, producer=None, link=None, link_error=None, shadow=None, **options):
        """Enhanced apply_async with monitoring."""
        # Record task submission
        logger.debug(f"Submitting task {self.name} with ID {task_id}")
        
        return super().apply_async(args, kwargs, task_id, producer, link, link_error, shadow, **options)


# Global instances
import threading
task_metrics = TaskMetrics()
retry_manager = TaskRetryManager()


def get_task_monitoring_report() -> Dict[str, Any]:
    """Get comprehensive task monitoring report."""
    return {
        'task_statistics': task_metrics.get_task_statistics(),
        'failure_analysis': task_metrics.get_failure_analysis(),
        'retry_statistics': retry_manager.get_retry_statistics(),
        'generated_at': timezone.now().isoformat()
    }


def configure_task_monitoring():
    """Configure task monitoring for the application."""
    # This function can be called during Django startup to ensure monitoring is active
    logger.info("Celery task monitoring configured")
    return task_metrics, retry_manager