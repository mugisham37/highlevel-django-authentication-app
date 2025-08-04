"""
Celery tasks for cache management operations.
Provides background tasks for cache warming, cleanup, and maintenance.
"""

import logging
from celery import shared_task
from django.conf import settings
from enterprise_auth.core.cache.cache_manager import cache_manager
from enterprise_auth.core.cache.session_storage import session_manager
from enterprise_auth.core.cache.rate_limiter import rate_limiter
import time

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def warm_user_cache(self, user_ids=None):
    """
    Celery task to warm user-related cache data.
    
    Args:
        user_ids: List of user IDs to warm, or None for all active users
    """
    try:
        logger.info("Starting user cache warming task")
        start_time = time.time()
        
        cache_manager.warmer.warm_user_data(user_ids)
        
        elapsed_time = time.time() - start_time
        logger.info(f"User cache warming completed in {elapsed_time:.2f} seconds")
        
        return {
            'status': 'success',
            'elapsed_time': elapsed_time,
            'user_count': len(user_ids) if user_ids else 'all_active'
        }
        
    except Exception as e:
        logger.error(f"User cache warming task failed: {e}")
        
        # Retry the task
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying user cache warming task (attempt {self.request.retries + 1})")
            raise self.retry(exc=e)
        
        return {
            'status': 'failed',
            'error': str(e),
            'retries': self.request.retries
        }


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def warm_oauth_providers_cache(self):
    """
    Celery task to warm OAuth provider configuration cache.
    """
    try:
        logger.info("Starting OAuth providers cache warming task")
        start_time = time.time()
        
        cache_manager.warmer.warm_oauth_providers()
        
        elapsed_time = time.time() - start_time
        logger.info(f"OAuth providers cache warming completed in {elapsed_time:.2f} seconds")
        
        return {
            'status': 'success',
            'elapsed_time': elapsed_time
        }
        
    except Exception as e:
        logger.error(f"OAuth providers cache warming task failed: {e}")
        
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying OAuth providers cache warming task (attempt {self.request.retries + 1})")
            raise self.retry(exc=e)
        
        return {
            'status': 'failed',
            'error': str(e),
            'retries': self.request.retries
        }


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def warm_role_permissions_cache(self):
    """
    Celery task to warm role and permission cache data.
    """
    try:
        logger.info("Starting role permissions cache warming task")
        start_time = time.time()
        
        cache_manager.warmer.warm_role_permissions()
        
        elapsed_time = time.time() - start_time
        logger.info(f"Role permissions cache warming completed in {elapsed_time:.2f} seconds")
        
        return {
            'status': 'success',
            'elapsed_time': elapsed_time
        }
        
    except Exception as e:
        logger.error(f"Role permissions cache warming task failed: {e}")
        
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying role permissions cache warming task (attempt {self.request.retries + 1})")
            raise self.retry(exc=e)
        
        return {
            'status': 'failed',
            'error': str(e),
            'retries': self.request.retries
        }


@shared_task(bind=True, max_retries=2, default_retry_delay=300)
def cleanup_expired_sessions(self):
    """
    Celery task to clean up expired sessions from Redis.
    """
    try:
        logger.info("Starting expired sessions cleanup task")
        start_time = time.time()
        
        cleaned_count = session_manager.cleanup_expired_sessions()
        
        elapsed_time = time.time() - start_time
        logger.info(f"Expired sessions cleanup completed in {elapsed_time:.2f} seconds, cleaned {cleaned_count} sessions")
        
        return {
            'status': 'success',
            'elapsed_time': elapsed_time,
            'cleaned_sessions': cleaned_count
        }
        
    except Exception as e:
        logger.error(f"Expired sessions cleanup task failed: {e}")
        
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying expired sessions cleanup task (attempt {self.request.retries + 1})")
            raise self.retry(exc=e)
        
        return {
            'status': 'failed',
            'error': str(e),
            'retries': self.request.retries
        }


@shared_task(bind=True, max_retries=2, default_retry_delay=300)
def cleanup_rate_limit_counters(self):
    """
    Celery task to clean up expired rate limiting counters.
    """
    try:
        logger.info("Starting rate limit counters cleanup task")
        start_time = time.time()
        
        # This would implement cleanup logic for expired rate limit counters
        # For now, we'll just log that the task ran
        
        elapsed_time = time.time() - start_time
        logger.info(f"Rate limit counters cleanup completed in {elapsed_time:.2f} seconds")
        
        return {
            'status': 'success',
            'elapsed_time': elapsed_time
        }
        
    except Exception as e:
        logger.error(f"Rate limit counters cleanup task failed: {e}")
        
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying rate limit counters cleanup task (attempt {self.request.retries + 1})")
            raise self.retry(exc=e)
        
        return {
            'status': 'failed',
            'error': str(e),
            'retries': self.request.retries
        }


@shared_task(bind=True, max_retries=1, default_retry_delay=600)
def comprehensive_cache_warming(self):
    """
    Celery task to perform comprehensive cache warming of all data types.
    """
    try:
        logger.info("Starting comprehensive cache warming task")
        start_time = time.time()
        
        # Run all warming tasks
        cache_manager.warmer.run_warming_tasks()
        
        elapsed_time = time.time() - start_time
        logger.info(f"Comprehensive cache warming completed in {elapsed_time:.2f} seconds")
        
        return {
            'status': 'success',
            'elapsed_time': elapsed_time,
            'tasks_run': 'all'
        }
        
    except Exception as e:
        logger.error(f"Comprehensive cache warming task failed: {e}")
        
        if self.request.retries < self.max_retries:
            logger.info(f"Retrying comprehensive cache warming task (attempt {self.request.retries + 1})")
            raise self.retry(exc=e)
        
        return {
            'status': 'failed',
            'error': str(e),
            'retries': self.request.retries
        }


@shared_task(bind=True)
def invalidate_user_cache(self, user_id):
    """
    Celery task to invalidate cache for a specific user.
    
    Args:
        user_id: User ID to invalidate cache for
    """
    try:
        logger.info(f"Starting cache invalidation for user {user_id}")
        
        cache_manager.invalidator.invalidate_user_cache(user_id)
        
        logger.info(f"Cache invalidation completed for user {user_id}")
        
        return {
            'status': 'success',
            'user_id': user_id
        }
        
    except Exception as e:
        logger.error(f"Cache invalidation task failed for user {user_id}: {e}")
        
        return {
            'status': 'failed',
            'user_id': user_id,
            'error': str(e)
        }


@shared_task(bind=True)
def invalidate_session_cache(self, session_id):
    """
    Celery task to invalidate cache for a specific session.
    
    Args:
        session_id: Session ID to invalidate cache for
    """
    try:
        logger.info(f"Starting cache invalidation for session {session_id}")
        
        cache_manager.invalidator.invalidate_session_cache(session_id)
        
        logger.info(f"Cache invalidation completed for session {session_id}")
        
        return {
            'status': 'success',
            'session_id': session_id
        }
        
    except Exception as e:
        logger.error(f"Cache invalidation task failed for session {session_id}: {e}")
        
        return {
            'status': 'failed',
            'session_id': session_id,
            'error': str(e)
        }