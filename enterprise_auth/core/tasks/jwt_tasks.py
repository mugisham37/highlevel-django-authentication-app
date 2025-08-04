"""
Celery tasks for JWT token management.

This module provides background tasks for:
- Cleaning up expired blacklisted tokens
- Periodic token maintenance
- Security incident response
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from celery import shared_task
from django.utils import timezone
from django.conf import settings

from ..services.jwt_service import jwt_service
from ..models.jwt import TokenBlacklist, RefreshToken

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def cleanup_expired_blacklisted_tokens(self) -> Dict[str, Any]:
    """
    Clean up expired blacklisted tokens from Redis and database.
    
    This task removes expired tokens from both the Redis blacklist
    and the database TokenBlacklist model to free up storage space.
    
    Returns:
        Dictionary with cleanup statistics
    """
    try:
        logger.info("Starting cleanup of expired blacklisted tokens")
        
        # Clean up Redis blacklist
        redis_cleaned = jwt_service.cleanup_expired_blacklist_entries()
        
        # Clean up database blacklist entries
        db_cleaned = TokenBlacklist.cleanup_expired_entries()
        
        # Clean up expired refresh tokens
        expired_refresh_tokens = RefreshToken.objects.filter(
            expires_at__lt=timezone.now(),
            status='active'
        )
        refresh_cleaned = expired_refresh_tokens.count()
        expired_refresh_tokens.update(status='expired')
        
        result = {
            'redis_cleaned': redis_cleaned,
            'db_cleaned': db_cleaned,
            'refresh_tokens_expired': refresh_cleaned,
            'total_cleaned': redis_cleaned + db_cleaned + refresh_cleaned,
            'cleanup_time': timezone.now().isoformat(),
        }
        
        logger.info(f"Token cleanup completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Token cleanup failed: {str(e)}")
        # Retry the task with exponential backoff
        raise self.retry(countdown=60 * (2 ** self.request.retries), exc=e)


@shared_task(bind=True, max_retries=3)
def cleanup_old_refresh_tokens(self, days_old: int = 60) -> Dict[str, Any]:
    """
    Clean up old refresh tokens that are no longer needed.
    
    This task removes refresh tokens that have been expired or revoked
    for a specified number of days to keep the database clean.
    
    Args:
        days_old: Number of days after expiration/revocation to keep tokens
        
    Returns:
        Dictionary with cleanup statistics
    """
    try:
        logger.info(f"Starting cleanup of refresh tokens older than {days_old} days")
        
        cutoff_date = timezone.now() - timedelta(days=days_old)
        
        # Clean up expired tokens
        expired_tokens = RefreshToken.objects.filter(
            expires_at__lt=cutoff_date,
            status__in=['expired', 'revoked', 'rotated']
        )
        expired_count = expired_tokens.count()
        expired_tokens.delete()
        
        # Clean up old blacklist entries
        old_blacklist = TokenBlacklist.objects.filter(
            expires_at__lt=cutoff_date
        )
        blacklist_count = old_blacklist.count()
        old_blacklist.delete()
        
        result = {
            'expired_tokens_deleted': expired_count,
            'blacklist_entries_deleted': blacklist_count,
            'total_deleted': expired_count + blacklist_count,
            'cutoff_date': cutoff_date.isoformat(),
            'cleanup_time': timezone.now().isoformat(),
        }
        
        logger.info(f"Old token cleanup completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Old token cleanup failed: {str(e)}")
        raise self.retry(countdown=60 * (2 ** self.request.retries), exc=e)


@shared_task(bind=True, max_retries=3)
def security_incident_token_revocation(
    self,
    incident_type: str,
    user_ids: list = None,
    device_ids: list = None,
    token_ids: list = None,
    reason: str = 'security_incident'
) -> Dict[str, Any]:
    """
    Handle bulk token revocation for security incidents.
    
    This task can revoke tokens based on various criteria:
    - All tokens for specific users
    - All tokens for specific devices
    - Specific token IDs
    
    Args:
        incident_type: Type of security incident
        user_ids: List of user IDs to revoke tokens for
        device_ids: List of device IDs to revoke tokens for
        token_ids: List of specific token IDs to revoke
        reason: Reason for the revocation
        
    Returns:
        Dictionary with revocation statistics
    """
    try:
        logger.info(f"Starting security incident token revocation: {incident_type}")
        
        result = {
            'incident_type': incident_type,
            'reason': reason,
            'users_affected': 0,
            'devices_affected': 0,
            'tokens_revoked': 0,
            'revocation_time': timezone.now().isoformat(),
        }
        
        # Revoke tokens for specific users
        if user_ids:
            for user_id in user_ids:
                success = jwt_service.revoke_all_user_tokens(user_id, reason)
                if success:
                    result['users_affected'] += 1
        
        # Revoke tokens for specific devices
        if device_ids:
            for device_id in device_ids:
                success = jwt_service.revoke_device_tokens(device_id, reason)
                if success:
                    result['devices_affected'] += 1
        
        # Revoke specific tokens
        if token_ids:
            revoked_count = jwt_service.bulk_revoke_tokens(token_ids, reason)
            result['tokens_revoked'] = revoked_count
        
        logger.info(f"Security incident revocation completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Security incident revocation failed: {str(e)}")
        raise self.retry(countdown=60 * (2 ** self.request.retries), exc=e)


@shared_task(bind=True)
def generate_token_blacklist_report(self, days_back: int = 7) -> Dict[str, Any]:
    """
    Generate a report of token blacklist activity.
    
    This task creates a summary report of token revocations
    and blacklist activity for monitoring and compliance.
    
    Args:
        days_back: Number of days to include in the report
        
    Returns:
        Dictionary with blacklist statistics
    """
    try:
        logger.info(f"Generating token blacklist report for last {days_back} days")
        
        start_date = timezone.now() - timedelta(days=days_back)
        
        # Get blacklist statistics from database
        blacklist_entries = TokenBlacklist.objects.filter(
            blacklisted_at__gte=start_date
        )
        
        # Group by reason
        reason_stats = {}
        for entry in blacklist_entries:
            reason = entry.reason
            if reason not in reason_stats:
                reason_stats[reason] = 0
            reason_stats[reason] += 1
        
        # Group by token type
        type_stats = {}
        for entry in blacklist_entries:
            token_type = entry.token_type
            if token_type not in type_stats:
                type_stats[token_type] = 0
            type_stats[token_type] += 1
        
        # Get refresh token statistics
        refresh_tokens = RefreshToken.objects.filter(
            created_at__gte=start_date
        )
        
        refresh_stats = {
            'total_created': refresh_tokens.count(),
            'active': refresh_tokens.filter(status='active').count(),
            'rotated': refresh_tokens.filter(status='rotated').count(),
            'revoked': refresh_tokens.filter(status='revoked').count(),
            'expired': refresh_tokens.filter(status='expired').count(),
        }
        
        result = {
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': timezone.now().isoformat(),
                'days': days_back,
            },
            'blacklist_stats': {
                'total_blacklisted': blacklist_entries.count(),
                'by_reason': reason_stats,
                'by_type': type_stats,
            },
            'refresh_token_stats': refresh_stats,
            'report_generated': timezone.now().isoformat(),
        }
        
        logger.info(f"Token blacklist report generated: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Token blacklist report generation failed: {str(e)}")
        raise


@shared_task(bind=True)
def monitor_token_usage_patterns(self) -> Dict[str, Any]:
    """
    Monitor token usage patterns for anomaly detection.
    
    This task analyzes token creation and usage patterns
    to identify potential security issues or abuse.
    
    Returns:
        Dictionary with usage pattern analysis
    """
    try:
        logger.info("Starting token usage pattern monitoring")
        
        # Get recent token activity (last 24 hours)
        last_24h = timezone.now() - timedelta(hours=24)
        
        # Analyze refresh token creation patterns
        recent_tokens = RefreshToken.objects.filter(
            created_at__gte=last_24h
        )
        
        # Group by user to detect unusual activity
        user_token_counts = {}
        device_token_counts = {}
        
        for token in recent_tokens:
            user_id = str(token.user.id)
            device_id = token.device_id
            
            user_token_counts[user_id] = user_token_counts.get(user_id, 0) + 1
            device_token_counts[device_id] = device_token_counts.get(device_id, 0) + 1
        
        # Identify potential anomalies
        high_activity_users = {
            user_id: count for user_id, count in user_token_counts.items()
            if count > 50  # More than 50 tokens in 24h might be suspicious
        }
        
        high_activity_devices = {
            device_id: count for device_id, count in device_token_counts.items()
            if count > 20  # More than 20 tokens per device in 24h might be suspicious
        }
        
        # Get blacklist activity
        recent_blacklist = TokenBlacklist.objects.filter(
            blacklisted_at__gte=last_24h
        )
        
        result = {
            'monitoring_period': {
                'start_time': last_24h.isoformat(),
                'end_time': timezone.now().isoformat(),
            },
            'token_activity': {
                'total_tokens_created': recent_tokens.count(),
                'unique_users': len(user_token_counts),
                'unique_devices': len(device_token_counts),
                'tokens_blacklisted': recent_blacklist.count(),
            },
            'anomalies': {
                'high_activity_users': high_activity_users,
                'high_activity_devices': high_activity_devices,
            },
            'analysis_time': timezone.now().isoformat(),
        }
        
        # Log anomalies for further investigation
        if high_activity_users or high_activity_devices:
            logger.warning(f"Token usage anomalies detected: {result['anomalies']}")
        
        logger.info(f"Token usage pattern monitoring completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Token usage pattern monitoring failed: {str(e)}")
        raise