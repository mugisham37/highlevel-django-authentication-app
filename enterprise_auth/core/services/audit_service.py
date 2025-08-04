"""
Audit service for enterprise authentication system.

This service provides comprehensive audit logging functionality
for user actions, profile changes, and compliance requirements.
"""

import logging
from typing import Dict, Any, Optional, List
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils import timezone
from django.conf import settings

from ..models import AuditLog, ProfileChangeHistory, UserProfile

logger = logging.getLogger(__name__)


class AuditService:
    """
    Service for managing audit logs and compliance tracking.
    
    This service provides methods for logging user actions,
    profile changes, and other security-relevant events.
    """
    
    def __init__(self):
        """Initialize the audit service."""
        self.default_retention_days = getattr(settings, 'AUDIT_LOG_RETENTION_DAYS', 2555)  # 7 years
    
    def log_profile_update(
        self,
        user: UserProfile,
        old_values: Dict[str, Any],
        new_values: Dict[str, Any],
        request_info: Optional[Dict[str, Any]] = None,
        changed_by: Optional[UserProfile] = None,
    ) -> AuditLog:
        """
        Log a user profile update with detailed change tracking.
        
        Args:
            user: User whose profile was updated
            old_values: Previous profile values
            new_values: New profile values
            request_info: Request metadata (IP, user agent, etc.)
            changed_by: User who made the change (if different from user)
            
        Returns:
            Created AuditLog instance
        """
        try:
            # Create the main audit log entry
            audit_log = AuditLog.log_profile_update(
                user=user,
                old_values=old_values,
                new_values=new_values,
                request_info=request_info or {},
            )
            
            # Create detailed change history records
            ProfileChangeHistory.create_change_records(
                user=user,
                old_values=old_values,
                new_values=new_values,
                audit_log=audit_log,
                changed_by=changed_by,
                request_info=request_info,
            )
            
            logger.info(
                f"Profile update logged for user {user.email}",
                extra={
                    'user_id': str(user.id),
                    'audit_log_id': str(audit_log.id),
                    'changed_fields': list(new_values.keys()),
                }
            )
            
            return audit_log
            
        except Exception as e:
            logger.error(
                f"Failed to log profile update for user {user.email}: {str(e)}",
                extra={
                    'user_id': str(user.id),
                    'error': str(e),
                }
            )
            raise
    
    def log_profile_view(
        self,
        user: UserProfile,
        viewed_by: Optional[UserProfile] = None,
        request_info: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Log a user profile view event.
        
        Args:
            user: User whose profile was viewed
            viewed_by: User who viewed the profile (if different)
            request_info: Request metadata
            
        Returns:
            Created AuditLog instance
        """
        try:
            audit_log = AuditLog.log_profile_view(
                user=user,
                viewed_by=viewed_by,
                request_info=request_info or {},
            )
            
            viewer = viewed_by or user
            logger.info(
                f"Profile view logged: {viewer.email} viewed {user.email}",
                extra={
                    'user_id': str(user.id),
                    'viewer_id': str(viewer.id),
                    'audit_log_id': str(audit_log.id),
                }
            )
            
            return audit_log
            
        except Exception as e:
            logger.error(
                f"Failed to log profile view for user {user.email}: {str(e)}",
                extra={
                    'user_id': str(user.id),
                    'error': str(e),
                }
            )
            raise
    
    def log_data_export(
        self,
        user: UserProfile,
        export_type: str,
        request_info: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Log a data export event for GDPR compliance.
        
        Args:
            user: User who requested data export
            export_type: Type of data exported
            request_info: Request metadata
            
        Returns:
            Created AuditLog instance
        """
        try:
            audit_log = AuditLog.log_data_export(
                user=user,
                export_type=export_type,
                request_info=request_info or {},
            )
            
            logger.info(
                f"Data export logged for user {user.email}: {export_type}",
                extra={
                    'user_id': str(user.id),
                    'export_type': export_type,
                    'audit_log_id': str(audit_log.id),
                }
            )
            
            return audit_log
            
        except Exception as e:
            logger.error(
                f"Failed to log data export for user {user.email}: {str(e)}",
                extra={
                    'user_id': str(user.id),
                    'export_type': export_type,
                    'error': str(e),
                }
            )
            raise
    
    def log_authentication_event(
        self,
        event_type: str,
        user: Optional[UserProfile],
        description: str,
        severity: str = 'low',
        request_info: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Log an authentication-related event.
        
        Args:
            event_type: Type of authentication event
            user: User involved in the event
            description: Description of the event
            severity: Severity level
            request_info: Request metadata
            metadata: Additional event metadata
            
        Returns:
            Created AuditLog instance
        """
        try:
            request_info = request_info or {}
            
            audit_log = AuditLog.log_event(
                event_type=event_type,
                description=description,
                user=user,
                severity=severity,
                ip_address=request_info.get('ip_address'),
                user_agent=request_info.get('user_agent'),
                request_id=request_info.get('request_id'),
                session_id=request_info.get('session_id'),
                metadata=metadata or {},
                retention_days=self.default_retention_days,
            )
            
            user_email = user.email if user else 'Anonymous'
            logger.info(
                f"Authentication event logged: {event_type} for {user_email}",
                extra={
                    'user_id': str(user.id) if user else None,
                    'event_type': event_type,
                    'severity': severity,
                    'audit_log_id': str(audit_log.id),
                }
            )
            
            return audit_log
            
        except Exception as e:
            user_email = user.email if user else 'Anonymous'
            logger.error(
                f"Failed to log authentication event for {user_email}: {str(e)}",
                extra={
                    'user_id': str(user.id) if user else None,
                    'event_type': event_type,
                    'error': str(e),
                }
            )
            raise
    
    def get_user_audit_logs(
        self,
        user: UserProfile,
        event_types: Optional[List[str]] = None,
        start_date: Optional[timezone.datetime] = None,
        end_date: Optional[timezone.datetime] = None,
        limit: int = 100,
    ) -> List[AuditLog]:
        """
        Get audit logs for a specific user.
        
        Args:
            user: User to get logs for
            event_types: Filter by event types
            start_date: Start date for filtering
            end_date: End date for filtering
            limit: Maximum number of logs to return
            
        Returns:
            List of AuditLog instances
        """
        try:
            queryset = AuditLog.objects.filter(user=user)
            
            if event_types:
                queryset = queryset.filter(event_type__in=event_types)
            
            if start_date:
                queryset = queryset.filter(created_at__gte=start_date)
            
            if end_date:
                queryset = queryset.filter(created_at__lte=end_date)
            
            return list(queryset.order_by('-created_at')[:limit])
            
        except Exception as e:
            logger.error(
                f"Failed to get audit logs for user {user.email}: {str(e)}",
                extra={
                    'user_id': str(user.id),
                    'error': str(e),
                }
            )
            return []
    
    def get_profile_change_history(
        self,
        user: UserProfile,
        field_name: Optional[str] = None,
        limit: int = 50,
    ) -> List[ProfileChangeHistory]:
        """
        Get profile change history for a user.
        
        Args:
            user: User to get change history for
            field_name: Filter by specific field name
            limit: Maximum number of changes to return
            
        Returns:
            List of ProfileChangeHistory instances
        """
        try:
            queryset = ProfileChangeHistory.objects.filter(user=user)
            
            if field_name:
                queryset = queryset.filter(field_name=field_name)
            
            return list(queryset.order_by('-created_at')[:limit])
            
        except Exception as e:
            logger.error(
                f"Failed to get profile change history for user {user.email}: {str(e)}",
                extra={
                    'user_id': str(user.id),
                    'field_name': field_name,
                    'error': str(e),
                }
            )
            return []
    
    def cleanup_expired_logs(self) -> int:
        """
        Clean up audit logs that have passed their retention period.
        
        Returns:
            Number of logs deleted
        """
        try:
            now = timezone.now()
            expired_logs = AuditLog.objects.filter(
                retention_until__lt=now
            )
            
            count = expired_logs.count()
            expired_logs.delete()
            
            logger.info(
                f"Cleaned up {count} expired audit logs",
                extra={'deleted_count': count}
            )
            
            return count
            
        except Exception as e:
            logger.error(
                f"Failed to cleanup expired audit logs: {str(e)}",
                extra={'error': str(e)}
            )
            return 0
    
    def export_user_audit_data(
        self,
        user: UserProfile,
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """
        Export all audit data for a user (GDPR compliance).
        
        Args:
            user: User to export data for
            include_sensitive: Whether to include sensitive audit logs
            
        Returns:
            Dictionary with user's audit data
        """
        try:
            # Get audit logs
            audit_logs_query = AuditLog.objects.filter(user=user)
            if not include_sensitive:
                audit_logs_query = audit_logs_query.filter(is_sensitive=False)
            
            audit_logs = audit_logs_query.order_by('-created_at')
            
            # Get profile change history
            profile_changes = ProfileChangeHistory.objects.filter(
                user=user
            ).order_by('-created_at')
            
            # Format data for export
            export_data = {
                'user_id': str(user.id),
                'user_email': user.email,
                'export_timestamp': timezone.now().isoformat(),
                'audit_logs': [
                    {
                        'id': str(log.id),
                        'event_type': log.event_type,
                        'description': log.event_description,
                        'severity': log.severity,
                        'timestamp': log.created_at.isoformat(),
                        'ip_address': log.ip_address,
                        'user_agent': log.user_agent,
                        'old_values': log.old_values,
                        'new_values': log.new_values,
                        'metadata': log.metadata,
                    }
                    for log in audit_logs
                ],
                'profile_changes': [
                    {
                        'id': str(change.id),
                        'field_name': change.field_name,
                        'old_value': change.old_value,
                        'new_value': change.new_value,
                        'timestamp': change.created_at.isoformat(),
                        'changed_by': change.changed_by.email if change.changed_by else None,
                        'ip_address': change.ip_address,
                    }
                    for change in profile_changes
                ],
                'summary': {
                    'total_audit_logs': len(audit_logs),
                    'total_profile_changes': len(profile_changes),
                    'earliest_log': audit_logs.last().created_at.isoformat() if audit_logs else None,
                    'latest_log': audit_logs.first().created_at.isoformat() if audit_logs else None,
                }
            }
            
            # Log the export
            self.log_data_export(user, 'audit_data')
            
            return export_data
            
        except Exception as e:
            logger.error(
                f"Failed to export audit data for user {user.email}: {str(e)}",
                extra={
                    'user_id': str(user.id),
                    'error': str(e),
                }
            )
            raise
    
    def get_audit_statistics(self) -> Dict[str, Any]:
        """
        Get audit log statistics for monitoring.
        
        Returns:
            Dictionary with audit statistics
        """
        try:
            now = timezone.now()
            last_24h = now - timezone.timedelta(hours=24)
            last_7d = now - timezone.timedelta(days=7)
            last_30d = now - timezone.timedelta(days=30)
            
            stats = {
                'total_logs': AuditLog.objects.count(),
                'logs_last_24h': AuditLog.objects.filter(created_at__gte=last_24h).count(),
                'logs_last_7d': AuditLog.objects.filter(created_at__gte=last_7d).count(),
                'logs_last_30d': AuditLog.objects.filter(created_at__gte=last_30d).count(),
                'by_event_type': dict(
                    AuditLog.objects.values_list('event_type')
                    .annotate(count=models.Count('id'))
                    .order_by('-count')
                ),
                'by_severity': dict(
                    AuditLog.objects.values_list('severity')
                    .annotate(count=models.Count('id'))
                    .order_by('-count')
                ),
                'sensitive_logs': AuditLog.objects.filter(is_sensitive=True).count(),
                'expired_logs': AuditLog.objects.filter(
                    retention_until__lt=now
                ).count(),
            }
            
            return stats
            
        except Exception as e:
            logger.error(
                f"Failed to get audit statistics: {str(e)}",
                extra={'error': str(e)}
            )
            return {}


# Global audit service instance
audit_service = AuditService()