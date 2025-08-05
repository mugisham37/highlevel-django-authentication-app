"""
Core views package for enterprise authentication system.
"""

from .auth_views import (
    login,
    refresh_token,
    logout,
    introspect_token,
    validate_token,
    user_profile,
)
from .session_views import (
    list_user_sessions,
    get_session_details,
    terminate_session,
    terminate_all_sessions,
    extend_current_session,
    get_session_activities,
    get_user_session_statistics,
    get_current_session,
    admin_get_session_statistics,
    admin_terminate_user_sessions,
    # Enhanced concurrent session management views
    get_concurrent_session_policy,
    terminate_sessions_by_criteria,
    detect_session_sharing,
    resolve_session_conflicts,
)

__all__ = [
    'login',
    'refresh_token',
    'logout',
    'introspect_token',
    'validate_token',
    'user_profile',
    # Session management views
    'list_user_sessions',
    'get_session_details',
    'terminate_session',
    'terminate_all_sessions',
    'extend_current_session',
    'get_session_activities',
    'get_user_session_statistics',
    'get_current_session',
    'admin_get_session_statistics',
    'admin_terminate_user_sessions',
    # Enhanced concurrent session management views
    'get_concurrent_session_policy',
    'terminate_sessions_by_criteria',
    'detect_session_sharing',
    'resolve_session_conflicts',
]