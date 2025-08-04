"""
OAuth provider implementations.

This package contains concrete implementations of OAuth providers
for various services like Google, GitHub, Microsoft, etc.
"""

from .google_oauth import GoogleOAuthProvider

__all__ = [
    'GoogleOAuthProvider',
]