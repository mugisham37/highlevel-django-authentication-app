"""
OAuth provider implementations.

This package contains concrete implementations of OAuth providers
for various services like Google, GitHub, Microsoft, etc.
"""

from .google_oauth import GoogleOAuthProvider
from .github_oauth import GitHubOAuthProvider

__all__ = [
    'GoogleOAuthProvider',
    'GitHubOAuthProvider',
]