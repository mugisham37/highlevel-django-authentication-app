"""
OAuth provider implementations.

This package contains concrete implementations of OAuth providers
for various services like Google, GitHub, Microsoft, etc.
"""

from .google_oauth import GoogleOAuthProvider
from .github_oauth import GitHubOAuthProvider
from .microsoft_oauth import MicrosoftOAuthProvider

__all__ = [
    'GoogleOAuthProvider',
    'GitHubOAuthProvider',
    'MicrosoftOAuthProvider',
]