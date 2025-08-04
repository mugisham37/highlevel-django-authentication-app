# OAuth Provider Implementations

This directory contains concrete implementations of OAuth providers for the enterprise authentication system.

## Google OAuth Provider

The Google OAuth provider (`google_oauth.py`) provides comprehensive integration with Google's OAuth2 and OpenID Connect services.

### Features

- **OAuth2 Authorization Code Flow with PKCE**: Secure authorization flow with Proof Key for Code Exchange
- **OpenID Connect Support**: Full OpenID Connect implementation with ID token validation
- **Automatic Token Refresh**: Handles token refresh automatically when possible
- **Comprehensive User Data Normalization**: Normalizes Google user data to a standard format
- **Fallback Endpoint Support**: Falls back to OAuth2 endpoint if OpenID Connect fails
- **Google Workspace Integration**: Supports hosted domain detection for enterprise accounts

### Configuration

#### Via Django Settings

```python
# settings.py
GOOGLE_OAUTH_CLIENT_ID = 'your-client-id.apps.googleusercontent.com'
GOOGLE_OAUTH_CLIENT_SECRET = 'your-client-secret'
GOOGLE_OAUTH_REDIRECT_URI = 'https://yourdomain.com/auth/google/callback'
GOOGLE_OAUTH_SCOPES = ['openid', 'email', 'profile']
```

#### Via OAUTH_PROVIDERS Setting

```python
# settings.py
OAUTH_PROVIDERS = {
    'google': {
        'provider_class': 'enterprise_auth.core.services.providers.google_oauth.GoogleOAuthProvider',
        'client_id': 'your-client-id.apps.googleusercontent.com',
        'client_secret': 'your-client-secret',
        'redirect_uri': 'https://yourdomain.com/auth/google/callback',
        'scopes': ['openid', 'email', 'profile'],
        'authorization_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_url': 'https://oauth2.googleapis.com/token',
        'user_info_url': 'https://www.googleapis.com/oauth2/v2/userinfo',
        'revoke_url': 'https://oauth2.googleapis.com/revoke',
        'extra_params': {
            'access_type': 'offline',
            'prompt': 'consent',
            'include_granted_scopes': 'true',
        },
        'timeout': 30,
        'use_pkce': True,
        'enabled': True,
    }
}
```

#### Via Environment Variables

```bash
OAUTH_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
OAUTH_GOOGLE_CLIENT_SECRET=your-client-secret
OAUTH_GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/google/callback
OAUTH_GOOGLE_SCOPES=openid,email,profile
OAUTH_GOOGLE_AUTHORIZATION_URL=https://accounts.google.com/o/oauth2/v2/auth
OAUTH_GOOGLE_TOKEN_URL=https://oauth2.googleapis.com/token
OAUTH_GOOGLE_USER_INFO_URL=https://www.googleapis.com/oauth2/v2/userinfo
OAUTH_GOOGLE_REVOKE_URL=https://oauth2.googleapis.com/revoke
OAUTH_GOOGLE_TIMEOUT=30
OAUTH_GOOGLE_USE_PKCE=true
```

### API Endpoints

The Google OAuth provider is automatically registered and available through these API endpoints:

#### List Available Providers

```http
GET /api/v1/oauth/providers/
```

#### Initiate Authorization

```http
POST /api/v1/oauth/google/authorize/
Content-Type: application/json

{
    "scopes": ["openid", "email", "profile"],
    "redirect_uri": "https://yourdomain.com/auth/google/callback"
}
```

Response:

```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...",
  "state": "random-state-string",
  "provider": "google",
  "uses_pkce": true
}
```

#### Handle Callback

```http
POST /api/v1/oauth/google/callback/
Content-Type: application/json

{
    "code": "authorization-code-from-google",
    "state": "state-from-authorization-request"
}
```

Response:

```json
{
  "access_token": "jwt-access-token",
  "refresh_token": "jwt-refresh-token",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "full_name": "John Doe",
    "is_email_verified": true,
    "profile_picture_url": "https://lh3.googleusercontent.com/...",
    "is_new_user": false
  },
  "oauth_identity": {
    "provider": "google",
    "provider_user_id": "google-user-id",
    "provider_username": "user@example.com",
    "is_primary": true,
    "linked_at": "2024-01-15T10:30:00Z"
  }
}
```

### Supported Scopes

The Google OAuth provider supports the following scopes:

#### OpenID Connect Scopes

- `openid` - Required for OpenID Connect
- `email` - Required for email access
- `profile` - Basic profile information

#### Google API Scopes

- `https://www.googleapis.com/auth/userinfo.email` - Email address
- `https://www.googleapis.com/auth/userinfo.profile` - Basic profile info
- `https://www.googleapis.com/auth/user.birthday.read` - Birthday information
- `https://www.googleapis.com/auth/user.gender.read` - Gender information
- `https://www.googleapis.com/auth/user.phonenumbers.read` - Phone numbers
- `https://www.googleapis.com/auth/user.addresses.read` - Addresses

#### Google Workspace Scopes (Enterprise)

- `https://www.googleapis.com/auth/admin.directory.user.readonly` - User directory
- `https://www.googleapis.com/auth/admin.directory.group.readonly` - Group directory
- `https://www.googleapis.com/auth/admin.directory.orgunit.readonly` - Org units

### User Data Normalization

The provider normalizes Google user data to a standard format:

```python
NormalizedUserData(
    provider_user_id='google-user-id',
    email='user@example.com',
    first_name='John',
    last_name='Doe',
    username='user@example.com',
    profile_picture_url='https://lh3.googleusercontent.com/...',
    locale='en-US',
    timezone='America/New_York',  # Mapped from locale
    verified_email=True,
    raw_data={
        # Original Google response
        'sub': 'google-user-id',
        'email': 'user@example.com',
        'email_verified': True,
        'given_name': 'John',
        'family_name': 'Doe',
        'picture': 'https://lh3.googleusercontent.com/...',
        'locale': 'en-US',
        'hd': 'company.com',  # Hosted domain for Google Workspace
        'google_specific': {
            'hd': 'company.com',
            'aud': 'client-id',
            'iss': 'https://accounts.google.com',
            # ... other Google-specific fields
        }
    }
)
```

### Error Handling

The provider handles various error scenarios:

- **Token Expired**: Raises `OAuthTokenExpiredError`
- **Invalid Configuration**: Raises `ConfigurationError`
- **Provider Errors**: Raises `OAuthProviderError`
- **Network Issues**: Automatic retry with fallback endpoints

### Security Features

- **PKCE Support**: Proof Key for Code Exchange for enhanced security
- **State Parameter**: CSRF protection with secure random state
- **Token Encryption**: All stored tokens are encrypted
- **Scope Validation**: Validates requested scopes against supported scopes
- **ID Token Validation**: Basic ID token validation (issuer, audience)

### Google Console Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API or Google Identity API
4. Go to "Credentials" and create an OAuth 2.0 Client ID
5. Configure authorized redirect URIs
6. Copy the Client ID and Client Secret to your Django settings

### Testing

The provider includes comprehensive tests covering:

- Authorization URL generation with PKCE
- Token exchange and validation
- User info retrieval from both endpoints
- Error handling scenarios
- User data normalization
- Token refresh and revocation

Run tests with:

```bash
python manage.py test enterprise_auth.core.tests.test_google_oauth
```

### Example Usage

```python
from enterprise_auth.core.services.oauth_service import oauth_service

# Initiate authorization
auth_request = oauth_service.initiate_authorization(
    provider_name='google',
    state='secure-random-state',
    scopes=['openid', 'email', 'profile']
)

# Handle callback
token_data, user_data = oauth_service.handle_callback(
    provider_name='google',
    code='authorization-code',
    state='secure-random-state',
    code_verifier=auth_request.code_verifier
)

# Link to user account
identity = oauth_service.link_user_identity(
    user=user,
    provider_name='google',
    token_data=token_data,
    user_data=user_data,
    is_primary=True
)
```

## Adding New Providers

To add a new OAuth provider:

1. Create a new file in this directory (e.g., `github_oauth.py`)
2. Implement the `BaseOAuthProvider` class
3. Register the provider in `oauth_providers_registry.py`
4. Add configuration support in `oauth_config.py`
5. Create comprehensive tests
6. Update this README with provider-specific documentation

### Provider Implementation Template

```python
from typing import Set
from ..oauth_provider import BaseOAuthProvider, NormalizedUserData

class NewProviderOAuth(BaseOAuthProvider):
    @property
    def provider_name(self) -> str:
        return "newprovider"

    @property
    def display_name(self) -> str:
        return "New Provider"

    @property
    def supported_scopes(self) -> Set[str]:
        return {"scope1", "scope2", "scope3"}

    def get_user_info(self, access_token: str) -> NormalizedUserData:
        # Implement user info retrieval
        pass

    # Implement other required methods...
```
