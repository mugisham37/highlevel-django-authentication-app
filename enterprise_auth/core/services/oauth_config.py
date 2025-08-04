"""
OAuth provider configuration management system.

This module provides utilities for managing OAuth provider configurations,
including validation, encryption, and dynamic configuration updates.
"""

import logging
from typing import Any, Dict, List, Optional, Union

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.functional import cached_property

from ..exceptions import ConfigurationError
from ..utils.encryption import EncryptionService
from .oauth_provider import ProviderConfig

logger = logging.getLogger(__name__)


class OAuthConfigManager:
    """
    Manager for OAuth provider configurations.
    
    This class handles loading, validating, and managing OAuth provider
    configurations from various sources including Django settings,
    environment variables, and database storage.
    """
    
    def __init__(self):
        """Initialize the configuration manager."""
        self._configs: Dict[str, ProviderConfig] = {}
        self._encrypted_fields = {'client_secret'}
        self._encryption_service = EncryptionService()
    
    @cached_property
    def default_config_template(self) -> Dict[str, Any]:
        """Get default configuration template for OAuth providers."""
        return {
            'client_id': '',
            'client_secret': '',
            'redirect_uri': '',
            'scopes': [],
            'authorization_url': '',
            'token_url': '',
            'user_info_url': '',
            'revoke_url': None,
            'extra_params': {},
            'timeout': 30,
            'use_pkce': True,
        }
    
    def load_config_from_settings(self, provider_name: str) -> Optional[ProviderConfig]:
        """
        Load provider configuration from Django settings.
        
        Args:
            provider_name: Name of the OAuth provider
            
        Returns:
            Provider configuration or None if not found
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        oauth_settings = getattr(settings, 'OAUTH_PROVIDERS', {})
        provider_settings = oauth_settings.get(provider_name)
        
        if not provider_settings:
            return None
        
        try:
            # Merge with default template
            config_data = self.default_config_template.copy()
            config_data.update(provider_settings)
            
            # Remove non-config fields
            non_config_fields = {
                'provider_class', 'display_name', 'description',
                'icon_url', 'documentation_url', 'enabled'
            }
            for field in non_config_fields:
                config_data.pop(field, None)
            
            # Validate and create config
            config = self._create_config_from_dict(provider_name, config_data)
            
            logger.info(
                f"Loaded configuration for provider {provider_name} from settings",
                extra={'provider': provider_name}
            )
            
            return config
            
        except Exception as e:
            raise ConfigurationError(
                f"Invalid configuration for provider {provider_name}: {e}",
                config_key=f"OAUTH_PROVIDERS.{provider_name}"
            )
    
    def load_config_from_env(self, provider_name: str) -> Optional[ProviderConfig]:
        """
        Load provider configuration from environment variables.
        
        Environment variables should follow the pattern:
        OAUTH_{PROVIDER_NAME}_{FIELD_NAME}
        
        Args:
            provider_name: Name of the OAuth provider
            
        Returns:
            Provider configuration or None if not found
        """
        import os
        
        provider_upper = provider_name.upper()
        env_prefix = f'OAUTH_{provider_upper}_'
        
        config_data = {}
        
        # Map environment variable names to config fields
        env_field_mapping = {
            'CLIENT_ID': 'client_id',
            'CLIENT_SECRET': 'client_secret',
            'REDIRECT_URI': 'redirect_uri',
            'SCOPES': 'scopes',
            'AUTHORIZATION_URL': 'authorization_url',
            'TOKEN_URL': 'token_url',
            'USER_INFO_URL': 'user_info_url',
            'REVOKE_URL': 'revoke_url',
            'TIMEOUT': 'timeout',
            'USE_PKCE': 'use_pkce',
        }
        
        # Load configuration from environment
        for env_name, config_field in env_field_mapping.items():
            env_var = f'{env_prefix}{env_name}'
            value = os.getenv(env_var)
            
            if value is not None:
                # Convert string values to appropriate types
                if config_field == 'scopes':
                    config_data[config_field] = [s.strip() for s in value.split(',') if s.strip()]
                elif config_field == 'timeout':
                    config_data[config_field] = int(value)
                elif config_field == 'use_pkce':
                    config_data[config_field] = value.lower() in ('true', '1', 'yes', 'on')
                else:
                    config_data[config_field] = value
        
        if not config_data:
            return None
        
        try:
            # Merge with default template
            full_config = self.default_config_template.copy()
            full_config.update(config_data)
            
            config = self._create_config_from_dict(provider_name, full_config)
            
            logger.info(
                f"Loaded configuration for provider {provider_name} from environment",
                extra={'provider': provider_name}
            )
            
            return config
            
        except Exception as e:
            raise ConfigurationError(
                f"Invalid environment configuration for provider {provider_name}: {e}",
                config_key=f"Environment variables {env_prefix}*"
            )
    
    def create_config(
        self,
        provider_name: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: List[str],
        authorization_url: str,
        token_url: str,
        user_info_url: str,
        revoke_url: Optional[str] = None,
        extra_params: Optional[Dict[str, Any]] = None,
        timeout: int = 30,
        use_pkce: bool = True
    ) -> ProviderConfig:
        """
        Create a new provider configuration.
        
        Args:
            provider_name: Name of the OAuth provider
            client_id: OAuth client ID
            client_secret: OAuth client secret
            redirect_uri: OAuth redirect URI
            scopes: List of OAuth scopes
            authorization_url: OAuth authorization endpoint URL
            token_url: OAuth token endpoint URL
            user_info_url: OAuth user info endpoint URL
            revoke_url: OAuth token revocation endpoint URL
            extra_params: Additional parameters for authorization
            timeout: HTTP request timeout in seconds
            use_pkce: Whether to use PKCE for authorization
            
        Returns:
            Provider configuration
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        config_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'redirect_uri': redirect_uri,
            'scopes': scopes,
            'authorization_url': authorization_url,
            'token_url': token_url,
            'user_info_url': user_info_url,
            'revoke_url': revoke_url,
            'extra_params': extra_params or {},
            'timeout': timeout,
            'use_pkce': use_pkce,
        }
        
        return self._create_config_from_dict(provider_name, config_data)
    
    def update_config(
        self,
        provider_name: str,
        updates: Dict[str, Any]
    ) -> ProviderConfig:
        """
        Update an existing provider configuration.
        
        Args:
            provider_name: Name of the OAuth provider
            updates: Configuration updates
            
        Returns:
            Updated provider configuration
            
        Raises:
            ConfigurationError: If configuration is invalid
            KeyError: If provider configuration doesn't exist
        """
        if provider_name not in self._configs:
            raise KeyError(f"Configuration for provider {provider_name} not found")
        
        # Get current configuration as dict
        current_config = self._config_to_dict(self._configs[provider_name])
        
        # Apply updates
        current_config.update(updates)
        
        # Create new configuration
        new_config = self._create_config_from_dict(provider_name, current_config)
        
        # Store updated configuration
        self._configs[provider_name] = new_config
        
        logger.info(
            f"Updated configuration for provider {provider_name}",
            extra={'provider': provider_name, 'updated_fields': list(updates.keys())}
        )
        
        return new_config
    
    def get_config(self, provider_name: str) -> Optional[ProviderConfig]:
        """
        Get provider configuration.
        
        Args:
            provider_name: Name of the OAuth provider
            
        Returns:
            Provider configuration or None if not found
        """
        return self._configs.get(provider_name)
    
    def set_config(self, provider_name: str, config: ProviderConfig) -> None:
        """
        Set provider configuration.
        
        Args:
            provider_name: Name of the OAuth provider
            config: Provider configuration
        """
        self._configs[provider_name] = config
        
        logger.info(
            f"Set configuration for provider {provider_name}",
            extra={'provider': provider_name}
        )
    
    def remove_config(self, provider_name: str) -> bool:
        """
        Remove provider configuration.
        
        Args:
            provider_name: Name of the OAuth provider
            
        Returns:
            True if configuration was removed, False if not found
        """
        if provider_name in self._configs:
            del self._configs[provider_name]
            logger.info(f"Removed configuration for provider {provider_name}")
            return True
        return False
    
    def list_configured_providers(self) -> List[str]:
        """
        List all configured providers.
        
        Returns:
            List of provider names
        """
        return list(self._configs.keys())
    
    def validate_config(self, provider_name: str, config_data: Dict[str, Any]) -> List[str]:
        """
        Validate provider configuration.
        
        Args:
            provider_name: Name of the OAuth provider
            config_data: Configuration data to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Required fields
        required_fields = [
            'client_id', 'client_secret', 'redirect_uri',
            'authorization_url', 'token_url', 'user_info_url'
        ]
        
        for field in required_fields:
            if not config_data.get(field):
                errors.append(f"Missing required field: {field}")
        
        # Validate URLs
        url_fields = ['authorization_url', 'token_url', 'user_info_url', 'revoke_url']
        for field in url_fields:
            url = config_data.get(field)
            if url and not self._is_valid_url(url):
                errors.append(f"Invalid URL for field: {field}")
        
        # Validate scopes
        scopes = config_data.get('scopes', [])
        if not isinstance(scopes, list):
            errors.append("Scopes must be a list")
        elif not all(isinstance(scope, str) for scope in scopes):
            errors.append("All scopes must be strings")
        
        # Validate timeout
        timeout = config_data.get('timeout', 30)
        if not isinstance(timeout, int) or timeout <= 0:
            errors.append("Timeout must be a positive integer")
        
        # Validate use_pkce
        use_pkce = config_data.get('use_pkce', True)
        if not isinstance(use_pkce, bool):
            errors.append("use_pkce must be a boolean")
        
        # Validate extra_params
        extra_params = config_data.get('extra_params', {})
        if not isinstance(extra_params, dict):
            errors.append("extra_params must be a dictionary")
        
        return errors
    
    def encrypt_sensitive_fields(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt sensitive fields in configuration data.
        
        Args:
            config_data: Configuration data
            
        Returns:
            Configuration data with encrypted sensitive fields
        """
        encrypted_data = config_data.copy()
        
        for field in self._encrypted_fields:
            if field in encrypted_data and encrypted_data[field]:
                encrypted_data[field] = self._encryption_service.encrypt(
                    encrypted_data[field]
                )
        
        return encrypted_data
    
    def decrypt_sensitive_fields(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt sensitive fields in configuration data.
        
        Args:
            config_data: Configuration data with encrypted fields
            
        Returns:
            Configuration data with decrypted sensitive fields
        """
        decrypted_data = config_data.copy()
        
        for field in self._encrypted_fields:
            if field in decrypted_data and decrypted_data[field]:
                try:
                    decrypted_data[field] = self._encryption_service.decrypt(
                        decrypted_data[field]
                    )
                except Exception as e:
                    logger.error(
                        f"Failed to decrypt field {field}",
                        extra={'field': field, 'error': str(e)}
                    )
                    # Keep encrypted value if decryption fails
        
        return decrypted_data
    
    def export_config(self, provider_name: str, include_secrets: bool = False) -> Optional[Dict[str, Any]]:
        """
        Export provider configuration as dictionary.
        
        Args:
            provider_name: Name of the OAuth provider
            include_secrets: Whether to include sensitive fields
            
        Returns:
            Configuration dictionary or None if not found
        """
        config = self.get_config(provider_name)
        if not config:
            return None
        
        config_dict = self._config_to_dict(config)
        
        if not include_secrets:
            # Remove sensitive fields
            for field in self._encrypted_fields:
                if field in config_dict:
                    config_dict[field] = '[REDACTED]'
        
        return config_dict
    
    def import_config(self, provider_name: str, config_data: Dict[str, Any]) -> ProviderConfig:
        """
        Import provider configuration from dictionary.
        
        Args:
            provider_name: Name of the OAuth provider
            config_data: Configuration data
            
        Returns:
            Provider configuration
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        return self._create_config_from_dict(provider_name, config_data)
    
    def _create_config_from_dict(self, provider_name: str, config_data: Dict[str, Any]) -> ProviderConfig:
        """
        Create ProviderConfig from dictionary data.
        
        Args:
            provider_name: Name of the OAuth provider
            config_data: Configuration data
            
        Returns:
            Provider configuration
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate configuration
        errors = self.validate_config(provider_name, config_data)
        if errors:
            raise ConfigurationError(
                f"Invalid configuration for provider {provider_name}: {'; '.join(errors)}",
                config_key=f"oauth.{provider_name}"
            )
        
        try:
            config = ProviderConfig(**config_data)
            self._configs[provider_name] = config
            return config
        except TypeError as e:
            raise ConfigurationError(
                f"Invalid configuration structure for provider {provider_name}: {e}",
                config_key=f"oauth.{provider_name}"
            )
    
    def _config_to_dict(self, config: ProviderConfig) -> Dict[str, Any]:
        """
        Convert ProviderConfig to dictionary.
        
        Args:
            config: Provider configuration
            
        Returns:
            Configuration dictionary
        """
        return {
            'client_id': config.client_id,
            'client_secret': config.client_secret,
            'redirect_uri': config.redirect_uri,
            'scopes': config.scopes,
            'authorization_url': config.authorization_url,
            'token_url': config.token_url,
            'user_info_url': config.user_info_url,
            'revoke_url': config.revoke_url,
            'extra_params': config.extra_params,
            'timeout': config.timeout,
            'use_pkce': config.use_pkce,
        }
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate if a string is a valid URL.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid
        """
        from urllib.parse import urlparse
        
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False


# Global configuration manager instance
oauth_config_manager = OAuthConfigManager()