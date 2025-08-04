"""
OAuth provider registry for dynamic provider management.

This module provides a centralized registry for managing OAuth providers,
enabling dynamic provider registration, configuration, and lifecycle management.
"""

import logging
from typing import Any, Dict, List, Optional, Type, Union

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from ..exceptions import ConfigurationError, OAuthError
from .oauth_provider import IOAuthProvider, ProviderConfig

logger = logging.getLogger(__name__)


class ProviderInfo:
    """Information about a registered OAuth provider."""
    
    def __init__(
        self,
        name: str,
        display_name: str,
        provider_class: Type[IOAuthProvider],
        is_configured: bool = False,
        is_enabled: bool = True,
        supported_scopes: Optional[List[str]] = None,
        description: Optional[str] = None,
        icon_url: Optional[str] = None,
        documentation_url: Optional[str] = None
    ):
        self.name = name
        self.display_name = display_name
        self.provider_class = provider_class
        self.is_configured = is_configured
        self.is_enabled = is_enabled
        self.supported_scopes = supported_scopes or []
        self.description = description
        self.icon_url = icon_url
        self.documentation_url = documentation_url
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert provider info to dictionary."""
        return {
            'name': self.name,
            'display_name': self.display_name,
            'is_configured': self.is_configured,
            'is_enabled': self.is_enabled,
            'supported_scopes': self.supported_scopes,
            'description': self.description,
            'icon_url': self.icon_url,
            'documentation_url': self.documentation_url,
        }


class OAuthProviderRegistry:
    """
    Registry for managing OAuth providers dynamically.
    
    This class provides a centralized way to register, configure, and manage
    OAuth providers throughout the application lifecycle.
    """
    
    def __init__(self):
        """Initialize the provider registry."""
        self._providers: Dict[str, ProviderInfo] = {}
        self._instances: Dict[str, IOAuthProvider] = {}
        self._configurations: Dict[str, ProviderConfig] = {}
        self._initialized = False
    
    def register_provider(
        self,
        name: str,
        provider_class: Type[IOAuthProvider],
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        icon_url: Optional[str] = None,
        documentation_url: Optional[str] = None,
        auto_configure: bool = True
    ) -> None:
        """
        Register a new OAuth provider.
        
        Args:
            name: Unique provider name (e.g., 'google', 'github')
            provider_class: Provider implementation class
            display_name: Human-readable provider name
            description: Provider description
            icon_url: URL to provider icon
            documentation_url: URL to provider documentation
            auto_configure: Whether to automatically configure from settings
            
        Raises:
            ValueError: If provider name is already registered
            TypeError: If provider_class doesn't implement IOAuthProvider
        """
        if name in self._providers:
            raise ValueError(f"Provider '{name}' is already registered")
        
        if not issubclass(provider_class, IOAuthProvider):
            raise TypeError(
                f"Provider class must implement IOAuthProvider interface"
            )
        
        # Create provider instance to get metadata
        try:
            temp_instance = provider_class()
            supported_scopes = list(temp_instance.supported_scopes)
            if not display_name:
                display_name = temp_instance.display_name
        except Exception as e:
            logger.error(
                f"Failed to create temporary instance of provider {name}",
                extra={'provider': name, 'error': str(e)}
            )
            supported_scopes = []
            if not display_name:
                display_name = name.title()
        
        # Register provider info
        provider_info = ProviderInfo(
            name=name,
            display_name=display_name,
            provider_class=provider_class,
            supported_scopes=supported_scopes,
            description=description,
            icon_url=icon_url,
            documentation_url=documentation_url
        )
        
        self._providers[name] = provider_info
        
        # Auto-configure if requested and configuration exists
        if auto_configure:
            try:
                self._auto_configure_provider(name)
            except ConfigurationError as e:
                logger.warning(
                    f"Auto-configuration failed for provider {name}: {e}",
                    extra={'provider': name}
                )
        
        logger.info(
            f"Registered OAuth provider: {name}",
            extra={
                'provider': name,
                'display_name': display_name,
                'auto_configure': auto_configure,
            }
        )
    
    def unregister_provider(self, name: str) -> None:
        """
        Unregister an OAuth provider.
        
        Args:
            name: Provider name to unregister
            
        Raises:
            KeyError: If provider is not registered
        """
        if name not in self._providers:
            raise KeyError(f"Provider '{name}' is not registered")
        
        # Clean up instances and configurations
        self._instances.pop(name, None)
        self._configurations.pop(name, None)
        del self._providers[name]
        
        logger.info(f"Unregistered OAuth provider: {name}")
    
    def configure_provider(self, name: str, config: Union[ProviderConfig, Dict[str, Any]]) -> None:
        """
        Configure an OAuth provider.
        
        Args:
            name: Provider name
            config: Provider configuration
            
        Raises:
            KeyError: If provider is not registered
            ConfigurationError: If configuration is invalid
        """
        if name not in self._providers:
            raise KeyError(f"Provider '{name}' is not registered")
        
        # Convert dict to ProviderConfig if needed
        if isinstance(config, dict):
            try:
                config = ProviderConfig(**config)
            except TypeError as e:
                raise ConfigurationError(
                    f"Invalid configuration for provider {name}: {e}",
                    config_key=f"oauth.{name}"
                )
        
        # Store configuration
        self._configurations[name] = config
        
        # Update provider info
        self._providers[name].is_configured = True
        
        # Clear existing instance to force reconfiguration
        self._instances.pop(name, None)
        
        logger.info(
            f"Configured OAuth provider: {name}",
            extra={'provider': name}
        )
    
    def get_provider(self, name: str) -> IOAuthProvider:
        """
        Get a configured OAuth provider instance.
        
        Args:
            name: Provider name
            
        Returns:
            Configured provider instance
            
        Raises:
            KeyError: If provider is not registered
            ConfigurationError: If provider is not configured
        """
        if name not in self._providers:
            raise KeyError(f"Provider '{name}' is not registered")
        
        provider_info = self._providers[name]
        
        if not provider_info.is_configured:
            raise ConfigurationError(
                f"Provider '{name}' is not configured",
                config_key=f"oauth.{name}"
            )
        
        if not provider_info.is_enabled:
            raise OAuthError(f"Provider '{name}' is disabled")
        
        # Return cached instance if available
        if name in self._instances:
            return self._instances[name]
        
        # Create and configure new instance
        try:
            instance = provider_info.provider_class()
            config = self._configurations[name]
            instance.configure(config)
            
            # Cache the instance
            self._instances[name] = instance
            
            logger.debug(
                f"Created provider instance: {name}",
                extra={'provider': name}
            )
            
            return instance
            
        except Exception as e:
            logger.error(
                f"Failed to create provider instance: {name}",
                extra={'provider': name, 'error': str(e)}
            )
            raise ConfigurationError(
                f"Failed to create provider instance for '{name}': {e}",
                config_key=f"oauth.{name}"
            )
    
    def list_providers(
        self,
        configured_only: bool = False,
        enabled_only: bool = False
    ) -> List[ProviderInfo]:
        """
        List registered OAuth providers.
        
        Args:
            configured_only: Only return configured providers
            enabled_only: Only return enabled providers
            
        Returns:
            List of provider information
        """
        providers = list(self._providers.values())
        
        if configured_only:
            providers = [p for p in providers if p.is_configured]
        
        if enabled_only:
            providers = [p for p in providers if p.is_enabled]
        
        return providers
    
    def get_provider_info(self, name: str) -> ProviderInfo:
        """
        Get information about a registered provider.
        
        Args:
            name: Provider name
            
        Returns:
            Provider information
            
        Raises:
            KeyError: If provider is not registered
        """
        if name not in self._providers:
            raise KeyError(f"Provider '{name}' is not registered")
        
        return self._providers[name]
    
    def is_provider_registered(self, name: str) -> bool:
        """
        Check if a provider is registered.
        
        Args:
            name: Provider name
            
        Returns:
            True if provider is registered
        """
        return name in self._providers
    
    def is_provider_configured(self, name: str) -> bool:
        """
        Check if a provider is configured.
        
        Args:
            name: Provider name
            
        Returns:
            True if provider is configured
            
        Raises:
            KeyError: If provider is not registered
        """
        if name not in self._providers:
            raise KeyError(f"Provider '{name}' is not registered")
        
        return self._providers[name].is_configured
    
    def enable_provider(self, name: str) -> None:
        """
        Enable a provider.
        
        Args:
            name: Provider name
            
        Raises:
            KeyError: If provider is not registered
        """
        if name not in self._providers:
            raise KeyError(f"Provider '{name}' is not registered")
        
        self._providers[name].is_enabled = True
        logger.info(f"Enabled OAuth provider: {name}")
    
    def disable_provider(self, name: str) -> None:
        """
        Disable a provider.
        
        Args:
            name: Provider name
            
        Raises:
            KeyError: If provider is not registered
        """
        if name not in self._providers:
            raise KeyError(f"Provider '{name}' is not registered")
        
        self._providers[name].is_enabled = False
        
        # Clear cached instance
        self._instances.pop(name, None)
        
        logger.info(f"Disabled OAuth provider: {name}")
    
    def get_available_providers(self) -> List[Dict[str, Any]]:
        """
        Get list of available providers for client applications.
        
        Returns:
            List of provider information dictionaries
        """
        providers = self.list_providers(configured_only=True, enabled_only=True)
        return [provider.to_dict() for provider in providers]
    
    def initialize_from_settings(self) -> None:
        """
        Initialize providers from Django settings.
        
        This method reads OAuth provider configurations from Django settings
        and automatically registers and configures providers.
        """
        if self._initialized:
            return
        
        oauth_settings = getattr(settings, 'OAUTH_PROVIDERS', {})
        
        for provider_name, provider_config in oauth_settings.items():
            try:
                # Skip if provider is already registered
                if self.is_provider_registered(provider_name):
                    continue
                
                # Get provider class from config
                provider_class_path = provider_config.get('provider_class')
                if not provider_class_path:
                    logger.warning(
                        f"No provider_class specified for {provider_name}",
                        extra={'provider': provider_name}
                    )
                    continue
                
                # Import provider class
                provider_class = self._import_provider_class(provider_class_path)
                
                # Register provider
                self.register_provider(
                    name=provider_name,
                    provider_class=provider_class,
                    display_name=provider_config.get('display_name'),
                    description=provider_config.get('description'),
                    icon_url=provider_config.get('icon_url'),
                    documentation_url=provider_config.get('documentation_url'),
                    auto_configure=False  # We'll configure manually
                )
                
                # Configure provider
                config_data = {
                    key: value for key, value in provider_config.items()
                    if key not in ['provider_class', 'display_name', 'description', 'icon_url', 'documentation_url']
                }
                
                if config_data:
                    self.configure_provider(provider_name, config_data)
                
                # Enable/disable based on settings
                if provider_config.get('enabled', True):
                    self.enable_provider(provider_name)
                else:
                    self.disable_provider(provider_name)
                
            except Exception as e:
                logger.error(
                    f"Failed to initialize provider {provider_name} from settings",
                    extra={'provider': provider_name, 'error': str(e)}
                )
        
        self._initialized = True
        logger.info("Initialized OAuth providers from settings")
    
    def _auto_configure_provider(self, name: str) -> None:
        """
        Automatically configure a provider from Django settings.
        
        Args:
            name: Provider name
        """
        oauth_settings = getattr(settings, 'OAUTH_PROVIDERS', {})
        provider_settings = oauth_settings.get(name, {})
        
        if not provider_settings:
            raise ConfigurationError(
                f"No configuration found for provider {name}",
                config_key=f"OAUTH_PROVIDERS.{name}"
            )
        
        # Extract configuration fields
        config_data = {
            key: value for key, value in provider_settings.items()
            if key not in ['provider_class', 'display_name', 'description', 'icon_url', 'documentation_url', 'enabled']
        }
        
        if config_data:
            self.configure_provider(name, config_data)
    
    def _import_provider_class(self, class_path: str) -> Type[IOAuthProvider]:
        """
        Import a provider class from a string path.
        
        Args:
            class_path: Dotted path to provider class
            
        Returns:
            Provider class
            
        Raises:
            ImportError: If class cannot be imported
            TypeError: If class doesn't implement IOAuthProvider
        """
        try:
            module_path, class_name = class_path.rsplit('.', 1)
            module = __import__(module_path, fromlist=[class_name])
            provider_class = getattr(module, class_name)
            
            if not issubclass(provider_class, IOAuthProvider):
                raise TypeError(
                    f"Provider class {class_path} must implement IOAuthProvider"
                )
            
            return provider_class
            
        except (ImportError, AttributeError, ValueError) as e:
            raise ImportError(f"Cannot import provider class {class_path}: {e}")
    
    def clear_cache(self) -> None:
        """Clear all cached provider instances."""
        self._instances.clear()
        logger.info("Cleared OAuth provider instance cache")
    
    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on all configured providers.
        
        Returns:
            Health check results
        """
        results = {
            'total_providers': len(self._providers),
            'configured_providers': len([p for p in self._providers.values() if p.is_configured]),
            'enabled_providers': len([p for p in self._providers.values() if p.is_enabled]),
            'provider_status': {}
        }
        
        for name, provider_info in self._providers.items():
            status = {
                'registered': True,
                'configured': provider_info.is_configured,
                'enabled': provider_info.is_enabled,
                'healthy': False
            }
            
            if provider_info.is_configured and provider_info.is_enabled:
                try:
                    provider = self.get_provider(name)
                    status['healthy'] = provider.validate_configuration()
                except Exception as e:
                    status['error'] = str(e)
            
            results['provider_status'][name] = status
        
        return results


# Global registry instance
oauth_registry = OAuthProviderRegistry()