"""
Tests for OAuth provider abstraction layer.

This module tests the OAuth provider interface, registry, configuration management,
and error handling functionality.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import TestCase

from ..exceptions import (
    ConfigurationError,
    OAuthError,
    OAuthProviderNotFoundError,
    OAuthProviderNotConfiguredError,
    OAuthScopeError,
)
from ..services.oauth_provider import (
    BaseOAuthProvider,
    IOAuthProvider,
    ProviderConfig,
    TokenData,
    NormalizedUserData,
    AuthorizationRequest,
)
from ..services.oauth_registry import (
    OAuthProviderRegistry,
    ProviderInfo,
)
from ..services.oauth_config import OAuthConfigManager
from ..services.oauth_service import OAuthService


class MockOAuthProvider(BaseOAuthProvider):
    """Mock OAuth provider for testing."""
    
    @property
    def provider_name(self) -> str:
        return "mock"
    
    @property
    def display_name(self) -> str:
        return "Mock Provider"
    
    @property
    def supported_scopes(self) -> set:
        return {"read", "write", "profile"}
    
    def get_user_info(self, access_token: str) -> NormalizedUserData:
        return NormalizedUserData(
            provider_user_id="mock_user_123",
            email="test@example.com",
            first_name="Test",
            last_name="User",
            username="testuser",
            verified_email=True,
            raw_data={"id": "mock_user_123", "name": "Test User"}
        )


class TestProviderConfig(TestCase):
    """Test ProviderConfig data structure."""
    
    def test_provider_config_creation(self):
        """Test creating a provider configuration."""
        config = ProviderConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            scopes=["read", "profile"],
            authorization_url="https://provider.com/oauth/authorize",
            token_url="https://provider.com/oauth/token",
            user_info_url="https://provider.com/oauth/userinfo",
            timeout=30,
            use_pkce=True
        )
        
        self.assertEqual(config.client_id, "test_client_id")
        self.assertEqual(config.client_secret, "test_client_secret")
        self.assertEqual(config.redirect_uri, "https://example.com/callback")
        self.assertEqual(config.scopes, ["read", "profile"])
        self.assertTrue(config.use_pkce)
        self.assertEqual(config.timeout, 30)


class TestBaseOAuthProvider(TestCase):
    """Test BaseOAuthProvider functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.provider = MockOAuthProvider()
        self.config = ProviderConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            scopes=["read", "profile"],
            authorization_url="https://provider.com/oauth/authorize",
            token_url="https://provider.com/oauth/token",
            user_info_url="https://provider.com/oauth/userinfo"
        )
    
    def test_provider_configuration(self):
        """Test provider configuration."""
        self.provider.configure(self.config)
        self.assertEqual(self.provider.config, self.config)
        self.assertTrue(self.provider.validate_configuration())
    
    def test_configuration_validation_missing_fields(self):
        """Test configuration validation with missing required fields."""
        invalid_config = ProviderConfig(
            client_id="",  # Missing required field
            client_secret="test_secret",
            redirect_uri="https://example.com/callback",
            scopes=["read"],
            authorization_url="https://provider.com/oauth/authorize",
            token_url="https://provider.com/oauth/token",
            user_info_url="https://provider.com/oauth/userinfo"
        )
        
        with self.assertRaises(ConfigurationError):
            self.provider.configure(invalid_config)
    
    def test_configuration_validation_invalid_urls(self):
        """Test configuration validation with invalid URLs."""
        invalid_config = ProviderConfig(
            client_id="test_client_id",
            client_secret="test_secret",
            redirect_uri="https://example.com/callback",
            scopes=["read"],
            authorization_url="invalid-url",  # Invalid URL
            token_url="https://provider.com/oauth/token",
            user_info_url="https://provider.com/oauth/userinfo"
        )
        
        with self.assertRaises(ConfigurationError):
            self.provider.configure(invalid_config)
    
    def test_get_authorization_url(self):
        """Test authorization URL generation."""
        self.provider.configure(self.config)
        
        auth_request = self.provider.get_authorization_url(
            state="test_state",
            scopes=["read", "profile"]
        )
        
        self.assertIsInstance(auth_request, AuthorizationRequest)
        self.assertIn("test_state", auth_request.authorization_url)
        self.assertIn("test_client_id", auth_request.authorization_url)
        self.assertIn("read+profile", auth_request.authorization_url)
        
        # Check PKCE parameters
        if self.config.use_pkce:
            self.assertIsNotNone(auth_request.code_verifier)
            self.assertIsNotNone(auth_request.code_challenge)
    
    def test_get_authorization_url_invalid_scopes(self):
        """Test authorization URL generation with invalid scopes."""
        self.provider.configure(self.config)
        
        with self.assertRaises(OAuthError):
            self.provider.get_authorization_url(
                state="test_state",
                scopes=["invalid_scope"]  # Not in supported_scopes
            )
    
    def test_exchange_code_for_token(self):
        """Test token exchange functionality."""
        self.provider.configure(self.config)
        
        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "expires_in": 3600,
            "token_type": "Bearer"
        }
        mock_response.raise_for_status.return_value = None
        
        with patch.object(self.provider, '_make_http_request') as mock_request:
            mock_request.return_value = {
                "access_token": "test_access_token",
                "refresh_token": "test_refresh_token",
                "expires_in": 3600,
                "token_type": "Bearer"
            }
            
            token_data = self.provider.exchange_code_for_token(
                code="test_code",
                state="test_state"
            )
            
            self.assertIsInstance(token_data, TokenData)
            self.assertEqual(token_data.access_token, "test_access_token")
            self.assertEqual(token_data.refresh_token, "test_refresh_token")
            self.assertEqual(token_data.expires_in, 3600)


class TestOAuthProviderRegistry(TestCase):
    """Test OAuth provider registry functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.registry = OAuthProviderRegistry()
    
    def test_register_provider(self):
        """Test provider registration."""
        self.registry.register_provider(
            name="mock",
            provider_class=MockOAuthProvider,
            display_name="Mock Provider",
            auto_configure=False
        )
        
        self.assertTrue(self.registry.is_provider_registered("mock"))
        provider_info = self.registry.get_provider_info("mock")
        self.assertEqual(provider_info.name, "mock")
        self.assertEqual(provider_info.display_name, "Mock Provider")
    
    def test_register_duplicate_provider(self):
        """Test registering duplicate provider raises error."""
        self.registry.register_provider(
            name="mock",
            provider_class=MockOAuthProvider,
            auto_configure=False
        )
        
        with self.assertRaises(ValueError):
            self.registry.register_provider(
                name="mock",
                provider_class=MockOAuthProvider,
                auto_configure=False
            )
    
    def test_register_invalid_provider_class(self):
        """Test registering invalid provider class raises error."""
        class InvalidProvider:
            pass
        
        with self.assertRaises(TypeError):
            self.registry.register_provider(
                name="invalid",
                provider_class=InvalidProvider,
                auto_configure=False
            )
    
    def test_configure_provider(self):
        """Test provider configuration."""
        self.registry.register_provider(
            name="mock",
            provider_class=MockOAuthProvider,
            auto_configure=False
        )
        
        config = ProviderConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            scopes=["read", "profile"],
            authorization_url="https://provider.com/oauth/authorize",
            token_url="https://provider.com/oauth/token",
            user_info_url="https://provider.com/oauth/userinfo"
        )
        
        self.registry.configure_provider("mock", config)
        self.assertTrue(self.registry.is_provider_configured("mock"))
    
    def test_get_provider(self):
        """Test getting configured provider instance."""
        self.registry.register_provider(
            name="mock",
            provider_class=MockOAuthProvider,
            auto_configure=False
        )
        
        config = ProviderConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            scopes=["read", "profile"],
            authorization_url="https://provider.com/oauth/authorize",
            token_url="https://provider.com/oauth/token",
            user_info_url="https://provider.com/oauth/userinfo"
        )
        
        self.registry.configure_provider("mock", config)
        
        provider = self.registry.get_provider("mock")
        self.assertIsInstance(provider, MockOAuthProvider)
        self.assertEqual(provider.config, config)
    
    def test_get_nonexistent_provider(self):
        """Test getting nonexistent provider raises error."""
        with self.assertRaises(KeyError):
            self.registry.get_provider("nonexistent")
    
    def test_get_unconfigured_provider(self):
        """Test getting unconfigured provider raises error."""
        self.registry.register_provider(
            name="mock",
            provider_class=MockOAuthProvider,
            auto_configure=False
        )
        
        with self.assertRaises(ConfigurationError):
            self.registry.get_provider("mock")
    
    def test_list_providers(self):
        """Test listing providers with filters."""
        self.registry.register_provider(
            name="mock1",
            provider_class=MockOAuthProvider,
            auto_configure=False
        )
        self.registry.register_provider(
            name="mock2",
            provider_class=MockOAuthProvider,
            auto_configure=False
        )
        
        # Configure only one provider
        config = ProviderConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            scopes=["read"],
            authorization_url="https://provider.com/oauth/authorize",
            token_url="https://provider.com/oauth/token",
            user_info_url="https://provider.com/oauth/userinfo"
        )
        self.registry.configure_provider("mock1", config)
        
        # Test listing all providers
        all_providers = self.registry.list_providers()
        self.assertEqual(len(all_providers), 2)
        
        # Test listing configured providers only
        configured_providers = self.registry.list_providers(configured_only=True)
        self.assertEqual(len(configured_providers), 1)
        self.assertEqual(configured_providers[0].name, "mock1")
    
    def test_enable_disable_provider(self):
        """Test enabling and disabling providers."""
        self.registry.register_provider(
            name="mock",
            provider_class=MockOAuthProvider,
            auto_configure=False
        )
        
        # Provider should be enabled by default
        provider_info = self.registry.get_provider_info("mock")
        self.assertTrue(provider_info.is_enabled)
        
        # Disable provider
        self.registry.disable_provider("mock")
        provider_info = self.registry.get_provider_info("mock")
        self.assertFalse(provider_info.is_enabled)
        
        # Enable provider
        self.registry.enable_provider("mock")
        provider_info = self.registry.get_provider_info("mock")
        self.assertTrue(provider_info.is_enabled)


class TestOAuthConfigManager(TestCase):
    """Test OAuth configuration manager functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config_manager = OAuthConfigManager()
    
    def test_create_config(self):
        """Test creating provider configuration."""
        config = self.config_manager.create_config(
            provider_name="test",
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            scopes=["read", "profile"],
            authorization_url="https://provider.com/oauth/authorize",
            token_url="https://provider.com/oauth/token",
            user_info_url="https://provider.com/oauth/userinfo"
        )
        
        self.assertIsInstance(config, ProviderConfig)
        self.assertEqual(config.client_id, "test_client_id")
        self.assertEqual(config.scopes, ["read", "profile"])
    
    def test_validate_config(self):
        """Test configuration validation."""
        valid_config = {
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "redirect_uri": "https://example.com/callback",
            "scopes": ["read", "profile"],
            "authorization_url": "https://provider.com/oauth/authorize",
            "token_url": "https://provider.com/oauth/token",
            "user_info_url": "https://provider.com/oauth/userinfo"
        }
        
        errors = self.config_manager.validate_config("test", valid_config)
        self.assertEqual(len(errors), 0)
        
        # Test invalid configuration
        invalid_config = valid_config.copy()
        invalid_config["client_id"] = ""  # Missing required field
        
        errors = self.config_manager.validate_config("test", invalid_config)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("client_id" in error for error in errors))
    
    def test_export_import_config(self):
        """Test configuration export and import."""
        config = self.config_manager.create_config(
            provider_name="test",
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            scopes=["read", "profile"],
            authorization_url="https://provider.com/oauth/authorize",
            token_url="https://provider.com/oauth/token",
            user_info_url="https://provider.com/oauth/userinfo"
        )
        
        # Export configuration
        exported = self.config_manager.export_config("test", include_secrets=True)
        self.assertIsNotNone(exported)
        self.assertEqual(exported["client_id"], "test_client_id")
        
        # Export without secrets
        exported_no_secrets = self.config_manager.export_config("test", include_secrets=False)
        self.assertEqual(exported_no_secrets["client_secret"], "[REDACTED]")
        
        # Import configuration
        imported_config = self.config_manager.import_config("test2", exported)
        self.assertEqual(imported_config.client_id, "test_client_id")


class TestOAuthService(TestCase):
    """Test OAuth service functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.oauth_service = OAuthService()
        
        # Register mock provider
        self.oauth_service.registry.register_provider(
            name="mock",
            provider_class=MockOAuthProvider,
            auto_configure=False
        )
        
        # Configure mock provider
        config = ProviderConfig(
            client_id="test_client_id",
            client_secret="test_client_secret",
            redirect_uri="https://example.com/callback",
            scopes=["read", "profile"],
            authorization_url="https://provider.com/oauth/authorize",
            token_url="https://provider.com/oauth/token",
            user_info_url="https://provider.com/oauth/userinfo"
        )
        self.oauth_service.registry.configure_provider("mock", config)
    
    def test_get_available_providers(self):
        """Test getting available providers."""
        providers = self.oauth_service.get_available_providers()
        self.assertEqual(len(providers), 1)
        self.assertEqual(providers[0]["name"], "mock")
    
    def test_get_provider(self):
        """Test getting provider instance."""
        provider = self.oauth_service.get_provider("mock")
        self.assertIsInstance(provider, MockOAuthProvider)
    
    def test_get_nonexistent_provider(self):
        """Test getting nonexistent provider raises appropriate error."""
        with self.assertRaises(OAuthProviderNotFoundError):
            self.oauth_service.get_provider("nonexistent")
    
    def test_initiate_authorization(self):
        """Test initiating OAuth authorization."""
        auth_request = self.oauth_service.initiate_authorization(
            provider_name="mock",
            state="test_state",
            scopes=["read", "profile"]
        )
        
        self.assertIsInstance(auth_request, AuthorizationRequest)
        self.assertIn("test_state", auth_request.authorization_url)
    
    def test_initiate_authorization_invalid_scopes(self):
        """Test initiating authorization with invalid scopes."""
        with self.assertRaises(OAuthScopeError):
            self.oauth_service.initiate_authorization(
                provider_name="mock",
                state="test_state",
                scopes=["invalid_scope"]
            )
    
    def test_validate_provider_configuration(self):
        """Test provider configuration validation."""
        errors = self.oauth_service.validate_provider_configuration("mock")
        self.assertEqual(len(errors), 0)
        
        # Test with nonexistent provider
        errors = self.oauth_service.validate_provider_configuration("nonexistent")
        self.assertGreater(len(errors), 0)
    
    def test_get_provider_health_status(self):
        """Test getting provider health status."""
        health_status = self.oauth_service.get_provider_health_status()
        
        self.assertIn("total_providers", health_status)
        self.assertIn("configured_providers", health_status)
        self.assertIn("provider_status", health_status)
        self.assertIn("mock", health_status["provider_status"])