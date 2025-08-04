"""
Tests for core utilities including encryption, correlation ID, and error handling.
"""

import uuid
from unittest.mock import Mock, patch

from django.test import TestCase, RequestFactory
from django.http import JsonResponse
from django.contrib.auth.models import AnonymousUser

from enterprise_auth.core.utils.encryption import (
    EncryptionService,
    HashingService,
    encrypt_sensitive_data,
    decrypt_sensitive_data,
    hash_sensitive_data,
    verify_sensitive_hash,
    EncryptionError,
    DecryptionError,
)
from enterprise_auth.core.utils.correlation import (
    CorrelationIDMiddleware,
    get_correlation_id,
    set_correlation_id,
    clear_correlation_id,
    generate_correlation_id,
    CorrelationContext,
)
from enterprise_auth.core.utils.error_handling import (
    ErrorHandlingMiddleware,
    handle_error_response,
)
from enterprise_auth.core.exceptions import (
    EnterpriseAuthError,
    AuthenticationError,
    InvalidCredentialsError,
    TokenExpiredError,
)


class EncryptionServiceTest(TestCase):
    """Test cases for encryption utilities."""
    
    def setUp(self):
        self.encryption_service = EncryptionService()
        self.test_data = "sensitive_test_data_123"
    
    def test_encrypt_decrypt_string(self):
        """Test encryption and decryption of string data."""
        encrypted = self.encryption_service.encrypt(self.test_data)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(encrypted, self.test_data)
        
        decrypted = self.encryption_service.decrypt(encrypted)
        self.assertEqual(decrypted, self.test_data)
    
    def test_encrypt_decrypt_bytes(self):
        """Test encryption and decryption of bytes data."""
        test_bytes = self.test_data.encode('utf-8')
        encrypted = self.encryption_service.encrypt(test_bytes)
        decrypted = self.encryption_service.decrypt(encrypted)
        self.assertEqual(decrypted, self.test_data)
    
    def test_encrypt_decrypt_dict(self):
        """Test encryption and decryption of dictionary data."""
        test_dict = {
            'username': 'testuser',
            'password': 'secret123',
            'metadata': {
                'token': 'abc123',
                'refresh': 'def456'
            },
            'count': 42  # Non-string value should remain unchanged
        }
        
        encrypted_dict = self.encryption_service.encrypt_dict(test_dict)
        self.assertNotEqual(encrypted_dict['username'], test_dict['username'])
        self.assertNotEqual(encrypted_dict['password'], test_dict['password'])
        self.assertEqual(encrypted_dict['count'], test_dict['count'])
        
        decrypted_dict = self.encryption_service.decrypt_dict(encrypted_dict)
        self.assertEqual(decrypted_dict, test_dict)
    
    def test_different_salts_produce_different_results(self):
        """Test that same data with different salts produces different encrypted values."""
        encrypted1 = self.encryption_service.encrypt(self.test_data)
        encrypted2 = self.encryption_service.encrypt(self.test_data)
        self.assertNotEqual(encrypted1, encrypted2)
        
        # But both should decrypt to the same value
        self.assertEqual(
            self.encryption_service.decrypt(encrypted1),
            self.encryption_service.decrypt(encrypted2)
        )
    
    def test_invalid_encrypted_data_raises_error(self):
        """Test that invalid encrypted data raises DecryptionError."""
        with self.assertRaises(DecryptionError):
            self.encryption_service.decrypt("invalid_encrypted_data")
    
    def test_convenience_functions(self):
        """Test convenience encryption/decryption functions."""
        encrypted = encrypt_sensitive_data(self.test_data)
        decrypted = decrypt_sensitive_data(encrypted)
        self.assertEqual(decrypted, self.test_data)


class HashingServiceTest(TestCase):
    """Test cases for hashing utilities."""
    
    def setUp(self):
        self.test_data = "test_data_to_hash"
    
    def test_hash_and_verify(self):
        """Test hashing and verification of data."""
        hashed = HashingService.hash_data(self.test_data)
        self.assertIsInstance(hashed, str)
        self.assertNotEqual(hashed, self.test_data)
        
        # Verify correct data
        self.assertTrue(HashingService.verify_hash(self.test_data, hashed))
        
        # Verify incorrect data
        self.assertFalse(HashingService.verify_hash("wrong_data", hashed))
    
    def test_same_data_different_hashes(self):
        """Test that same data produces different hashes due to random salt."""
        hash1 = HashingService.hash_data(self.test_data)
        hash2 = HashingService.hash_data(self.test_data)
        self.assertNotEqual(hash1, hash2)
        
        # But both should verify correctly
        self.assertTrue(HashingService.verify_hash(self.test_data, hash1))
        self.assertTrue(HashingService.verify_hash(self.test_data, hash2))
    
    def test_convenience_functions(self):
        """Test convenience hashing functions."""
        hashed = hash_sensitive_data(self.test_data)
        self.assertTrue(verify_sensitive_hash(self.test_data, hashed))
        self.assertFalse(verify_sensitive_hash("wrong_data", hashed))


class CorrelationIDTest(TestCase):
    """Test cases for correlation ID utilities."""
    
    def setUp(self):
        self.factory = RequestFactory()
        # Mock get_response for middleware
        self.get_response = Mock(return_value=JsonResponse({'test': 'response'}))
        self.middleware = CorrelationIDMiddleware(self.get_response)
        clear_correlation_id()  # Ensure clean state
    
    def test_correlation_id_generation(self):
        """Test correlation ID generation."""
        correlation_id = generate_correlation_id()
        self.assertIsInstance(correlation_id, str)
        # Should be a valid UUID
        uuid.UUID(correlation_id)
    
    def test_correlation_id_middleware_sets_id(self):
        """Test that middleware sets correlation ID on request."""
        request = self.factory.get('/')
        
        self.middleware.process_request(request)
        
        self.assertTrue(hasattr(request, 'correlation_id'))
        self.assertIsNotNone(request.correlation_id)
        self.assertEqual(get_correlation_id(), request.correlation_id)
    
    def test_correlation_id_middleware_uses_existing_header(self):
        """Test that middleware uses existing correlation ID from headers."""
        existing_id = str(uuid.uuid4())
        request = self.factory.get('/', HTTP_X_CORRELATION_ID=existing_id)
        
        self.middleware.process_request(request)
        
        self.assertEqual(request.correlation_id, existing_id)
        self.assertEqual(get_correlation_id(), existing_id)
    
    def test_correlation_id_middleware_adds_response_header(self):
        """Test that middleware adds correlation ID to response headers."""
        request = self.factory.get('/')
        response = JsonResponse({'test': 'data'})
        
        self.middleware.process_request(request)
        processed_response = self.middleware.process_response(request, response)
        
        self.assertIn('X-Correlation-ID', processed_response)
        self.assertEqual(processed_response['X-Correlation-ID'], request.correlation_id)
    
    def test_correlation_context_manager(self):
        """Test correlation ID context manager."""
        test_id = str(uuid.uuid4())
        
        self.assertIsNone(get_correlation_id())
        
        with CorrelationContext(test_id) as context_id:
            self.assertEqual(context_id, test_id)
            self.assertEqual(get_correlation_id(), test_id)
        
        self.assertIsNone(get_correlation_id())
    
    def test_correlation_context_manager_with_existing_id(self):
        """Test correlation context manager with existing correlation ID."""
        existing_id = str(uuid.uuid4())
        new_id = str(uuid.uuid4())
        
        set_correlation_id(existing_id)
        
        with CorrelationContext(new_id):
            self.assertEqual(get_correlation_id(), new_id)
        
        self.assertEqual(get_correlation_id(), existing_id)


class ErrorHandlingTest(TestCase):
    """Test cases for error handling utilities."""
    
    def setUp(self):
        self.factory = RequestFactory()
        # Mock get_response for middleware
        self.get_response = Mock(return_value=JsonResponse({'test': 'response'}))
        self.middleware = ErrorHandlingMiddleware(self.get_response)
    
    def test_enterprise_auth_error_handling(self):
        """Test handling of custom enterprise auth errors."""
        request = self.factory.get('/')
        request.user = AnonymousUser()
        
        error = InvalidCredentialsError(
            message="Test error message",
            details={'field': 'password'}
        )
        
        response = self.middleware._handle_enterprise_auth_error(request, error)
        
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 401)
        
        # Parse response content
        import json
        content = json.loads(response.content)
        self.assertEqual(content['error']['code'], 'INVALID_CREDENTIALS')
        self.assertEqual(content['error']['message'], 'Test error message')
        self.assertEqual(content['error']['details']['field'], 'password')
    
    def test_handle_error_response_utility(self):
        """Test error response utility function."""
        response = handle_error_response(
            error_code='TEST_ERROR',
            message='Test error message',
            status_code=400,
            details={'field': 'test'},
            correlation_id='test-correlation-id'
        )
        
        self.assertIsInstance(response, JsonResponse)
        self.assertEqual(response.status_code, 400)
        
        import json
        content = json.loads(response.content)
        self.assertEqual(content['error']['code'], 'TEST_ERROR')
        self.assertEqual(content['error']['message'], 'Test error message')
        self.assertEqual(content['error']['details']['field'], 'test')
        self.assertEqual(content['error']['correlation_id'], 'test-correlation-id')


class ExceptionsTest(TestCase):
    """Test cases for custom exception classes."""
    
    def test_base_enterprise_auth_error(self):
        """Test base enterprise auth error."""
        error = EnterpriseAuthError(
            message="Test error",
            error_code="TEST_ERROR",
            details={'key': 'value'},
            correlation_id='test-id'
        )
        
        self.assertEqual(str(error), "Test error")
        self.assertEqual(error.error_code, "TEST_ERROR")
        self.assertEqual(error.details, {'key': 'value'})
        self.assertEqual(error.correlation_id, 'test-id')
        
        error_dict = error.to_dict()
        expected = {
            'error': {
                'code': 'TEST_ERROR',
                'message': 'Test error',
                'details': {'key': 'value'},
                'correlation_id': 'test-id'
            }
        }
        self.assertEqual(error_dict, expected)
    
    def test_authentication_error_inheritance(self):
        """Test that authentication errors inherit properly."""
        error = InvalidCredentialsError()
        self.assertIsInstance(error, AuthenticationError)
        self.assertIsInstance(error, EnterpriseAuthError)
        self.assertEqual(error.error_code, "INVALID_CREDENTIALS")
    
    def test_token_error_inheritance(self):
        """Test that token errors inherit properly."""
        error = TokenExpiredError()
        self.assertEqual(error.error_code, "TOKEN_EXPIRED")
        self.assertEqual(error.message, "Token has expired")