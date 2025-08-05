"""
Tests for session models and device fingerprinting functionality.
"""

import uuid
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from django.test import TestCase, RequestFactory
from django.utils import timezone
from django.contrib.auth import get_user_model

from ..models.session import UserSession, DeviceInfo, SessionActivity
from ..models.user import UserProfile
from ..services.session_service import SessionService, create_user_session
from ..utils.device_fingerprinting import DeviceFingerprinter, generate_device_fingerprint
from ..utils.geolocation import GeolocationService, get_client_ip


class DeviceInfoModelTest(TestCase):
    """Test DeviceInfo model functionality."""
    
    def setUp(self):
        self.device_data = {
            'device_fingerprint': 'test_fingerprint_123',
            'device_type': 'desktop',
            'browser': 'Chrome 120.0',
            'operating_system': 'Windows 11',
            'screen_resolution': '1920x1080',
            'timezone_offset': -300,
            'language': 'en-US',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'device_characteristics': {
                'screen_color_depth': 24,
                'timezone': 'America/New_York',
                'platform': 'Win32',
            }
        }
    
    def test_device_info_creation(self):
        """Test creating a DeviceInfo instance."""
        device = DeviceInfo.objects.create(**self.device_data)
        
        self.assertEqual(device.device_fingerprint, 'test_fingerprint_123')
        self.assertEqual(device.device_type, 'desktop')
        self.assertEqual(device.browser, 'Chrome 120.0')
        self.assertEqual(device.operating_system, 'Windows 11')
        self.assertFalse(device.is_trusted)
        self.assertIsNotNone(device.first_seen)
        self.assertIsNotNone(device.last_seen)
    
    def test_device_info_str_representation(self):
        """Test string representation of DeviceInfo."""
        device = DeviceInfo.objects.create(**self.device_data)
        expected_str = "desktop - Chrome 120.0 on Windows 11"
        self.assertEqual(str(device), expected_str)


class UserSessionModelTest(TestCase):
    """Test UserSession model functionality."""
    
    def setUp(self):
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        self.device = DeviceInfo.objects.create(
            device_fingerprint='test_fingerprint_123',
            device_type='desktop',
            browser='Chrome 120.0',
            operating_system='Windows 11',
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        
        self.session_data = {
            'session_id': 'sess_' + uuid.uuid4().hex,
            'user': self.user,
            'device_info': self.device,
            'ip_address': '192.168.1.100',
            'country': 'United States',
            'region': 'California',
            'city': 'San Francisco',
            'latitude': 37.7749,
            'longitude': -122.4194,
            'isp': 'Test ISP',
            'login_method': 'password',
            'expires_at': timezone.now() + timedelta(hours=24),
        }
    
    def test_session_creation(self):
        """Test creating a UserSession instance."""
        session = UserSession.objects.create(**self.session_data)
        
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.device_info, self.device)
        self.assertEqual(session.status, 'active')
        self.assertEqual(session.risk_score, 0.0)
        self.assertTrue(session.is_active)
        self.assertFalse(session.is_expired)
    
    def test_session_expiration(self):
        """Test session expiration logic."""
        # Create expired session
        expired_session_data = self.session_data.copy()
        expired_session_data['expires_at'] = timezone.now() - timedelta(hours=1)
        expired_session_data['session_id'] = 'sess_expired_' + uuid.uuid4().hex
        
        session = UserSession.objects.create(**expired_session_data)
        
        self.assertFalse(session.is_active)
        self.assertTrue(session.is_expired)
    
    def test_session_termination(self):
        """Test session termination functionality."""
        session = UserSession.objects.create(**self.session_data)
        
        # Terminate session
        session.terminate(terminated_by=self.user, reason='user_logout')
        
        self.assertEqual(session.status, 'terminated')
        self.assertIsNotNone(session.terminated_at)
        self.assertEqual(session.terminated_by, self.user)
        self.assertEqual(session.termination_reason, 'user_logout')
        self.assertFalse(session.is_active)
    
    def test_location_string_property(self):
        """Test location string formatting."""
        session = UserSession.objects.create(**self.session_data)
        expected_location = "San Francisco, California, United States"
        self.assertEqual(session.location_string, expected_location)
    
    def test_session_duration_property(self):
        """Test session duration calculation."""
        session = UserSession.objects.create(**self.session_data)
        
        # Duration should be very small for a just-created session
        duration = session.duration
        self.assertIsInstance(duration, timedelta)
        self.assertLess(duration.total_seconds(), 5)  # Less than 5 seconds
    
    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        session = UserSession.objects.create(**self.session_data)
        
        # Calculate risk score
        risk_score = session.calculate_risk_score()
        
        self.assertIsInstance(risk_score, float)
        self.assertGreaterEqual(risk_score, 0.0)
        self.assertLessEqual(risk_score, 100.0)
        self.assertIsInstance(session.risk_factors, dict)


class DeviceFingerprintingTest(TestCase):
    """Test device fingerprinting functionality."""
    
    def setUp(self):
        self.factory = RequestFactory()
        self.fingerprinter = DeviceFingerprinter()
    
    def test_generate_fingerprint(self):
        """Test fingerprint generation from request."""
        request = self.factory.get('/')
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        request.META['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9'
        
        additional_data = {
            'screen_resolution': '1920x1080',
            'timezone_offset': -300,
            'language': 'en-US',
        }
        
        fingerprint = self.fingerprinter.generate_fingerprint(request, additional_data)
        
        self.assertIsInstance(fingerprint, str)
        self.assertEqual(len(fingerprint), 64)  # SHA256 hash length
    
    def test_extract_device_info(self):
        """Test device information extraction."""
        request = self.factory.get('/')
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        request.META['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9'
        
        additional_data = {
            'screen_resolution': '1920x1080',
            'timezone_offset': -300,
        }
        
        device_info = self.fingerprinter.extract_device_info(request, additional_data)
        
        self.assertIn('device_type', device_info)
        self.assertIn('browser', device_info)
        self.assertIn('operating_system', device_info)
        self.assertEqual(device_info['screen_resolution'], '1920x1080')
        self.assertEqual(device_info['timezone_offset'], -300)
    
    def test_generate_device_fingerprint_convenience_function(self):
        """Test convenience function for fingerprint generation."""
        request = self.factory.get('/')
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        
        fingerprint, device_info = generate_device_fingerprint(request)
        
        self.assertIsInstance(fingerprint, str)
        self.assertIsInstance(device_info, dict)
        self.assertEqual(len(fingerprint), 64)


class GeolocationServiceTest(TestCase):
    """Test geolocation service functionality."""
    
    def setUp(self):
        self.geolocation_service = GeolocationService()
        self.factory = RequestFactory()
    
    def test_private_ip_detection(self):
        """Test private IP address detection."""
        private_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '127.0.0.1']
        
        for ip in private_ips:
            self.assertTrue(self.geolocation_service._is_private_ip(ip))
    
    def test_public_ip_detection(self):
        """Test public IP address detection."""
        public_ips = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        
        for ip in public_ips:
            self.assertFalse(self.geolocation_service._is_private_ip(ip))
    
    def test_get_location_data_private_ip(self):
        """Test location data for private IP returns default data."""
        location_data = self.geolocation_service.get_location_data('192.168.1.1')
        
        self.assertEqual(location_data['country'], '')
        self.assertEqual(location_data['provider'], 'default')
    
    def test_get_client_ip_from_request(self):
        """Test extracting client IP from request."""
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        
        ip = get_client_ip(request)
        self.assertEqual(ip, '192.168.1.100')
    
    def test_get_client_ip_with_forwarded_header(self):
        """Test extracting client IP from forwarded headers."""
        request = self.factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '203.0.113.1, 192.168.1.100'
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        
        ip = get_client_ip(request)
        self.assertEqual(ip, '203.0.113.1')


class SessionServiceTest(TestCase):
    """Test session service functionality."""
    
    def setUp(self):
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        self.factory = RequestFactory()
        self.session_service = SessionService()
    
    @patch('enterprise_auth.core.utils.geolocation.GeolocationService.get_location_data')
    def test_create_session(self, mock_get_location_data):
        """Test session creation through service."""
        # Mock geolocation response
        mock_get_location_data.return_value = {
            'country': 'United States',
            'region': 'California',
            'city': 'San Francisco',
            'latitude': 37.7749,
            'longitude': -122.4194,
            'isp': 'Test ISP',
        }
        
        request = self.factory.post('/login/')
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        request.META['REMOTE_ADDR'] = '203.0.113.1'
        
        additional_data = {
            'screen_resolution': '1920x1080',
            'timezone_offset': -300,
        }
        
        session = self.session_service.create_session(
            user=self.user,
            request=request,
            login_method='password',
            additional_data=additional_data
        )
        
        self.assertIsInstance(session, UserSession)
        self.assertEqual(session.user, self.user)
        self.assertEqual(session.status, 'active')
        self.assertEqual(session.login_method, 'password')
        self.assertEqual(session.country, 'United States')
        self.assertTrue(session.is_active)
    
    def test_validate_session(self):
        """Test session validation."""
        # Create a session first
        device = DeviceInfo.objects.create(
            device_fingerprint='test_fingerprint',
            device_type='desktop',
            user_agent='Test User Agent'
        )
        
        session = UserSession.objects.create(
            session_id='test_session_123',
            user=self.user,
            device_info=device,
            ip_address='192.168.1.100',
            login_method='password',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        
        # Validate the session
        is_valid, session_obj, details = self.session_service.validate_session('test_session_123')
        
        self.assertTrue(is_valid)
        self.assertEqual(session_obj, session)
        self.assertTrue(details['exists'])
        self.assertTrue(details['active'])
        self.assertFalse(details['expired'])
    
    def test_validate_nonexistent_session(self):
        """Test validation of non-existent session."""
        is_valid, session_obj, details = self.session_service.validate_session('nonexistent_session')
        
        self.assertFalse(is_valid)
        self.assertIsNone(session_obj)
        self.assertFalse(details['exists'])
    
    def test_terminate_session(self):
        """Test session termination."""
        # Create a session first
        device = DeviceInfo.objects.create(
            device_fingerprint='test_fingerprint',
            device_type='desktop',
            user_agent='Test User Agent'
        )
        
        session = UserSession.objects.create(
            session_id='test_session_terminate',
            user=self.user,
            device_info=device,
            ip_address='192.168.1.100',
            login_method='password',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        
        # Terminate the session
        result = self.session_service.terminate_session(
            session_id='test_session_terminate',
            terminated_by=self.user,
            reason='test_termination'
        )
        
        self.assertTrue(result)
        
        # Refresh from database
        session.refresh_from_db()
        self.assertEqual(session.status, 'terminated')
        self.assertEqual(session.terminated_by, self.user)
        self.assertEqual(session.termination_reason, 'test_termination')
    
    def test_get_user_sessions(self):
        """Test getting user sessions."""
        # Create multiple sessions
        device = DeviceInfo.objects.create(
            device_fingerprint='test_fingerprint',
            device_type='desktop',
            user_agent='Test User Agent'
        )
        
        session1 = UserSession.objects.create(
            session_id='session_1',
            user=self.user,
            device_info=device,
            ip_address='192.168.1.100',
            login_method='password',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        
        session2 = UserSession.objects.create(
            session_id='session_2',
            user=self.user,
            device_info=device,
            ip_address='192.168.1.101',
            login_method='oauth_google',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        
        # Get user sessions
        sessions = self.session_service.get_user_sessions(self.user)
        
        self.assertEqual(len(sessions), 2)
        self.assertIn(session1, sessions)
        self.assertIn(session2, sessions)
    
    @patch('enterprise_auth.core.utils.geolocation.GeolocationService.get_location_data')
    def test_create_user_session_convenience_function(self, mock_get_location_data):
        """Test convenience function for session creation."""
        # Mock geolocation response
        mock_get_location_data.return_value = {
            'country': 'United States',
            'region': 'California',
            'city': 'San Francisco',
            'latitude': 37.7749,
            'longitude': -122.4194,
            'isp': 'Test ISP',
        }
        
        request = self.factory.post('/login/')
        request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        request.META['REMOTE_ADDR'] = '203.0.113.1'
        
        session = create_user_session(
            user=self.user,
            request=request,
            login_method='password'
        )
        
        self.assertIsInstance(session, UserSession)
        self.assertEqual(session.user, self.user)
        self.assertTrue(session.is_active)


class SessionActivityModelTest(TestCase):
    """Test SessionActivity model functionality."""
    
    def setUp(self):
        self.user = UserProfile.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        self.device = DeviceInfo.objects.create(
            device_fingerprint='test_fingerprint',
            device_type='desktop',
            user_agent='Test User Agent'
        )
        
        self.session = UserSession.objects.create(
            session_id='test_session',
            user=self.user,
            device_info=self.device,
            ip_address='192.168.1.100',
            login_method='password',
            expires_at=timezone.now() + timedelta(hours=24)
        )
    
    def test_session_activity_creation(self):
        """Test creating a SessionActivity instance."""
        activity = SessionActivity.objects.create(
            session=self.session,
            activity_type='login',
            endpoint='/api/v1/auth/login',
            method='POST',
            status_code=200,
            response_time_ms=150,
            activity_data={'login_method': 'password'},
            risk_indicators=['new_device']
        )
        
        self.assertEqual(activity.session, self.session)
        self.assertEqual(activity.activity_type, 'login')
        self.assertEqual(activity.endpoint, '/api/v1/auth/login')
        self.assertEqual(activity.method, 'POST')
        self.assertEqual(activity.status_code, 200)
        self.assertEqual(activity.response_time_ms, 150)
        self.assertEqual(activity.activity_data['login_method'], 'password')
        self.assertIn('new_device', activity.risk_indicators)
    
    def test_session_activity_str_representation(self):
        """Test string representation of SessionActivity."""
        activity = SessionActivity.objects.create(
            session=self.session,
            activity_type='api_call',
            endpoint='/api/v1/users/profile'
        )
        
        expected_str = f"api_call - {self.session.session_id[:8]}..."
        self.assertEqual(str(activity), expected_str)