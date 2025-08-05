"""
Management command to demonstrate advanced session tracking functionality.
"""

from django.core.management.base import BaseCommand
from django.test import RequestFactory
from django.utils import timezone
from datetime import timedelta

from enterprise_auth.core.models.user import UserProfile
from enterprise_auth.core.services.session_service import SessionService
from enterprise_auth.core.utils.device_fingerprinting import DeviceFingerprinter


class Command(BaseCommand):
    help = 'Demonstrate advanced session tracking functionality'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--create-demo-user',
            action='store_true',
            help='Create a demo user for testing',
        )
    
    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('🚀 Advanced Session Tracking Demo')
        )
        
        # Create or get demo user
        if options['create_demo_user']:
            user = self.create_demo_user()
        else:
            try:
                user = UserProfile.objects.get(email='demo@example.com')
            except UserProfile.DoesNotExist:
                user = self.create_demo_user()
        
        self.stdout.write(f"Using demo user: {user.email}")
        
        # Initialize services
        session_service = SessionService()
        factory = RequestFactory()
        
        # Demo 1: Create session from desktop device
        self.stdout.write("\n" + "="*50)
        self.stdout.write("Demo 1: Desktop Session Creation")
        self.stdout.write("="*50)
        
        desktop_request = factory.post('/login/')
        desktop_request.META['HTTP_USER_AGENT'] = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        desktop_request.META['REMOTE_ADDR'] = '203.0.113.1'
        desktop_request.META['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9'
        
        desktop_additional_data = {
            'screen_resolution': '1920x1080',
            'timezone_offset': -300,
            'language': 'en-US',
            'platform': 'Win32',
            'cookie_enabled': True,
            'local_storage': True,
        }
        
        desktop_session = session_service.create_session(
            user=user,
            request=desktop_request,
            login_method='password',
            additional_data=desktop_additional_data
        )
        
        self.display_session_info(desktop_session, "Desktop Session")
        
        # Demo 2: Create session from mobile device
        self.stdout.write("\n" + "="*50)
        self.stdout.write("Demo 2: Mobile Session Creation")
        self.stdout.write("="*50)
        
        mobile_request = factory.post('/login/')
        mobile_request.META['HTTP_USER_AGENT'] = (
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) '
            'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
        )
        mobile_request.META['REMOTE_ADDR'] = '198.51.100.1'
        mobile_request.META['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9'
        
        mobile_additional_data = {
            'screen_resolution': '390x844',
            'timezone_offset': -300,
            'language': 'en-US',
            'platform': 'iPhone',
            'cookie_enabled': True,
            'local_storage': True,
        }
        
        mobile_session = session_service.create_session(
            user=user,
            request=mobile_request,
            login_method='oauth_google',
            additional_data=mobile_additional_data
        )
        
        self.display_session_info(mobile_session, "Mobile Session")
        
        # Demo 3: Create suspicious session (different country)
        self.stdout.write("\n" + "="*50)
        self.stdout.write("Demo 3: Suspicious Session (Different Location)")
        self.stdout.write("="*50)
        
        suspicious_request = factory.post('/login/')
        suspicious_request.META['HTTP_USER_AGENT'] = (
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        suspicious_request.META['REMOTE_ADDR'] = '192.0.2.1'  # Different IP
        suspicious_request.META['HTTP_ACCEPT_LANGUAGE'] = 'ru-RU,ru;q=0.9'
        
        suspicious_additional_data = {
            'screen_resolution': '1366x768',
            'timezone_offset': 180,  # Different timezone
            'language': 'ru-RU',
            'platform': 'Linux x86_64',
            'cookie_enabled': True,
            'local_storage': True,
        }
        
        suspicious_session = session_service.create_session(
            user=user,
            request=suspicious_request,
            login_method='password',
            additional_data=suspicious_additional_data
        )
        
        self.display_session_info(suspicious_session, "Suspicious Session")
        
        # Demo 4: Session validation
        self.stdout.write("\n" + "="*50)
        self.stdout.write("Demo 4: Session Validation")
        self.stdout.write("="*50)
        
        is_valid, session_obj, details = session_service.validate_session(desktop_session.session_id)
        
        self.stdout.write(f"Session ID: {desktop_session.session_id}")
        self.stdout.write(f"Is Valid: {is_valid}")
        self.stdout.write(f"Validation Details: {details}")
        
        # Demo 5: Risk analysis
        self.stdout.write("\n" + "="*50)
        self.stdout.write("Demo 5: Risk Analysis")
        self.stdout.write("="*50)
        
        risk_analysis = session_service.analyze_session_risk(suspicious_session)
        
        self.stdout.write(f"Risk Score: {risk_analysis['current_risk_score']:.2f}")
        self.stdout.write(f"Risk Level: {risk_analysis['risk_level']}")
        self.stdout.write(f"Risk Factors: {risk_analysis['risk_factors']}")
        self.stdout.write(f"Recommendations: {risk_analysis['recommendations']}")
        
        # Demo 6: Get all user sessions
        self.stdout.write("\n" + "="*50)
        self.stdout.write("Demo 6: User Sessions Overview")
        self.stdout.write("="*50)
        
        user_sessions = session_service.get_user_sessions(user)
        
        self.stdout.write(f"Total Active Sessions: {len(user_sessions)}")
        for i, session in enumerate(user_sessions, 1):
            self.stdout.write(
                f"  {i}. {session.device_info.device_type} - "
                f"{session.location_string} - "
                f"Risk: {session.risk_score:.1f}"
            )
        
        # Demo 7: Session termination
        self.stdout.write("\n" + "="*50)
        self.stdout.write("Demo 7: Session Termination")
        self.stdout.write("="*50)
        
        terminated = session_service.terminate_session(
            session_id=suspicious_session.session_id,
            terminated_by=user,
            reason='high_risk_session'
        )
        
        self.stdout.write(f"Session terminated: {terminated}")
        
        # Demo 8: Device fingerprinting details
        self.stdout.write("\n" + "="*50)
        self.stdout.write("Demo 8: Device Fingerprinting Details")
        self.stdout.write("="*50)
        
        fingerprinter = DeviceFingerprinter()
        
        desktop_fingerprint = fingerprinter.generate_fingerprint(desktop_request, desktop_additional_data)
        mobile_fingerprint = fingerprinter.generate_fingerprint(mobile_request, mobile_additional_data)
        
        self.stdout.write(f"Desktop Fingerprint: {desktop_fingerprint[:16]}...")
        self.stdout.write(f"Mobile Fingerprint: {mobile_fingerprint[:16]}...")
        
        # Calculate similarity
        desktop_data = fingerprinter._extract_fingerprint_data(desktop_request, desktop_additional_data)
        mobile_data = fingerprinter._extract_fingerprint_data(mobile_request, mobile_additional_data)
        
        similarity = fingerprinter.calculate_fingerprint_similarity(
            desktop_fingerprint, mobile_fingerprint, desktop_data, mobile_data
        )
        
        self.stdout.write(f"Fingerprint Similarity: {similarity:.2%}")
        
        self.stdout.write("\n" + "="*50)
        self.stdout.write(self.style.SUCCESS("✅ Demo completed successfully!"))
        self.stdout.write("="*50)
    
    def create_demo_user(self):
        """Create a demo user for testing."""
        try:
            user = UserProfile.objects.get(email='demo@example.com')
            created = False
        except UserProfile.DoesNotExist:
            # Delete any existing user with empty username to avoid conflicts
            UserProfile.objects.filter(username='').delete()
            
            user = UserProfile.objects.create_user(
                email='demo@example.com',
                password='demo123',
                first_name='Demo',
                last_name='User'
            )
            user.is_email_verified = True
            user.save()
            created = True
        
        if created:
            self.stdout.write(
                self.style.SUCCESS(f"Created demo user: {user.email}")
            )
        
        return user
    
    def display_session_info(self, session, title):
        """Display detailed session information."""
        self.stdout.write(f"\n{title}:")
        self.stdout.write(f"  Session ID: {session.session_id}")
        self.stdout.write(f"  Device Type: {session.device_info.device_type}")
        self.stdout.write(f"  Browser: {session.device_info.browser}")
        self.stdout.write(f"  OS: {session.device_info.operating_system}")
        self.stdout.write(f"  Location: {session.location_string}")
        self.stdout.write(f"  IP Address: {session.ip_address}")
        self.stdout.write(f"  Login Method: {session.login_method}")
        self.stdout.write(f"  Risk Score: {session.risk_score:.2f}")
        self.stdout.write(f"  Status: {session.status}")
        self.stdout.write(f"  Created: {session.created_at}")
        self.stdout.write(f"  Expires: {session.expires_at}")
        
        if session.risk_factors:
            self.stdout.write(f"  Risk Factors:")
            for factor, score in session.risk_factors.items():
                self.stdout.write(f"    - {factor}: {score:.2f}")