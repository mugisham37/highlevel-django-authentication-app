"""
URL patterns for Email Multi-Factor Authentication endpoints.
"""

from django.urls import path
from ..views.email_mfa_views import (
    setup_email_mfa,
    confirm_email_setup,
    send_email_code,
    verify_email_code,
    resend_email_code,
    trigger_sms_fallback,
    get_email_mfa_status,
    remove_email_device,
)

app_name = 'email_mfa'

urlpatterns = [
    # Email MFA setup endpoints
    path('setup/', setup_email_mfa, name='setup_email_mfa'),
    path('setup/confirm/', confirm_email_setup, name='confirm_email_setup'),
    
    # Email MFA verification endpoints
    path('send/', send_email_code, name='send_email_code'),
    path('verify/', verify_email_code, name='verify_email_code'),
    path('resend/', resend_email_code, name='resend_email_code'),
    
    # Email MFA fallback and management endpoints
    path('fallback/sms/', trigger_sms_fallback, name='trigger_sms_fallback'),
    path('status/', get_email_mfa_status, name='get_email_mfa_status'),
    path('device/<str:device_id>/', remove_email_device, name='remove_email_device'),
]