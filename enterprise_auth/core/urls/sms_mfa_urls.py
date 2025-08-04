"""
URL patterns for SMS Multi-Factor Authentication endpoints.
"""

from django.urls import path
from ..views.sms_mfa_views import (
    setup_sms_mfa,
    confirm_sms_setup,
    send_sms_code,
    verify_sms_code,
    resend_sms_code,
    get_sms_delivery_status,
)

app_name = 'sms_mfa'

urlpatterns = [
    # SMS MFA setup endpoints
    path('setup/', setup_sms_mfa, name='setup_sms_mfa'),
    path('setup/confirm/', confirm_sms_setup, name='confirm_sms_setup'),
    
    # SMS MFA verification endpoints
    path('send/', send_sms_code, name='send_sms_code'),
    path('verify/', verify_sms_code, name='verify_sms_code'),
    path('resend/', resend_sms_code, name='resend_sms_code'),
    
    # SMS delivery status endpoint
    path('status/', get_sms_delivery_status, name='get_sms_delivery_status'),
]