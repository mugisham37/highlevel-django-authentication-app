"""
Data portability service for GDPR Article 20 compliance.
Handles user data export in machine-readable formats.
"""

import json
import csv
import xml.etree.ElementTree as ET
from io import StringIO
from typing import Dict, List, Any, Optional
from datetime import datetime
from django.contrib.auth import get_user_model
from django.core.serializers import serialize
from django.db import models
from django.utils import timezone
import logging

from ..models import (
    UserProfile, UserSession, SecurityEvent, AuditLog, MFADevice,
    ConsentRecord, DataDisclosureLog, PrivacyPolicyAcceptance
)

User = get_user_model()
logger = logging.getLogger(__name__)


class DataPortabilityService:
    """
    Service for exporting user data in portable formats for GDPR compliance.
    """
    
    EXPORTABLE_DATA_TYPES = {
        'profile': 'User profile information',
        'sessions': 'Login sessions and device information',
        'security_events': 'Security-related events',
        'audit_logs': 'User activity audit logs',
        'mfa_devices': 'Multi-factor authentication devices',
        'consent_records': 'Data processing consent records',
        'privacy_acceptances': 'Privacy policy acceptances',
        'data_disclosures': 'Data disclosure records'
    }
    
    def get_available_data_types(self) -> Dict[str, str]:
        """
        Get list of available data types for export.
        """
        return self.EXPORTABLE_DATA_TYPES.copy()
    
    def export_user_data(self, user: User, data_types: List[str], 
                        export_format: str = 'json') -> Dict[str, Any]:
        """
        Export user data in the specified format.
        
        Args:
            user: User whose data to export
            data_types: List of data types to include in export
            export_format: Format for export ('json', 'csv', 'xml')
            
        Returns:
            Dictionary containing exported data
        """
        try:
            # Validate data types
            invalid_types = set(data_types) - set(self.EXPORTABLE_DATA_TYPES.keys())
            if invalid_types:
                raise ValueError(f"Invalid data types: {invalid_types}")
            
            # Collect data
            export_data = {
                'export_metadata': {
                    'user_id': str(user.id),
                    'export_timestamp': timezone.now().isoformat(),
                    'export_format': export_format,
                    'data_types_included': data_types,
                    'gdpr_article': 'Article 20 - Right to data portability'
                }
            }
            
            # Export each requested data type
            for data_type in data_types:
                if data_type in self.EXPORTABLE_DATA_TYPES:
                    export_method = getattr(self, f'_export_{data_type}')
                    export_data[data_type] = export_method(user)
            
            logger.info(f"Data export completed for user {user.id}, types: {data_types}")
            return export_data
            
        except Exception as e:
            logger.error(f"Failed to export user data for user {user.id}: {str(e)}")
            raise
    
    def _export_profile(self, user: User) -> Dict[str, Any]:
        """
        Export user profile data.
        """
        profile_data = {
            'basic_information': {
                'user_id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'date_joined': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'is_active': user.is_active,
                'is_email_verified': getattr(user, 'is_email_verified', None),
                'is_phone_verified': getattr(user, 'is_phone_verified', None)
            }
        }
        
        # Add extended profile fields if they exist
        extended_fields = ['phone_number', 'organization', 'department', 'employee_id']
        for field in extended_fields:
            if hasattr(user, field):
                profile_data['basic_information'][field] = getattr(user, field)
        
        # Add user identities (OAuth connections)
        if hasattr(user, 'useridentity_set'):
            identities = []
            for identity in user.useridentity_set.all():
                identities.append({
                    'provider': identity.provider,
                    'provider_username': identity.provider_username,
                    'provider_email': identity.provider_email,
                    'linked_at': identity.linked_at.isoformat(),
                    'last_used': identity.last_used.isoformat() if identity.last_used else None,
                    'is_primary': identity.is_primary
                })
            profile_data['connected_accounts'] = identities
        
        return profile_data
    
    def _export_sessions(self, user: User) -> List[Dict[str, Any]]:
        """
        Export user session data.
        """
        sessions = []
        
        for session in UserSession.objects.filter(user=user).order_by('-created_at'):
            session_data = {
                'session_id': session.session_id,
                'device_information': {
                    'device_type': session.device_type,
                    'browser': session.browser,
                    'operating_system': session.operating_system,
                    'device_fingerprint': session.device_fingerprint,
                    'is_trusted_device': session.is_trusted_device
                },
                'location_information': {
                    'ip_address': str(session.ip_address) if session.ip_address else None,
                    'country': session.country,
                    'city': session.city
                },
                'session_details': {
                    'status': session.status,
                    'login_method': getattr(session, 'login_method', None),
                    'risk_score': session.risk_score,
                    'created_at': session.created_at.isoformat(),
                    'last_activity': session.last_activity.isoformat(),
                    'expires_at': session.expires_at.isoformat()
                }
            }
            sessions.append(session_data)
        
        return sessions
    
    def _export_security_events(self, user: User) -> List[Dict[str, Any]]:
        """
        Export security events related to the user.
        """
        events = []
        
        for event in SecurityEvent.objects.filter(user=user).order_by('-timestamp'):
            event_data = {
                'event_id': str(event.id),
                'event_type': event.event_type,
                'severity': event.severity,
                'description': event.description,
                'timestamp': event.timestamp.isoformat(),
                'ip_address': str(event.ip_address) if event.ip_address else None,
                'user_agent': event.user_agent,
                'risk_score': getattr(event, 'risk_score', None),
                'response_taken': getattr(event, 'response_taken', None),
                'event_data': event.event_data if hasattr(event, 'event_data') else {}
            }
            events.append(event_data)
        
        return events
    
    def _export_audit_logs(self, user: User) -> List[Dict[str, Any]]:
        """
        Export audit logs for the user.
        """
        logs = []
        
        for log in AuditLog.objects.filter(user=user).order_by('-timestamp'):
            log_data = {
                'log_id': str(log.id),
                'action': log.action,
                'resource': log.resource,
                'timestamp': log.timestamp.isoformat(),
                'ip_address': str(log.ip_address) if log.ip_address else None,
                'user_agent': getattr(log, 'user_agent', ''),
                'outcome': getattr(log, 'outcome', 'success'),
                'details': getattr(log, 'details', {})
            }
            logs.append(log_data)
        
        return logs
    
    def _export_mfa_devices(self, user: User) -> List[Dict[str, Any]]:
        """
        Export MFA device information (excluding sensitive data).
        """
        devices = []
        
        for device in MFADevice.objects.filter(user=user):
            device_data = {
                'device_id': str(device.id),
                'device_type': device.device_type,
                'is_confirmed': device.is_confirmed,
                'is_active': getattr(device, 'is_active', True),
                'created_at': device.created_at.isoformat(),
                'last_used': device.last_used.isoformat() if device.last_used else None
            }
            # Note: We don't export secret keys or backup codes for security reasons
            devices.append(device_data)
        
        return devices
    
    def _export_consent_records(self, user: User) -> List[Dict[str, Any]]:
        """
        Export consent records for data processing.
        """
        consents = []
        
        for consent in ConsentRecord.objects.filter(user=user).select_related('purpose'):
            consent_data = {
                'consent_id': str(consent.id),
                'purpose': {
                    'name': consent.purpose.name,
                    'description': consent.purpose.description,
                    'purpose_type': consent.purpose.purpose_type,
                    'legal_basis': consent.purpose.legal_basis
                },
                'consent_details': {
                    'status': consent.status,
                    'consent_method': consent.consent_method,
                    'consent_given_at': consent.consent_given_at.isoformat() if consent.consent_given_at else None,
                    'consent_withdrawn_at': consent.consent_withdrawn_at.isoformat() if consent.consent_withdrawn_at else None,
                    'expires_at': consent.expires_at.isoformat() if consent.expires_at else None,
                    'version': consent.version,
                    'ip_address': str(consent.ip_address) if consent.ip_address else None
                }
            }
            consents.append(consent_data)
        
        return consents
    
    def _export_privacy_acceptances(self, user: User) -> List[Dict[str, Any]]:
        """
        Export privacy policy acceptances.
        """
        acceptances = []
        
        for acceptance in PrivacyPolicyAcceptance.objects.filter(user=user).select_related('policy_version'):
            acceptance_data = {
                'acceptance_id': str(acceptance.id),
                'policy_version': {
                    'version': acceptance.policy_version.version,
                    'title': acceptance.policy_version.title,
                    'effective_date': acceptance.policy_version.effective_date.isoformat()
                },
                'acceptance_details': {
                    'accepted_at': acceptance.accepted_at.isoformat(),
                    'acceptance_method': acceptance.acceptance_method,
                    'ip_address': str(acceptance.ip_address) if acceptance.ip_address else None
                }
            }
            acceptances.append(acceptance_data)
        
        return acceptances
    
    def _export_data_disclosures(self, user: User) -> List[Dict[str, Any]]:
        """
        Export data disclosure records.
        """
        disclosures = []
        
        for disclosure in DataDisclosureLog.objects.filter(user=user):
            disclosure_data = {
                'disclosure_id': str(disclosure.disclosure_id),
                'disclosure_type': disclosure.disclosure_type,
                'recipient_information': {
                    'recipient_name': disclosure.recipient_name,
                    'recipient_contact': disclosure.recipient_contact
                },
                'disclosure_details': {
                    'legal_basis': disclosure.legal_basis,
                    'data_categories': disclosure.data_categories,
                    'purpose': disclosure.purpose,
                    'disclosure_date': disclosure.disclosure_date.isoformat(),
                    'retention_period': disclosure.retention_period,
                    'user_notified': disclosure.user_notified,
                    'user_notification_date': disclosure.user_notification_date.isoformat() if disclosure.user_notification_date else None
                }
            }
            disclosures.append(disclosure_data)
        
        return disclosures
    
    def convert_to_csv(self, export_data: Dict[str, Any]) -> str:
        """
        Convert exported data to CSV format.
        """
        output = StringIO()
        writer = csv.writer(output)
        
        # Write metadata
        writer.writerow(['Data Export Report'])
        writer.writerow(['Generated:', export_data['export_metadata']['export_timestamp']])
        writer.writerow(['User ID:', export_data['export_metadata']['user_id']])
        writer.writerow(['Data Types:', ', '.join(export_data['export_metadata']['data_types_included'])])
        writer.writerow([])  # Empty row
        
        # Write each data type
        for data_type, data in export_data.items():
            if data_type == 'export_metadata':
                continue
                
            writer.writerow([f'{data_type.upper()} DATA'])
            writer.writerow([])
            
            if isinstance(data, list) and data:
                # Handle list data (sessions, events, etc.)
                if isinstance(data[0], dict):
                    # Flatten nested dictionaries for CSV
                    flattened_data = []
                    for item in data:
                        flattened_item = self._flatten_dict(item)
                        flattened_data.append(flattened_item)
                    
                    if flattened_data:
                        # Write headers
                        headers = list(flattened_data[0].keys())
                        writer.writerow(headers)
                        
                        # Write data rows
                        for item in flattened_data:
                            writer.writerow([item.get(header, '') for header in headers])
                
            elif isinstance(data, dict):
                # Handle dictionary data (profile)
                flattened_data = self._flatten_dict(data)
                for key, value in flattened_data.items():
                    writer.writerow([key, value])
            
            writer.writerow([])  # Empty row between sections
        
        return output.getvalue()
    
    def convert_to_xml(self, export_data: Dict[str, Any]) -> str:
        """
        Convert exported data to XML format.
        """
        root = ET.Element('user_data_export')
        
        # Add metadata
        metadata = ET.SubElement(root, 'export_metadata')
        for key, value in export_data['export_metadata'].items():
            elem = ET.SubElement(metadata, key)
            if isinstance(value, list):
                elem.text = ', '.join(str(v) for v in value)
            else:
                elem.text = str(value)
        
        # Add each data type
        for data_type, data in export_data.items():
            if data_type == 'export_metadata':
                continue
                
            section = ET.SubElement(root, data_type)
            
            if isinstance(data, list):
                for i, item in enumerate(data):
                    item_elem = ET.SubElement(section, f'{data_type[:-1]}_{i}')  # Remove 's' from plural
                    self._dict_to_xml(item, item_elem)
                    
            elif isinstance(data, dict):
                self._dict_to_xml(data, section)
        
        return ET.tostring(root, encoding='unicode', method='xml')
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
        """
        Flatten nested dictionary for CSV export.
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Convert lists to comma-separated strings
                items.append((new_key, ', '.join(str(item) for item in v)))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _dict_to_xml(self, d: Dict[str, Any], parent: ET.Element) -> None:
        """
        Convert dictionary to XML elements.
        """
        for key, value in d.items():
            # Clean key name for XML
            clean_key = key.replace(' ', '_').replace('-', '_')
            elem = ET.SubElement(parent, clean_key)
            
            if isinstance(value, dict):
                self._dict_to_xml(value, elem)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        item_elem = ET.SubElement(elem, f'item_{i}')
                        self._dict_to_xml(item, item_elem)
                    else:
                        item_elem = ET.SubElement(elem, f'item_{i}')
                        item_elem.text = str(item)
            else:
                elem.text = str(value) if value is not None else ''
    
    def validate_export_request(self, user: User, data_types: List[str]) -> Dict[str, Any]:
        """
        Validate a data export request and return availability information.
        """
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'data_availability': {}
        }
        
        # Check for invalid data types
        invalid_types = set(data_types) - set(self.EXPORTABLE_DATA_TYPES.keys())
        if invalid_types:
            validation_result['valid'] = False
            validation_result['errors'].append(f"Invalid data types: {list(invalid_types)}")
        
        # Check data availability for each type
        for data_type in data_types:
            if data_type in self.EXPORTABLE_DATA_TYPES:
                count = self._get_data_count(user, data_type)
                validation_result['data_availability'][data_type] = {
                    'available': count > 0,
                    'record_count': count
                }
                
                if count == 0:
                    validation_result['warnings'].append(f"No {data_type} data available for export")
        
        return validation_result
    
    def _get_data_count(self, user: User, data_type: str) -> int:
        """
        Get count of available records for a data type.
        """
        if data_type == 'profile':
            return 1  # Always have profile data
        elif data_type == 'sessions':
            return UserSession.objects.filter(user=user).count()
        elif data_type == 'security_events':
            return SecurityEvent.objects.filter(user=user).count()
        elif data_type == 'audit_logs':
            return AuditLog.objects.filter(user=user).count()
        elif data_type == 'mfa_devices':
            return MFADevice.objects.filter(user=user).count()
        elif data_type == 'consent_records':
            return ConsentRecord.objects.filter(user=user).count()
        elif data_type == 'privacy_acceptances':
            return PrivacyPolicyAcceptance.objects.filter(user=user).count()
        elif data_type == 'data_disclosures':
            return DataDisclosureLog.objects.filter(user=user).count()
        else:
            return 0