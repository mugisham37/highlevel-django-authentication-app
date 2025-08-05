"""
Privacy rights management service for GDPR and CCPA compliance.
Handles consent management, privacy policy tracking, and user rights.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError

from ..models.compliance import (
    DataProcessingPurpose, ConsentRecord, PrivacyPolicyVersion,
    PrivacyPolicyAcceptance, DataDisclosureLog, ComplianceAuditLog
)
from .compliance_service import SOC2AuditService

User = get_user_model()
logger = logging.getLogger(__name__)


class PrivacyRightsService:
    """
    Service for managing user privacy rights and consent under GDPR/CCPA.
    """
    
    def __init__(self):
        self.audit_service = SOC2AuditService()
    
    def initialize_data_processing_purposes(self) -> List[DataProcessingPurpose]:
        """
        Initialize default data processing purposes for GDPR compliance.
        """
        default_purposes = [
            {
                'name': 'authentication',
                'purpose_type': 'authentication',
                'description': 'User authentication and account access',
                'legal_basis': 'Contract performance (GDPR Art. 6(1)(b))',
                'retention_period_days': 2555,  # 7 years
                'is_essential': True
            },
            {
                'name': 'authorization',
                'purpose_type': 'authorization',
                'description': 'Access control and permission management',
                'legal_basis': 'Contract performance (GDPR Art. 6(1)(b))',
                'retention_period_days': 2555,
                'is_essential': True
            },
            {
                'name': 'security_monitoring',
                'purpose_type': 'security',
                'description': 'Security monitoring and threat detection',
                'legal_basis': 'Legitimate interests (GDPR Art. 6(1)(f))',
                'retention_period_days': 730,  # 2 years
                'is_essential': True
            },
            {
                'name': 'usage_analytics',
                'purpose_type': 'analytics',
                'description': 'Usage analytics and service improvement',
                'legal_basis': 'Legitimate interests (GDPR Art. 6(1)(f))',
                'retention_period_days': 365,  # 1 year
                'is_essential': False
            },
            {
                'name': 'user_communication',
                'purpose_type': 'communication',
                'description': 'User communication and notifications',
                'legal_basis': 'Consent (GDPR Art. 6(1)(a))',
                'retention_period_days': 1095,  # 3 years
                'is_essential': False
            },
            {
                'name': 'legal_compliance',
                'purpose_type': 'legal_compliance',
                'description': 'Legal compliance and regulatory requirements',
                'legal_basis': 'Legal obligation (GDPR Art. 6(1)(c))',
                'retention_period_days': 2555,  # 7 years
                'is_essential': True
            }
        ]
        
        created_purposes = []
        for purpose_data in default_purposes:
            purpose, created = DataProcessingPurpose.objects.get_or_create(
                name=purpose_data['name'],
                defaults=purpose_data
            )
            if created:
                logger.info(f"Created data processing purpose: {purpose.name}")
            created_purposes.append(purpose)
        
        return created_purposes
    
    def grant_consent(self, user: User, purpose_name: str, consent_method: str = 'explicit',
                     ip_address: str = None, user_agent: str = None, 
                     consent_text: str = None, version: str = '1.0') -> ConsentRecord:
        """
        Grant user consent for a specific data processing purpose.
        """
        try:
            with transaction.atomic():
                purpose = DataProcessingPurpose.objects.get(name=purpose_name, is_active=True)
                
                # Get or create consent record
                consent_record, created = ConsentRecord.objects.get_or_create(
                    user=user,
                    purpose=purpose,
                    defaults={
                        'status': 'granted',
                        'consent_given_at': timezone.now(),
                        'consent_method': consent_method,
                        'ip_address': ip_address,
                        'user_agent': user_agent,
                        'consent_text': consent_text or f"Consent for {purpose.description}",
                        'version': version,
                        'expires_at': timezone.now() + timedelta(days=purpose.retention_period_days) if not purpose.is_essential else None
                    }
                )
                
                if not created and consent_record.status != 'granted':
                    # Update existing consent
                    consent_record.status = 'granted'
                    consent_record.consent_given_at = timezone.now()
                    consent_record.consent_withdrawn_at = None
                    consent_record.consent_method = consent_method
                    consent_record.ip_address = ip_address
                    consent_record.user_agent = user_agent
                    consent_record.version = version
                    consent_record.save()
                
                # Log consent grant
                self.audit_service.create_audit_log(
                    activity_type='compliance_action',
                    user=user,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    action='consent_granted',
                    resource='data_processing_consent',
                    outcome='success',
                    details={
                        'purpose': purpose_name,
                        'consent_method': consent_method,
                        'legal_basis': purpose.legal_basis,
                        'is_essential': purpose.is_essential
                    }
                )
                
                logger.info(f"Consent granted for user {user.id}, purpose: {purpose_name}")
                return consent_record
                
        except DataProcessingPurpose.DoesNotExist:
            logger.error(f"Data processing purpose not found: {purpose_name}")
            raise ValidationError(f"Invalid data processing purpose: {purpose_name}")
        except Exception as e:
            logger.error(f"Failed to grant consent for user {user.id}: {str(e)}")
            raise
    
    def withdraw_consent(self, user: User, purpose_name: str, ip_address: str = None,
                        user_agent: str = None) -> ConsentRecord:
        """
        Withdraw user consent for a specific data processing purpose.
        """
        try:
            with transaction.atomic():
                purpose = DataProcessingPurpose.objects.get(name=purpose_name, is_active=True)
                
                if purpose.is_essential:
                    raise ValidationError(f"Cannot withdraw consent for essential purpose: {purpose_name}")
                
                consent_record = ConsentRecord.objects.get(user=user, purpose=purpose)
                
                if consent_record.status == 'withdrawn':
                    logger.warning(f"Consent already withdrawn for user {user.id}, purpose: {purpose_name}")
                    return consent_record
                
                # Update consent record
                consent_record.status = 'withdrawn'
                consent_record.consent_withdrawn_at = timezone.now()
                consent_record.save()
                
                # Log consent withdrawal
                self.audit_service.create_audit_log(
                    activity_type='compliance_action',
                    user=user,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    action='consent_withdrawn',
                    resource='data_processing_consent',
                    outcome='success',
                    details={
                        'purpose': purpose_name,
                        'legal_basis': purpose.legal_basis,
                        'withdrawal_date': consent_record.consent_withdrawn_at.isoformat()
                    }
                )
                
                logger.info(f"Consent withdrawn for user {user.id}, purpose: {purpose_name}")
                return consent_record
                
        except DataProcessingPurpose.DoesNotExist:
            logger.error(f"Data processing purpose not found: {purpose_name}")
            raise ValidationError(f"Invalid data processing purpose: {purpose_name}")
        except ConsentRecord.DoesNotExist:
            logger.error(f"Consent record not found for user {user.id}, purpose: {purpose_name}")
            raise ValidationError(f"No consent record found for purpose: {purpose_name}")
        except Exception as e:
            logger.error(f"Failed to withdraw consent for user {user.id}: {str(e)}")
            raise
    
    def get_user_consent_status(self, user: User) -> Dict[str, Any]:
        """
        Get comprehensive consent status for a user.
        """
        try:
            consent_status = {
                'user_id': str(user.id),
                'last_updated': timezone.now().isoformat(),
                'consent_records': [],
                'summary': {
                    'total_purposes': 0,
                    'granted_consents': 0,
                    'withdrawn_consents': 0,
                    'expired_consents': 0,
                    'essential_purposes': 0
                }
            }
            
            # Get all active data processing purposes
            purposes = DataProcessingPurpose.objects.filter(is_active=True)
            consent_status['summary']['total_purposes'] = purposes.count()
            
            for purpose in purposes:
                try:
                    consent_record = ConsentRecord.objects.get(user=user, purpose=purpose)
                    
                    # Check if consent is expired
                    is_expired = (consent_record.expires_at and 
                                consent_record.expires_at < timezone.now())
                    
                    if is_expired and consent_record.status == 'granted':
                        consent_record.status = 'expired'
                        consent_record.save()
                    
                    consent_info = {
                        'purpose': {
                            'name': purpose.name,
                            'description': purpose.description,
                            'purpose_type': purpose.purpose_type,
                            'legal_basis': purpose.legal_basis,
                            'is_essential': purpose.is_essential
                        },
                        'consent': {
                            'status': consent_record.status,
                            'consent_given_at': consent_record.consent_given_at.isoformat() if consent_record.consent_given_at else None,
                            'consent_withdrawn_at': consent_record.consent_withdrawn_at.isoformat() if consent_record.consent_withdrawn_at else None,
                            'expires_at': consent_record.expires_at.isoformat() if consent_record.expires_at else None,
                            'consent_method': consent_record.consent_method,
                            'version': consent_record.version
                        }
                    }
                    
                    # Update summary counts
                    if consent_record.status == 'granted':
                        consent_status['summary']['granted_consents'] += 1
                    elif consent_record.status == 'withdrawn':
                        consent_status['summary']['withdrawn_consents'] += 1
                    elif consent_record.status == 'expired':
                        consent_status['summary']['expired_consents'] += 1
                    
                except ConsentRecord.DoesNotExist:
                    # No consent record exists for this purpose
                    consent_info = {
                        'purpose': {
                            'name': purpose.name,
                            'description': purpose.description,
                            'purpose_type': purpose.purpose_type,
                            'legal_basis': purpose.legal_basis,
                            'is_essential': purpose.is_essential
                        },
                        'consent': {
                            'status': 'not_provided',
                            'consent_given_at': None,
                            'consent_withdrawn_at': None,
                            'expires_at': None,
                            'consent_method': None,
                            'version': None
                        }
                    }
                
                if purpose.is_essential:
                    consent_status['summary']['essential_purposes'] += 1
                
                consent_status['consent_records'].append(consent_info)
            
            return consent_status
            
        except Exception as e:
            logger.error(f"Failed to get consent status for user {user.id}: {str(e)}")
            raise
    
    def create_privacy_policy_version(self, version: str, title: str, content: str,
                                    effective_date: datetime, requires_explicit_consent: bool = True,
                                    changes_summary: str = '') -> PrivacyPolicyVersion:
        """
        Create a new privacy policy version.
        """
        try:
            with transaction.atomic():
                # Set current policy as not current
                PrivacyPolicyVersion.objects.filter(is_current=True).update(is_current=False)
                
                # Create new policy version
                policy_version = PrivacyPolicyVersion.objects.create(
                    version=version,
                    title=title,
                    content=content,
                    effective_date=effective_date,
                    is_current=True,
                    requires_explicit_consent=requires_explicit_consent,
                    changes_summary=changes_summary
                )
                
                # Log policy creation
                self.audit_service.create_audit_log(
                    activity_type='compliance_action',
                    action='privacy_policy_created',
                    resource='privacy_policy',
                    outcome='success',
                    details={
                        'version': version,
                        'title': title,
                        'effective_date': effective_date.isoformat(),
                        'requires_explicit_consent': requires_explicit_consent
                    }
                )
                
                logger.info(f"Created privacy policy version: {version}")
                return policy_version
                
        except Exception as e:
            logger.error(f"Failed to create privacy policy version: {str(e)}")
            raise
    
    def record_privacy_policy_acceptance(self, user: User, policy_version: PrivacyPolicyVersion,
                                       acceptance_method: str = 'explicit', ip_address: str = None,
                                       user_agent: str = None) -> PrivacyPolicyAcceptance:
        """
        Record user acceptance of a privacy policy version.
        """
        try:
            acceptance, created = PrivacyPolicyAcceptance.objects.get_or_create(
                user=user,
                policy_version=policy_version,
                defaults={
                    'accepted_at': timezone.now(),
                    'ip_address': ip_address,
                    'user_agent': user_agent,
                    'acceptance_method': acceptance_method
                }
            )
            
            if not created:
                logger.warning(f"Privacy policy already accepted by user {user.id}, version: {policy_version.version}")
                return acceptance
            
            # Log policy acceptance
            self.audit_service.create_audit_log(
                activity_type='compliance_action',
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                action='privacy_policy_accepted',
                resource='privacy_policy_acceptance',
                outcome='success',
                details={
                    'policy_version': policy_version.version,
                    'acceptance_method': acceptance_method,
                    'policy_title': policy_version.title
                }
            )
            
            logger.info(f"Privacy policy accepted by user {user.id}, version: {policy_version.version}")
            return acceptance
            
        except Exception as e:
            logger.error(f"Failed to record privacy policy acceptance: {str(e)}")
            raise
    
    def get_user_privacy_policy_status(self, user: User) -> Dict[str, Any]:
        """
        Get user's privacy policy acceptance status.
        """
        try:
            current_policy = PrivacyPolicyVersion.objects.filter(is_current=True).first()
            
            status = {
                'user_id': str(user.id),
                'current_policy': None,
                'user_acceptance': None,
                'requires_acceptance': False
            }
            
            if current_policy:
                status['current_policy'] = {
                    'version': current_policy.version,
                    'title': current_policy.title,
                    'effective_date': current_policy.effective_date.isoformat(),
                    'requires_explicit_consent': current_policy.requires_explicit_consent
                }
                
                try:
                    acceptance = PrivacyPolicyAcceptance.objects.get(
                        user=user,
                        policy_version=current_policy
                    )
                    status['user_acceptance'] = {
                        'accepted_at': acceptance.accepted_at.isoformat(),
                        'acceptance_method': acceptance.acceptance_method,
                        'ip_address': str(acceptance.ip_address) if acceptance.ip_address else None
                    }
                    status['requires_acceptance'] = False
                    
                except PrivacyPolicyAcceptance.DoesNotExist:
                    status['requires_acceptance'] = current_policy.requires_explicit_consent
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get privacy policy status for user {user.id}: {str(e)}")
            raise
    
    def log_data_disclosure(self, user: User, disclosure_type: str, recipient_name: str,
                           recipient_contact: str, legal_basis: str, data_categories: List[str],
                           purpose: str, retention_period: str, user_notified: bool = False) -> DataDisclosureLog:
        """
        Log data disclosure to third parties for compliance tracking.
        """
        try:
            disclosure = DataDisclosureLog.objects.create(
                user=user,
                disclosure_type=disclosure_type,
                recipient_name=recipient_name,
                recipient_contact=recipient_contact,
                legal_basis=legal_basis,
                data_categories=data_categories,
                purpose=purpose,
                retention_period=retention_period,
                user_notified=user_notified,
                user_notification_date=timezone.now() if user_notified else None
            )
            
            # Log the disclosure
            self.audit_service.create_audit_log(
                activity_type='compliance_action',
                user=user,
                action='data_disclosed',
                resource='user_data',
                outcome='success',
                severity='medium',
                details={
                    'disclosure_id': str(disclosure.disclosure_id),
                    'disclosure_type': disclosure_type,
                    'recipient': recipient_name,
                    'legal_basis': legal_basis,
                    'data_categories': data_categories,
                    'purpose': purpose,
                    'user_notified': user_notified
                }
            )
            
            logger.info(f"Data disclosure logged for user {user.id}: {disclosure.disclosure_id}")
            return disclosure
            
        except Exception as e:
            logger.error(f"Failed to log data disclosure for user {user.id}: {str(e)}")
            raise
    
    def get_user_data_disclosures(self, user: User) -> List[Dict[str, Any]]:
        """
        Get all data disclosures for a user.
        """
        try:
            disclosures = []
            
            for disclosure in DataDisclosureLog.objects.filter(user=user).order_by('-disclosure_date'):
                disclosure_info = {
                    'disclosure_id': str(disclosure.disclosure_id),
                    'disclosure_type': disclosure.disclosure_type,
                    'recipient_name': disclosure.recipient_name,
                    'legal_basis': disclosure.legal_basis,
                    'data_categories': disclosure.data_categories,
                    'purpose': disclosure.purpose,
                    'disclosure_date': disclosure.disclosure_date.isoformat(),
                    'retention_period': disclosure.retention_period,
                    'user_notified': disclosure.user_notified,
                    'user_notification_date': disclosure.user_notification_date.isoformat() if disclosure.user_notification_date else None
                }
                disclosures.append(disclosure_info)
            
            return disclosures
            
        except Exception as e:
            logger.error(f"Failed to get data disclosures for user {user.id}: {str(e)}")
            raise
    
    def check_consent_expiration(self) -> Dict[str, Any]:
        """
        Check for expired consents and update their status.
        """
        try:
            now = timezone.now()
            expired_consents = ConsentRecord.objects.filter(
                status='granted',
                expires_at__lt=now
            )
            
            expired_count = expired_consents.count()
            
            # Update expired consents
            expired_consents.update(status='expired')
            
            # Log the expiration check
            self.audit_service.create_audit_log(
                activity_type='compliance_action',
                action='consent_expiration_check',
                resource='consent_records',
                outcome='success',
                details={
                    'expired_consents_count': expired_count,
                    'check_timestamp': now.isoformat()
                }
            )
            
            logger.info(f"Consent expiration check completed: {expired_count} consents expired")
            
            return {
                'expired_consents': expired_count,
                'check_timestamp': now.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to check consent expiration: {str(e)}")
            raise
    
    def get_withdrawable_consents(self, user: User) -> List[Dict[str, Any]]:
        """
        Get list of consents that can be withdrawn by the user.
        """
        try:
            withdrawable_consents = []
            
            consent_records = ConsentRecord.objects.filter(
                user=user,
                status='granted'
            ).select_related('purpose')
            
            for consent in consent_records:
                if not consent.purpose.is_essential:
                    consent_info = {
                        'purpose': {
                            'name': consent.purpose.name,
                            'description': consent.purpose.description,
                            'purpose_type': consent.purpose.purpose_type
                        },
                        'consent_given_at': consent.consent_given_at.isoformat(),
                        'expires_at': consent.expires_at.isoformat() if consent.expires_at else None,
                        'can_withdraw': True
                    }
                    withdrawable_consents.append(consent_info)
            
            return withdrawable_consents
            
        except Exception as e:
            logger.error(f"Failed to get withdrawable consents for user {user.id}: {str(e)}")
            raise