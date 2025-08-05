"""
Management command to check and update expired consents.
"""

import logging
from django.core.management.base import BaseCommand

from enterprise_auth.core.services.privacy_rights_service import PrivacyRightsService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Check for expired consents and update their status'
    
    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Starting consent expiration check')
        )
        
        try:
            privacy_service = PrivacyRightsService()
            result = privacy_service.check_consent_expiration()
            
            expired_count = result['expired_consents']
            
            if expired_count > 0:
                self.stdout.write(
                    self.style.WARNING(f'Updated {expired_count} expired consents')
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS('No expired consents found')
                )
            
            self.stdout.write(
                self.style.SUCCESS(f'Consent expiration check completed at {result["check_timestamp"]}')
            )
            
        except Exception as e:
            logger.error(f'Failed to check consent expiration: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'Failed to check consent expiration: {str(e)}')
            )