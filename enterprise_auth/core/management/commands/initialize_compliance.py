"""
Management command to initialize compliance system with default data processing purposes.
"""

import logging
from django.core.management.base import BaseCommand

from enterprise_auth.core.services.privacy_rights_service import PrivacyRightsService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Initialize compliance system with default data processing purposes'
    
    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Initializing compliance system')
        )
        
        try:
            privacy_service = PrivacyRightsService()
            purposes = privacy_service.initialize_data_processing_purposes()
            
            self.stdout.write(
                self.style.SUCCESS(f'Initialized {len(purposes)} data processing purposes:')
            )
            
            for purpose in purposes:
                essential_marker = ' (Essential)' if purpose.is_essential else ''
                self.stdout.write(f'  - {purpose.name}: {purpose.description}{essential_marker}')
            
            self.stdout.write(
                self.style.SUCCESS('Compliance system initialization completed')
            )
            
        except Exception as e:
            logger.error(f'Failed to initialize compliance system: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'Failed to initialize compliance system: {str(e)}')
            )