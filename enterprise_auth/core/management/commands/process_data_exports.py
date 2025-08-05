"""
Management command to process pending data export requests.
"""

import logging
from django.core.management.base import BaseCommand
from django.utils import timezone

from enterprise_auth.core.models.compliance import DataExportRequest
from enterprise_auth.core.services.compliance_service import GDPRComplianceService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Process pending data export requests'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--max-requests',
            type=int,
            default=10,
            help='Maximum number of requests to process in one run'
        )
        parser.add_argument(
            '--timeout-hours',
            type=int,
            default=24,
            help='Timeout for stuck processing requests in hours'
        )
    
    def handle(self, *args, **options):
        max_requests = options['max_requests']
        timeout_hours = options['timeout_hours']
        
        self.stdout.write(
            self.style.SUCCESS(f'Starting data export processing (max: {max_requests} requests)')
        )
        
        # Reset stuck processing requests
        timeout_threshold = timezone.now() - timezone.timedelta(hours=timeout_hours)
        stuck_requests = DataExportRequest.objects.filter(
            status='processing',
            processing_started_at__lt=timeout_threshold
        )
        
        if stuck_requests.exists():
            stuck_count = stuck_requests.count()
            stuck_requests.update(
                status='failed',
                error_message='Processing timeout - request was stuck'
            )
            self.stdout.write(
                self.style.WARNING(f'Reset {stuck_count} stuck processing requests')
            )
        
        # Get pending requests
        pending_requests = DataExportRequest.objects.filter(
            status='pending'
        ).order_by('created_at')[:max_requests]
        
        if not pending_requests.exists():
            self.stdout.write(
                self.style.SUCCESS('No pending data export requests found')
            )
            return
        
        gdpr_service = GDPRComplianceService()
        processed_count = 0
        failed_count = 0
        
        for export_request in pending_requests:
            try:
                self.stdout.write(f'Processing export request: {export_request.request_id}')
                
                success = gdpr_service.process_data_export(export_request)
                
                if success:
                    processed_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'✓ Successfully processed: {export_request.request_id}')
                    )
                else:
                    failed_count += 1
                    self.stdout.write(
                        self.style.ERROR(f'✗ Failed to process: {export_request.request_id}')
                    )
                    
            except Exception as e:
                failed_count += 1
                logger.error(f'Failed to process export request {export_request.request_id}: {str(e)}')
                self.stdout.write(
                    self.style.ERROR(f'✗ Exception processing {export_request.request_id}: {str(e)}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Data export processing completed: {processed_count} successful, {failed_count} failed'
            )
        )