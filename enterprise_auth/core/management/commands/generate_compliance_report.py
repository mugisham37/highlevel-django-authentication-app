"""
Management command to generate compliance reports.
"""

import logging
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth import get_user_model

from enterprise_auth.core.services.compliance_service import SOC2AuditService

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Generate compliance reports'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--report-type',
            type=str,
            required=True,
            choices=[
                'gdpr_compliance', 'ccpa_compliance', 'soc2_audit',
                'security_assessment', 'data_processing', 'breach_notification'
            ],
            help='Type of compliance report to generate'
        )
        parser.add_argument(
            '--period-days',
            type=int,
            default=30,
            help='Number of days to include in the report period'
        )
        parser.add_argument(
            '--generated-by',
            type=str,
            help='Email of the user generating the report (for admin users)'
        )
    
    def handle(self, *args, **options):
        report_type = options['report_type']
        period_days = options['period_days']
        generated_by_email = options.get('generated_by')
        
        self.stdout.write(
            self.style.SUCCESS(f'Generating {report_type} report for {period_days} days')
        )
        
        try:
            # Calculate report period
            end_date = timezone.now()
            start_date = end_date - timedelta(days=period_days)
            
            # Get user if specified
            generated_by = None
            if generated_by_email:
                try:
                    generated_by = User.objects.get(email=generated_by_email)
                except User.DoesNotExist:
                    self.stdout.write(
                        self.style.WARNING(f'User not found: {generated_by_email}. Report will be generated without user attribution.')
                    )
            
            # Generate report
            audit_service = SOC2AuditService()
            report = audit_service.generate_compliance_report(
                report_type=report_type,
                period_start=start_date,
                period_end=end_date,
                generated_by=generated_by
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'Report generated successfully: {report.report_id}')
            )
            
            # Display report summary
            self.stdout.write(f'Report Title: {report.title}')
            self.stdout.write(f'Period: {start_date.strftime("%Y-%m-%d")} to {end_date.strftime("%Y-%m-%d")}')
            self.stdout.write(f'Generated At: {report.generated_at.strftime("%Y-%m-%d %H:%M:%S")}')
            
            if report.summary:
                self.stdout.write('\nReport Summary:')
                for key, value in report.summary.items():
                    self.stdout.write(f'  {key}: {value}')
            
            if report.recommendations:
                self.stdout.write('\nRecommendations:')
                for rec in report.recommendations:
                    self.stdout.write(f'  - {rec}')
            
            self.stdout.write(
                self.style.SUCCESS('Compliance report generation completed')
            )
            
        except Exception as e:
            logger.error(f'Failed to generate compliance report: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'Failed to generate compliance report: {str(e)}')
            )