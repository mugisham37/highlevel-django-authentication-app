"""
Management command to verify audit log integrity.
"""

import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from enterprise_auth.core.services.audit_integrity_service import AuditIntegrityService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Verify audit log integrity and generate integrity report'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--period-days',
            type=int,
            default=30,
            help='Number of days to verify (default: 30)'
        )
        parser.add_argument(
            '--repair',
            action='store_true',
            help='Repair integrity issues if found'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Simulate repair without making changes (only with --repair)'
        )
        parser.add_argument(
            '--generate-report',
            action='store_true',
            help='Generate comprehensive integrity report'
        )
    
    def handle(self, *args, **options):
        period_days = options['period_days']
        repair = options['repair']
        dry_run = options['dry_run']
        generate_report = options['generate_report']
        
        self.stdout.write(
            self.style.SUCCESS(f'Starting audit integrity verification for {period_days} days')
        )
        
        try:
            integrity_service = AuditIntegrityService()
            
            # Calculate date range
            end_date = timezone.now()
            start_date = end_date - timedelta(days=period_days)
            
            # Run integrity verification
            verification_results = integrity_service.verify_audit_chain_integrity(
                start_date=start_date,
                end_date=end_date
            )
            
            # Display verification results
            self._display_verification_results(verification_results)
            
            # Repair if requested
            if repair:
                self.stdout.write('\nStarting audit chain repair...')
                repair_results = integrity_service.repair_audit_chain(
                    start_date=start_date,
                    end_date=end_date,
                    dry_run=dry_run
                )
                self._display_repair_results(repair_results)
            
            # Generate report if requested
            if generate_report:
                self.stdout.write('\nGenerating integrity report...')
                report = integrity_service.create_integrity_report(period_days)
                self._display_integrity_report(report)
            
            self.stdout.write(
                self.style.SUCCESS('Audit integrity verification completed')
            )
            
        except Exception as e:
            logger.error(f'Failed to verify audit integrity: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'Failed to verify audit integrity: {str(e)}')
            )
    
    def _display_verification_results(self, results):
        """Display verification results."""
        self.stdout.write(f'\n=== Verification Results ===')
        self.stdout.write(f'Period: {results.get("period_start", "N/A")} to {results.get("period_end", "N/A")}')
        self.stdout.write(f'Total logs verified: {results["total_logs_verified"]}')
        
        status = results['integrity_status']
        if status == 'valid':
            self.stdout.write(self.style.SUCCESS(f'Integrity Status: {status.upper()}'))
        elif status == 'compromised':
            self.stdout.write(self.style.ERROR(f'Integrity Status: {status.upper()}'))
        else:
            self.stdout.write(self.style.WARNING(f'Integrity Status: {status.upper()}'))
        
        # Display issues
        if results['missing_checksums'] > 0:
            self.stdout.write(
                self.style.WARNING(f'Missing checksums: {results["missing_checksums"]}')
            )
        
        if results['checksum_mismatches']:
            self.stdout.write(
                self.style.ERROR(f'Checksum mismatches: {len(results["checksum_mismatches"])}')
            )
            for mismatch in results['checksum_mismatches'][:5]:  # Show first 5
                self.stdout.write(f'  - Audit ID: {mismatch["audit_id"]} at {mismatch["timestamp"]}')
            if len(results['checksum_mismatches']) > 5:
                self.stdout.write(f'  ... and {len(results["checksum_mismatches"]) - 5} more')
        
        if results['chain_breaks']:
            self.stdout.write(
                self.style.ERROR(f'Chain breaks: {len(results["chain_breaks"])}')
            )
            for break_info in results['chain_breaks'][:5]:  # Show first 5
                self.stdout.write(f'  - Audit ID: {break_info["audit_id"]} at {break_info["timestamp"]}')
            if len(results['chain_breaks']) > 5:
                self.stdout.write(f'  ... and {len(results["chain_breaks"]) - 5} more')
    
    def _display_repair_results(self, results):
        """Display repair results."""
        self.stdout.write(f'\n=== Repair Results ===')
        
        if results['dry_run']:
            self.stdout.write(self.style.WARNING('DRY RUN - No changes were made'))
        
        self.stdout.write(f'Total logs processed: {results["total_logs_processed"]}')
        self.stdout.write(f'Checksums updated: {results["checksums_updated"]}')
        self.stdout.write(f'Chain links updated: {results["chain_links_updated"]}')
        
        if results['errors']:
            self.stdout.write(
                self.style.ERROR(f'Errors encountered: {len(results["errors"])}')
            )
            for error in results['errors'][:3]:  # Show first 3 errors
                self.stdout.write(f'  - {error["audit_id"]}: {error["error"]}')
            if len(results['errors']) > 3:
                self.stdout.write(f'  ... and {len(results["errors"]) - 3} more errors')
        
        if results['checksums_updated'] > 0 or results['chain_links_updated'] > 0:
            if not results['dry_run']:
                self.stdout.write(self.style.SUCCESS('Audit chain repair completed successfully'))
            else:
                self.stdout.write(self.style.WARNING('Run without --dry-run to apply changes'))
    
    def _display_integrity_report(self, report):
        """Display integrity report summary."""
        self.stdout.write(f'\n=== Integrity Report Summary ===')
        
        metadata = report['report_metadata']
        self.stdout.write(f'Report generated: {metadata["generated_at"]}')
        self.stdout.write(f'Period: {metadata["period_days"]} days')
        
        stats = report['audit_statistics']
        self.stdout.write(f'Total audit logs: {stats["total_audit_logs"]}')
        self.stdout.write(f'Average logs per day: {stats["average_logs_per_day"]}')
        
        # Severity breakdown
        self.stdout.write('\nLogs by severity:')
        for severity, count in stats['logs_by_severity'].items():
            self.stdout.write(f'  {severity}: {count}')
        
        # Integrity score
        integrity_score = report['integrity_score']
        if integrity_score >= 95:
            score_style = self.style.SUCCESS
        elif integrity_score >= 85:
            score_style = self.style.WARNING
        else:
            score_style = self.style.ERROR
        
        self.stdout.write(f'\nIntegrity Score: {score_style(str(integrity_score))}%')
        
        # Compliance status
        compliance = report['compliance_status']
        compliance_status = 'COMPLIANT' if compliance['soc2_compliant'] else 'NON-COMPLIANT'
        status_style = self.style.SUCCESS if compliance['soc2_compliant'] else self.style.ERROR
        
        self.stdout.write(f'SOC2 Compliance: {status_style(compliance_status)}')
        self.stdout.write(f'Integrity Level: {compliance["integrity_level"].upper()}')
        
        # Recommendations
        if compliance['recommendations']:
            self.stdout.write('\nRecommendations:')
            for i, rec in enumerate(compliance['recommendations'], 1):
                self.stdout.write(f'  {i}. {rec}')