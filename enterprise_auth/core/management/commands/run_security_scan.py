"""
Management command to run security vulnerability scans.
"""

import logging
from django.core.management.base import BaseCommand

from enterprise_auth.core.services.security_compliance_service import SecurityComplianceService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Run security vulnerability scan'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--scan-type',
            type=str,
            default='comprehensive',
            choices=['comprehensive', 'dependency', 'static', 'configuration'],
            help='Type of security scan to run'
        )
    
    def handle(self, *args, **options):
        scan_type = options['scan_type']
        
        self.stdout.write(
            self.style.SUCCESS(f'Starting {scan_type} security scan')
        )
        
        try:
            security_service = SecurityComplianceService()
            scan_results = security_service.run_security_scan(scan_type)
            
            # Display scan summary
            summary = scan_results['scan_summary']
            self.stdout.write(
                self.style.SUCCESS(f'Scan completed: {scan_results["scan_id"]}')
            )
            
            self.stdout.write(f'Total vulnerabilities found: {summary["total_vulnerabilities"]}')
            
            if summary['critical_vulnerabilities'] > 0:
                self.stdout.write(
                    self.style.ERROR(f'Critical vulnerabilities: {summary["critical_vulnerabilities"]}')
                )
            
            if summary['high_vulnerabilities'] > 0:
                self.stdout.write(
                    self.style.WARNING(f'High severity vulnerabilities: {summary["high_vulnerabilities"]}')
                )
            
            self.stdout.write(f'Medium severity vulnerabilities: {summary["medium_vulnerabilities"]}')
            self.stdout.write(f'Low severity vulnerabilities: {summary["low_vulnerabilities"]}')
            
            # Display recommendations
            if scan_results['recommendations']:
                self.stdout.write('\nRecommendations:')
                for rec in scan_results['recommendations']:
                    priority_style = self.style.ERROR if rec['priority'] == 'critical' else (
                        self.style.WARNING if rec['priority'] in ['high', 'warning'] else self.style.SUCCESS
                    )
                    self.stdout.write(f'  {priority_style(rec["priority"].upper())}: {rec["message"]}')
            
            # Display OWASP compliance
            owasp_compliance = scan_results['owasp_compliance']
            self.stdout.write(f'\nOWASP Compliance Score: {owasp_compliance["overall_compliance_score"]}%')
            self.stdout.write(f'Overall Status: {owasp_compliance["overall_status"]}')
            
            self.stdout.write(
                self.style.SUCCESS(f'Security scan completed successfully')
            )
            
        except Exception as e:
            logger.error(f'Failed to run security scan: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'Failed to run security scan: {str(e)}')
            )