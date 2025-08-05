"""
Management command to set up the complete compliance system.
"""

import logging
from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.utils import timezone

from enterprise_auth.core.services.privacy_rights_service import PrivacyRightsService
from enterprise_auth.core.services.security_compliance_service import SecurityComplianceService
from enterprise_auth.core.services.compliance_dashboard_service import ComplianceDashboardService
from enterprise_auth.core.services.audit_integrity_service import AuditIntegrityService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Set up the complete compliance system with all components'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--skip-security-scan',
            action='store_true',
            help='Skip initial security scan (faster setup)'
        )
        parser.add_argument(
            '--skip-integrity-check',
            action='store_true',
            help='Skip initial audit integrity check'
        )
        parser.add_argument(
            '--generate-sample-reports',
            action='store_true',
            help='Generate sample compliance reports'
        )
    
    def handle(self, *args, **options):
        skip_security_scan = options['skip_security_scan']
        skip_integrity_check = options['skip_integrity_check']
        generate_sample_reports = options['generate_sample_reports']
        
        self.stdout.write(
            self.style.SUCCESS('Setting up comprehensive compliance system')
        )
        
        try:
            # Step 1: Initialize data processing purposes
            self.stdout.write('\n1. Initializing data processing purposes...')
            self._initialize_data_processing_purposes()
            
            # Step 2: Set up security compliance
            self.stdout.write('\n2. Setting up security compliance...')
            self._setup_security_compliance(skip_security_scan)
            
            # Step 3: Verify audit integrity
            if not skip_integrity_check:
                self.stdout.write('\n3. Verifying audit integrity...')
                self._verify_audit_integrity()
            else:
                self.stdout.write('\n3. Skipping audit integrity check...')
            
            # Step 4: Generate sample reports
            if generate_sample_reports:
                self.stdout.write('\n4. Generating sample compliance reports...')
                self._generate_sample_reports()
            else:
                self.stdout.write('\n4. Skipping sample report generation...')
            
            # Step 5: Test compliance dashboard
            self.stdout.write('\n5. Testing compliance dashboard...')
            self._test_compliance_dashboard()
            
            # Step 6: Display setup summary
            self.stdout.write('\n6. Displaying setup summary...')
            self._display_setup_summary()
            
            self.stdout.write(
                self.style.SUCCESS('\n✅ Compliance system setup completed successfully!')
            )
            
            # Display next steps
            self._display_next_steps()
            
        except Exception as e:
            logger.error(f'Failed to set up compliance system: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'❌ Failed to set up compliance system: {str(e)}')
            )
    
    def _initialize_data_processing_purposes(self):
        """Initialize data processing purposes."""
        try:
            privacy_service = PrivacyRightsService()
            purposes = privacy_service.initialize_data_processing_purposes()
            
            self.stdout.write(f'   ✅ Initialized {len(purposes)} data processing purposes:')
            for purpose in purposes:
                essential_marker = ' (Essential)' if purpose.is_essential else ''
                self.stdout.write(f'      - {purpose.name}: {purpose.description}{essential_marker}')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'   ❌ Failed to initialize data processing purposes: {str(e)}')
            )
            raise
    
    def _setup_security_compliance(self, skip_scan):
        """Set up security compliance system."""
        try:
            security_service = SecurityComplianceService()
            
            if not skip_scan:
                self.stdout.write('   Running initial security scan...')
                scan_results = security_service.run_security_scan('comprehensive')
                
                summary = scan_results.get('scan_summary', {})
                self.stdout.write(f'   ✅ Security scan completed:')
                self.stdout.write(f'      - Total vulnerabilities: {summary.get("total_vulnerabilities", 0)}')
                self.stdout.write(f'      - Critical: {summary.get("critical_vulnerabilities", 0)}')
                self.stdout.write(f'      - High: {summary.get("high_vulnerabilities", 0)}')
                self.stdout.write(f'      - Medium: {summary.get("medium_vulnerabilities", 0)}')
                self.stdout.write(f'      - Low: {summary.get("low_vulnerabilities", 0)}')
                
                # Display OWASP compliance
                owasp_compliance = scan_results.get('owasp_compliance', {})
                overall_score = owasp_compliance.get('overall_compliance_score', 0)
                self.stdout.write(f'      - OWASP Compliance Score: {overall_score}%')
            else:
                self.stdout.write('   ✅ Security scan skipped')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'   ❌ Failed to set up security compliance: {str(e)}')
            )
            raise
    
    def _verify_audit_integrity(self):
        """Verify audit integrity."""
        try:
            integrity_service = AuditIntegrityService()
            
            # Run integrity verification for last 7 days
            verification_results = integrity_service.verify_audit_chain_integrity()
            
            self.stdout.write(f'   ✅ Audit integrity verification completed:')
            self.stdout.write(f'      - Total logs verified: {verification_results["total_logs_verified"]}')
            self.stdout.write(f'      - Integrity status: {verification_results["integrity_status"]}')
            self.stdout.write(f'      - Missing checksums: {verification_results["missing_checksums"]}')
            self.stdout.write(f'      - Checksum mismatches: {len(verification_results["checksum_mismatches"])}')
            self.stdout.write(f'      - Chain breaks: {len(verification_results["chain_breaks"])}')
            
            # Repair if needed
            if verification_results['integrity_status'] == 'compromised':
                self.stdout.write('   🔧 Repairing audit chain integrity...')
                repair_results = integrity_service.repair_audit_chain(dry_run=False)
                self.stdout.write(f'      - Checksums updated: {repair_results["checksums_updated"]}')
                self.stdout.write(f'      - Chain links updated: {repair_results["chain_links_updated"]}')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'   ❌ Failed to verify audit integrity: {str(e)}')
            )
            raise
    
    def _generate_sample_reports(self):
        """Generate sample compliance reports."""
        try:
            # Use existing management command
            report_types = ['gdpr_compliance', 'soc2_audit', 'security_assessment']
            
            for report_type in report_types:
                try:
                    call_command('generate_compliance_report', 
                               report_type=report_type, 
                               period_days=30,
                               verbosity=0)
                    self.stdout.write(f'   ✅ Generated {report_type} report')
                except Exception as e:
                    self.stdout.write(
                        self.style.WARNING(f'   ⚠️  Failed to generate {report_type} report: {str(e)}')
                    )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'   ❌ Failed to generate sample reports: {str(e)}')
            )
            raise
    
    def _test_compliance_dashboard(self):
        """Test compliance dashboard functionality."""
        try:
            dashboard_service = ComplianceDashboardService()
            
            # Get compliance overview
            overview = dashboard_service.get_compliance_overview(period_days=7)
            
            self.stdout.write(f'   ✅ Compliance dashboard test completed:')
            self.stdout.write(f'      - Overall compliance score: {overview["overall_compliance_score"]}%')
            
            # Display compliance status by area
            areas = ['gdpr_compliance', 'soc2_compliance', 'security_compliance', 'audit_integrity']
            for area in areas:
                if area in overview:
                    status = overview[area].get('status', 'unknown')
                    score = overview[area].get('compliance_score', 0)
                    status_icon = '✅' if status == 'compliant' else '⚠️'
                    self.stdout.write(f'      - {area.replace("_", " ").title()}: {status_icon} {status} ({score}%)')
            
            # Display action items
            action_items = overview.get('action_items', [])
            if action_items:
                self.stdout.write(f'      - Action items: {len(action_items)}')
                for item in action_items[:3]:  # Show first 3
                    priority = item.get('priority', 'medium')
                    title = item.get('title', 'Unknown')
                    self.stdout.write(f'        • [{priority.upper()}] {title}')
                if len(action_items) > 3:
                    self.stdout.write(f'        ... and {len(action_items) - 3} more')
            else:
                self.stdout.write(f'      - Action items: None (all good!)')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'   ❌ Failed to test compliance dashboard: {str(e)}')
            )
            raise
    
    def _display_setup_summary(self):
        """Display setup summary."""
        try:
            self.stdout.write(f'   📊 Compliance System Components:')
            
            components = [
                ('GDPR Compliance', 'Data portability, right to erasure, consent management'),
                ('CCPA Compliance', 'Privacy rights management, opt-out handling'),
                ('SOC2 Compliance', 'Audit trail integrity, security controls'),
                ('Security Compliance', 'OWASP guidelines, vulnerability management'),
                ('Audit Integrity', 'Cryptographic verification, chain integrity'),
                ('Compliance Dashboard', 'Real-time monitoring, alerting'),
                ('Privacy Rights', 'Consent management, policy tracking'),
                ('Data Portability', 'Export in multiple formats (JSON, CSV, XML)'),
                ('Monitoring & Alerting', 'Real-time compliance monitoring'),
                ('Management Commands', 'Automated compliance operations')
            ]
            
            for component, description in components:
                self.stdout.write(f'      ✅ {component}: {description}')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'   ❌ Failed to display setup summary: {str(e)}')
            )
    
    def _display_next_steps(self):
        """Display next steps for the user."""
        self.stdout.write(f'\n📋 Next Steps:')
        
        next_steps = [
            '1. Configure compliance monitoring middleware in settings.py',
            '2. Set up Celery periodic tasks for automated compliance monitoring',
            '3. Configure alerting channels (email, Slack, PagerDuty) in settings',
            '4. Review and customize data processing purposes as needed',
            '5. Set up regular security scans and vulnerability assessments',
            '6. Configure backup and disaster recovery procedures',
            '7. Train staff on compliance procedures and incident response',
            '8. Schedule regular compliance audits and reviews'
        ]
        
        for step in next_steps:
            self.stdout.write(f'   {step}')
        
        self.stdout.write(f'\n🔧 Management Commands Available:')
        
        commands = [
            ('verify_audit_integrity', 'Verify and repair audit log integrity'),
            ('run_security_scan', 'Run security vulnerability scans'),
            ('generate_compliance_report', 'Generate compliance reports'),
            ('generate_compliance_dashboard', 'Generate compliance dashboard data'),
            ('check_consent_expiration', 'Check and update expired consents'),
            ('process_data_exports', 'Process pending data export requests'),
            ('initialize_compliance', 'Initialize compliance data processing purposes')
        ]
        
        for command, description in commands:
            self.stdout.write(f'   • python manage.py {command} - {description}')
        
        self.stdout.write(f'\n📚 API Endpoints Available:')
        
        endpoints = [
            ('GET /api/v1/compliance/dashboard/', 'Compliance dashboard overview'),
            ('GET /api/v1/compliance/data-export/', 'GDPR data export requests'),
            ('POST /api/v1/compliance/data-deletion/', 'GDPR data deletion requests'),
            ('GET /api/v1/compliance/consent/', 'Consent management'),
            ('GET /api/v1/compliance/security/', 'Security compliance status'),
            ('GET /api/v1/compliance/audit-integrity/', 'Audit integrity verification'),
            ('GET /api/v1/compliance/alerts/', 'Compliance alerts'),
            ('GET /api/v1/compliance/reports/', 'Compliance reports')
        ]
        
        for endpoint, description in endpoints:
            self.stdout.write(f'   • {endpoint} - {description}')
        
        self.stdout.write(f'\n🎯 Key Features Implemented:')
        
        features = [
            '✅ GDPR Article 20 (Right to data portability) - Export user data in JSON/CSV/XML',
            '✅ GDPR Article 17 (Right to erasure) - Secure data deletion with audit trails',
            '✅ GDPR Article 6 (Lawful basis) - Consent management and tracking',
            '✅ CCPA Privacy Rights - Right to know, delete, and opt-out',
            '✅ SOC2 Audit Trail - Cryptographic integrity verification',
            '✅ OWASP Security Guidelines - Automated vulnerability scanning',
            '✅ Real-time Compliance Monitoring - Dashboard and alerting',
            '✅ Audit Log Integrity - SHA-256 checksums and chain verification',
            '✅ Privacy Policy Management - Version tracking and acceptance',
            '✅ Data Disclosure Logging - Third-party data sharing tracking'
        ]
        
        for feature in features:
            self.stdout.write(f'   {feature}')
        
        self.stdout.write(
            self.style.SUCCESS(f'\n🚀 Your enterprise-grade compliance system is ready!')
        )