"""
Management command to generate compliance dashboard data.
"""

import json
import logging
from django.core.management.base import BaseCommand
from django.utils import timezone

from enterprise_auth.core.services.compliance_dashboard_service import ComplianceDashboardService

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Generate compliance dashboard data and metrics'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--period-days',
            type=int,
            default=30,
            help='Number of days to include in dashboard metrics (default: 30)'
        )
        parser.add_argument(
            '--output-format',
            type=str,
            choices=['json', 'summary'],
            default='summary',
            help='Output format (default: summary)'
        )
        parser.add_argument(
            '--save-to-file',
            type=str,
            help='Save dashboard data to JSON file'
        )
        parser.add_argument(
            '--show-alerts',
            action='store_true',
            help='Show compliance alerts'
        )
    
    def handle(self, *args, **options):
        period_days = options['period_days']
        output_format = options['output_format']
        save_to_file = options.get('save_to_file')
        show_alerts = options['show_alerts']
        
        self.stdout.write(
            self.style.SUCCESS(f'Generating compliance dashboard for {period_days} days')
        )
        
        try:
            dashboard_service = ComplianceDashboardService()
            
            # Generate compliance overview
            overview = dashboard_service.get_compliance_overview(period_days)
            
            if output_format == 'json':
                self._display_json_output(overview)
            else:
                self._display_summary_output(overview)
            
            # Show alerts if requested
            if show_alerts:
                alerts = dashboard_service.get_compliance_alerts()
                self._display_alerts(alerts)
            
            # Save to file if requested
            if save_to_file:
                self._save_to_file(overview, save_to_file)
            
            self.stdout.write(
                self.style.SUCCESS('Compliance dashboard generation completed')
            )
            
        except Exception as e:
            logger.error(f'Failed to generate compliance dashboard: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'Failed to generate compliance dashboard: {str(e)}')
            )
    
    def _display_json_output(self, overview):
        """Display overview in JSON format."""
        self.stdout.write(json.dumps(overview, indent=2, default=str))
    
    def _display_summary_output(self, overview):
        """Display overview in summary format."""
        metadata = overview['dashboard_metadata']
        
        self.stdout.write(f'\n=== Compliance Dashboard Summary ===')
        self.stdout.write(f'Generated: {metadata["generated_at"]}')
        self.stdout.write(f'Period: {metadata["period_start"]} to {metadata["period_end"]}')
        self.stdout.write(f'Period Days: {metadata["period_days"]}')
        
        # Overall compliance score
        overall_score = overview['overall_compliance_score']
        if overall_score >= 90:
            score_style = self.style.SUCCESS
        elif overall_score >= 70:
            score_style = self.style.WARNING
        else:
            score_style = self.style.ERROR
        
        self.stdout.write(f'\nOverall Compliance Score: {score_style(f"{overall_score}%")}')
        
        # GDPR Compliance
        self._display_gdpr_summary(overview.get('gdpr_compliance', {}))
        
        # CCPA Compliance
        self._display_ccpa_summary(overview.get('ccpa_compliance', {}))
        
        # SOC2 Compliance
        self._display_soc2_summary(overview.get('soc2_compliance', {}))
        
        # Security Compliance
        self._display_security_summary(overview.get('security_compliance', {}))
        
        # Audit Integrity
        self._display_audit_integrity_summary(overview.get('audit_integrity', {}))
        
        # Action Items
        self._display_action_items(overview.get('action_items', []))
    
    def _display_gdpr_summary(self, gdpr_data):
        """Display GDPR compliance summary."""
        if not gdpr_data:
            return
        
        self.stdout.write(f'\n--- GDPR Compliance ---')
        
        score = gdpr_data.get('compliance_score', 0)
        status = gdpr_data.get('status', 'unknown')
        
        status_style = self.style.SUCCESS if status == 'compliant' else self.style.ERROR
        self.stdout.write(f'Score: {score}% | Status: {status_style(status.upper())}')
        
        # Data portability
        portability = gdpr_data.get('data_portability', {})
        if portability:
            self.stdout.write(f'Data Export Requests:')
            self.stdout.write(f'  Total: {portability.get("total_requests", 0)}')
            self.stdout.write(f'  Completed: {portability.get("completed_requests", 0)}')
            self.stdout.write(f'  Pending: {portability.get("pending_requests", 0)}')
            self.stdout.write(f'  Failed: {portability.get("failed_requests", 0)}')
            
            avg_time = portability.get('average_processing_time_hours', 0)
            if avg_time > 72:  # More than 3 days
                time_style = self.style.ERROR
            elif avg_time > 24:  # More than 1 day
                time_style = self.style.WARNING
            else:
                time_style = self.style.SUCCESS
            self.stdout.write(f'  Avg Processing Time: {time_style(f"{avg_time}h")}')
        
        # Right to erasure
        erasure = gdpr_data.get('right_to_erasure', {})
        if erasure:
            self.stdout.write(f'Data Deletion Requests:')
            self.stdout.write(f'  Total: {erasure.get("total_requests", 0)}')
            self.stdout.write(f'  Completed: {erasure.get("completed_requests", 0)}')
            self.stdout.write(f'  Pending: {erasure.get("pending_requests", 0)}')
            self.stdout.write(f'  Rejected: {erasure.get("rejected_requests", 0)}')
    
    def _display_ccpa_summary(self, ccpa_data):
        """Display CCPA compliance summary."""
        if not ccpa_data:
            return
        
        self.stdout.write(f'\n--- CCPA Compliance ---')
        
        score = ccpa_data.get('compliance_score', 0)
        status = ccpa_data.get('status', 'unknown')
        
        status_style = self.style.SUCCESS if status == 'compliant' else self.style.ERROR
        self.stdout.write(f'Score: {score}% | Status: {status_style(status.upper())}')
        
        self.stdout.write(f'Right to Know Requests: {ccpa_data.get("right_to_know_requests", 0)}')
        self.stdout.write(f'Right to Delete Requests: {ccpa_data.get("right_to_delete_requests", 0)}')
        self.stdout.write(f'Opt-out Requests: {ccpa_data.get("opt_out_requests", 0)}')
    
    def _display_soc2_summary(self, soc2_data):
        """Display SOC2 compliance summary."""
        if not soc2_data:
            return
        
        self.stdout.write(f'\n--- SOC2 Compliance ---')
        
        score = soc2_data.get('compliance_score', 0)
        status = soc2_data.get('status', 'unknown')
        
        status_style = self.style.SUCCESS if status == 'compliant' else self.style.ERROR
        self.stdout.write(f'Score: {score}% | Status: {status_style(status.upper())}')
        
        # Audit trail
        audit_trail = soc2_data.get('audit_trail', {})
        if audit_trail:
            self.stdout.write(f'Audit Trail:')
            self.stdout.write(f'  Total Logs: {audit_trail.get("total_logs", 0)}')
            
            integrity_score = audit_trail.get('integrity_score', 0)
            if integrity_score >= 95:
                integrity_style = self.style.SUCCESS
            elif integrity_score >= 85:
                integrity_style = self.style.WARNING
            else:
                integrity_style = self.style.ERROR
            
            self.stdout.write(f'  Integrity Score: {integrity_style(f"{integrity_score}%")}')
            self.stdout.write(f'  Integrity Status: {audit_trail.get("integrity_status", "unknown").upper()}')
            
            # Severity breakdown
            severity_breakdown = audit_trail.get('logs_by_severity', {})
            if severity_breakdown:
                self.stdout.write(f'  Logs by Severity:')
                for severity, count in severity_breakdown.items():
                    self.stdout.write(f'    {severity}: {count}')
    
    def _display_security_summary(self, security_data):
        """Display security compliance summary."""
        if not security_data:
            return
        
        self.stdout.write(f'\n--- Security Compliance ---')
        
        score = security_data.get('compliance_score', 0)
        status = security_data.get('status', 'unknown')
        
        status_style = self.style.SUCCESS if status == 'compliant' else self.style.ERROR
        self.stdout.write(f'OWASP Score: {score}% | Status: {status_style(status.upper())}')
        
        # Vulnerability management
        vuln_mgmt = security_data.get('vulnerability_management', {})
        if vuln_mgmt:
            self.stdout.write(f'Vulnerabilities:')
            self.stdout.write(f'  Total: {vuln_mgmt.get("total_vulnerabilities", 0)}')
            self.stdout.write(f'  Open: {vuln_mgmt.get("open_vulnerabilities", 0)}')
            self.stdout.write(f'  Resolved: {vuln_mgmt.get("resolved_vulnerabilities", 0)}')
            
            critical = vuln_mgmt.get('critical_vulnerabilities', 0)
            high = vuln_mgmt.get('high_vulnerabilities', 0)
            
            if critical > 0:
                self.stdout.write(f'  Critical: {self.style.ERROR(str(critical))}')
            if high > 0:
                self.stdout.write(f'  High: {self.style.WARNING(str(high))}')
        
        # Security monitoring
        monitoring = security_data.get('security_monitoring', {})
        if monitoring:
            self.stdout.write(f'Security Events: {monitoring.get("total_events", 0)}')
            high_severity = monitoring.get('high_severity_events', 0)
            if high_severity > 0:
                self.stdout.write(f'  High Severity: {self.style.WARNING(str(high_severity))}')
    
    def _display_audit_integrity_summary(self, integrity_data):
        """Display audit integrity summary."""
        if not integrity_data:
            return
        
        self.stdout.write(f'\n--- Audit Integrity ---')
        
        score = integrity_data.get('integrity_score', 0)
        status = integrity_data.get('status', 'unknown')
        
        status_style = self.style.SUCCESS if status == 'compliant' else self.style.ERROR
        self.stdout.write(f'Score: {score}% | Status: {status_style(status.upper())}')
        
        verification = integrity_data.get('verification_results', {})
        if verification:
            self.stdout.write(f'Verification Results:')
            self.stdout.write(f'  Total Logs Verified: {verification.get("total_logs_verified", 0)}')
            self.stdout.write(f'  Missing Checksums: {verification.get("missing_checksums", 0)}')
            self.stdout.write(f'  Checksum Mismatches: {len(verification.get("checksum_mismatches", []))}')
            self.stdout.write(f'  Chain Breaks: {len(verification.get("chain_breaks", []))}')
    
    def _display_action_items(self, action_items):
        """Display action items."""
        if not action_items:
            self.stdout.write(f'\n--- Action Items ---')
            self.stdout.write(self.style.SUCCESS('No action items - all compliance areas are healthy!'))
            return
        
        self.stdout.write(f'\n--- Action Items ({len(action_items)}) ---')
        
        for item in action_items:
            priority = item.get('priority', 'medium')
            title = item.get('title', 'Unknown')
            description = item.get('description', '')
            due_date = item.get('due_date', '')
            
            if priority == 'critical':
                priority_style = self.style.ERROR
            elif priority == 'high':
                priority_style = self.style.WARNING
            else:
                priority_style = self.style.SUCCESS
            
            self.stdout.write(f'{priority_style(f"[{priority.upper()}]")} {title}')
            if description:
                self.stdout.write(f'  {description}')
            if due_date:
                self.stdout.write(f'  Due: {due_date}')
            self.stdout.write('')
    
    def _display_alerts(self, alerts):
        """Display compliance alerts."""
        if not alerts:
            self.stdout.write(f'\n--- Compliance Alerts ---')
            self.stdout.write(self.style.SUCCESS('No active compliance alerts'))
            return
        
        self.stdout.write(f'\n--- Compliance Alerts ({len(alerts)}) ---')
        
        for alert in alerts:
            severity = alert.get('severity', 'medium')
            title = alert.get('title', 'Unknown Alert')
            message = alert.get('message', '')
            
            if severity == 'critical':
                severity_style = self.style.ERROR
            elif severity == 'high':
                severity_style = self.style.WARNING
            else:
                severity_style = self.style.SUCCESS
            
            self.stdout.write(f'{severity_style(f"[{severity.upper()}]")} {title}')
            if message:
                self.stdout.write(f'  {message}')
            self.stdout.write('')
    
    def _save_to_file(self, overview, filename):
        """Save dashboard data to JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(overview, f, indent=2, default=str)
            
            self.stdout.write(
                self.style.SUCCESS(f'Dashboard data saved to {filename}')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Failed to save dashboard data to file: {str(e)}')
            )