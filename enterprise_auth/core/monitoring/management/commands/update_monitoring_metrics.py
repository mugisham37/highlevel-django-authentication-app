"""
Management command to update monitoring metrics and perform maintenance tasks.
"""

import logging
from django.core.management.base import BaseCommand
from django.utils import timezone
from enterprise_auth.core.monitoring.metrics import (
    business_metrics_collector,
    compliance_metrics_collector,
    security_metrics_collector
)
from enterprise_auth.core.monitoring.health_checks import system_health_monitor
from enterprise_auth.core.monitoring.alerting import alert_manager
from enterprise_auth.core.monitoring.logging_config import get_structured_logger

logger = get_structured_logger(__name__)


class Command(BaseCommand):
    help = 'Update monitoring metrics and perform maintenance tasks'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--daily',
            action='store_true',
            help='Update daily metrics',
        )
        parser.add_argument(
            '--monthly',
            action='store_true',
            help='Update monthly metrics',
        )
        parser.add_argument(
            '--cleanup',
            action='store_true',
            help='Perform cleanup tasks',
        )
        parser.add_argument(
            '--health-check',
            action='store_true',
            help='Run health checks',
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        self.stdout.write(
            self.style.SUCCESS(f'Starting monitoring metrics update at {timezone.now()}')
        )
        
        try:
            if options['daily']:
                self.update_daily_metrics()
            
            if options['monthly']:
                self.update_monthly_metrics()
            
            if options['cleanup']:
                self.perform_cleanup()
            
            if options['health_check']:
                self.run_health_checks()
            
            # If no specific options, run all tasks
            if not any([options['daily'], options['monthly'], options['cleanup'], options['health_check']]):
                self.update_daily_metrics()
                self.run_health_checks()
            
            self.stdout.write(
                self.style.SUCCESS('Monitoring metrics update completed successfully')
            )
            
        except Exception as e:
            logger.error("Monitoring metrics update failed", error=str(e))
            self.stdout.write(
                self.style.ERROR(f'Monitoring metrics update failed: {str(e)}')
            )
            raise
    
    def update_daily_metrics(self):
        """Update daily business metrics."""
        self.stdout.write('Updating daily metrics...')
        
        try:
            # Update daily business metrics
            business_metrics_collector.update_daily_metrics()
            
            self.stdout.write(
                self.style.SUCCESS('Daily metrics updated successfully')
            )
            
        except Exception as e:
            logger.error("Failed to update daily metrics", error=str(e))
            self.stdout.write(
                self.style.ERROR(f'Failed to update daily metrics: {str(e)}')
            )
            raise
    
    def update_monthly_metrics(self):
        """Update monthly business metrics."""
        self.stdout.write('Updating monthly metrics...')
        
        try:
            # Update monthly business metrics
            business_metrics_collector.update_monthly_metrics()
            
            self.stdout.write(
                self.style.SUCCESS('Monthly metrics updated successfully')
            )
            
        except Exception as e:
            logger.error("Failed to update monthly metrics", error=str(e))
            self.stdout.write(
                self.style.ERROR(f'Failed to update monthly metrics: {str(e)}')
            )
            raise
    
    def perform_cleanup(self):
        """Perform cleanup tasks."""
        self.stdout.write('Performing cleanup tasks...')
        
        try:
            # Clean up old alerts
            alert_manager.cleanup_old_alerts(days=30)
            
            self.stdout.write(
                self.style.SUCCESS('Cleanup tasks completed successfully')
            )
            
        except Exception as e:
            logger.error("Failed to perform cleanup tasks", error=str(e))
            self.stdout.write(
                self.style.ERROR(f'Failed to perform cleanup tasks: {str(e)}')
            )
            raise
    
    def run_health_checks(self):
        """Run system health checks."""
        self.stdout.write('Running health checks...')
        
        try:
            # Run health monitoring
            health_summary = system_health_monitor.monitor_health()
            
            # Display health summary
            self.stdout.write(f"Overall health status: {health_summary['overall_status']}")
            self.stdout.write(f"Health score: {health_summary['health_score']}%")
            self.stdout.write(f"Total checks: {health_summary['total_checks']}")
            self.stdout.write(f"Healthy checks: {health_summary['healthy_checks']}")
            self.stdout.write(f"Degraded checks: {health_summary['degraded_checks']}")
            self.stdout.write(f"Unhealthy checks: {health_summary['unhealthy_checks']}")
            
            # Show unhealthy checks
            if health_summary['unhealthy_checks'] > 0:
                self.stdout.write(self.style.WARNING('Unhealthy checks detected:'))
                for check_name, check_result in health_summary['checks'].items():
                    if check_result['status'] in ['unhealthy', 'degraded']:
                        self.stdout.write(
                            f"  - {check_name}: {check_result['status']} - {check_result['message']}"
                        )
            
            self.stdout.write(
                self.style.SUCCESS('Health checks completed successfully')
            )
            
        except Exception as e:
            logger.error("Failed to run health checks", error=str(e))
            self.stdout.write(
                self.style.ERROR(f'Failed to run health checks: {str(e)}')
            )
            raise