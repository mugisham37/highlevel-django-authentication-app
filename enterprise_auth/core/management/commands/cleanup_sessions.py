"""
Management command to cleanup expired sessions and related data.

This command provides comprehensive session cleanup functionality including:
- Marking expired sessions as expired
- Deleting old terminated/expired sessions
- Cleaning up old session activities
- Removing orphaned device info records
"""

import logging
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta

from enterprise_auth.core.services.session_service import (
    cleanup_expired_sessions,
    cleanup_old_sessions,
    cleanup_old_session_activities,
    cleanup_orphaned_device_info,
    get_session_statistics,
)


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Cleanup expired sessions and related data'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--expired-only',
            action='store_true',
            help='Only mark expired sessions as expired (default behavior)',
        )
        
        parser.add_argument(
            '--delete-old',
            action='store_true',
            help='Delete old terminated/expired sessions',
        )
        
        parser.add_argument(
            '--session-days',
            type=int,
            default=90,
            help='Number of days to keep old sessions (default: 90)',
        )
        
        parser.add_argument(
            '--activity-days',
            type=int,
            default=90,
            help='Number of days to keep session activities (default: 90)',
        )
        
        parser.add_argument(
            '--cleanup-activities',
            action='store_true',
            help='Cleanup old session activities',
        )
        
        parser.add_argument(
            '--cleanup-devices',
            action='store_true',
            help='Cleanup orphaned device info records',
        )
        
        parser.add_argument(
            '--all',
            action='store_true',
            help='Perform all cleanup operations',
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be cleaned up without actually doing it',
        )
        
        parser.add_argument(
            '--stats',
            action='store_true',
            help='Show session statistics before and after cleanup',
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output',
        )
    
    def handle(self, *args, **options):
        """Execute the session cleanup command."""
        
        if options['verbose']:
            logging.basicConfig(level=logging.INFO)
        
        # Show initial statistics if requested
        if options['stats']:
            self.stdout.write(self.style.SUCCESS('=== Initial Session Statistics ==='))
            self._show_statistics()
            self.stdout.write('')
        
        total_cleaned = 0
        
        # Always cleanup expired sessions (mark as expired)
        if not options['dry_run']:
            expired_count = cleanup_expired_sessions()
            total_cleaned += expired_count
            
            if expired_count > 0:
                self.stdout.write(
                    self.style.SUCCESS(f'Marked {expired_count} expired sessions as expired')
                )
            elif options['verbose']:
                self.stdout.write('No expired sessions found to mark')
        else:
            self.stdout.write(self.style.WARNING('[DRY RUN] Would mark expired sessions as expired'))
        
        # Delete old sessions if requested
        if options['delete_old'] or options['all']:
            if not options['dry_run']:
                old_sessions_count = cleanup_old_sessions(options['session_days'])
                total_cleaned += old_sessions_count
                
                if old_sessions_count > 0:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'Deleted {old_sessions_count} old sessions older than {options["session_days"]} days'
                        )
                    )
                elif options['verbose']:
                    self.stdout.write(f'No old sessions found older than {options["session_days"]} days')
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f'[DRY RUN] Would delete old sessions older than {options["session_days"]} days'
                    )
                )
        
        # Cleanup old session activities if requested
        if options['cleanup_activities'] or options['all']:
            if not options['dry_run']:
                activities_count = cleanup_old_session_activities(options['activity_days'])
                total_cleaned += activities_count
                
                if activities_count > 0:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'Deleted {activities_count} old session activities older than {options["activity_days"]} days'
                        )
                    )
                elif options['verbose']:
                    self.stdout.write(f'No old session activities found older than {options["activity_days"]} days')
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f'[DRY RUN] Would delete old session activities older than {options["activity_days"]} days'
                    )
                )
        
        # Cleanup orphaned device info if requested
        if options['cleanup_devices'] or options['all']:
            if not options['dry_run']:
                devices_count = cleanup_orphaned_device_info()
                total_cleaned += devices_count
                
                if devices_count > 0:
                    self.stdout.write(
                        self.style.SUCCESS(f'Deleted {devices_count} orphaned device info records')
                    )
                elif options['verbose']:
                    self.stdout.write('No orphaned device info records found')
            else:
                self.stdout.write(
                    self.style.WARNING('[DRY RUN] Would delete orphaned device info records')
                )
        
        # Show final statistics if requested
        if options['stats']:
            self.stdout.write('')
            self.stdout.write(self.style.SUCCESS('=== Final Session Statistics ==='))
            self._show_statistics()
        
        # Summary
        if not options['dry_run']:
            if total_cleaned > 0:
                self.stdout.write('')
                self.stdout.write(
                    self.style.SUCCESS(f'Session cleanup completed. Total items cleaned: {total_cleaned}')
                )
            else:
                self.stdout.write('')
                self.stdout.write(self.style.SUCCESS('Session cleanup completed. No items needed cleaning.'))
        else:
            self.stdout.write('')
            self.stdout.write(self.style.WARNING('DRY RUN completed. No actual cleanup performed.'))
    
    def _show_statistics(self):
        """Show current session statistics."""
        try:
            stats = get_session_statistics()
            
            self.stdout.write(f"Total sessions: {stats['total_sessions']}")
            self.stdout.write(f"Active sessions: {stats['active_sessions']}")
            self.stdout.write(f"Expired sessions: {stats['expired_sessions']}")
            self.stdout.write(f"Terminated sessions: {stats['terminated_sessions']}")
            self.stdout.write(f"Suspicious sessions: {stats['suspicious_sessions']}")
            self.stdout.write(f"Sessions in last 24h: {stats['sessions_last_24h']}")
            
            if stats.get('avg_risk_score') is not None:
                self.stdout.write(f"Average risk score: {stats['avg_risk_score']:.2f}")
                self.stdout.write(f"High risk sessions: {stats['high_risk_sessions']}")
                self.stdout.write(f"Medium risk sessions: {stats['medium_risk_sessions']}")
                self.stdout.write(f"Low risk sessions: {stats['low_risk_sessions']}")
            
            # Show top device types
            if stats.get('device_types'):
                self.stdout.write("Top device types:")
                for device_type in stats['device_types'][:5]:
                    self.stdout.write(f"  {device_type['device_info__device_type']}: {device_type['count']}")
            
            # Show top countries
            if stats.get('top_countries'):
                self.stdout.write("Top countries:")
                for country in stats['top_countries'][:5]:
                    self.stdout.write(f"  {country['country']}: {country['count']}")
                    
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error retrieving session statistics: {e}')
            )