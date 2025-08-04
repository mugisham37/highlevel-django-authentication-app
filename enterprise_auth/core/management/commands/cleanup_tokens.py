"""
Django management command for JWT token cleanup operations.

This command provides various token cleanup operations:
- Clean up expired blacklisted tokens
- Clean up old refresh tokens
- Generate cleanup reports
- Bulk token revocation for security incidents
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.db import transaction

from enterprise_auth.core.services.jwt_service import jwt_service
from enterprise_auth.core.models.jwt import TokenBlacklist, RefreshToken
from enterprise_auth.core.models.user import UserProfile

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for JWT token cleanup operations."""
    
    help = 'Perform JWT token cleanup operations'
    
    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            'operation',
            choices=[
                'cleanup-expired',
                'cleanup-old',
                'revoke-user',
                'revoke-device',
                'bulk-revoke',
                'report',
                'stats'
            ],
            help='Cleanup operation to perform'
        )
        
        # Arguments for cleanup-old operation
        parser.add_argument(
            '--days-old',
            type=int,
            default=60,
            help='Number of days after expiration to keep tokens (default: 60)'
        )
        
        # Arguments for user revocation
        parser.add_argument(
            '--user-email',
            type=str,
            help='Email of user to revoke tokens for'
        )
        
        parser.add_argument(
            '--user-id',
            type=str,
            help='ID of user to revoke tokens for'
        )
        
        # Arguments for device revocation
        parser.add_argument(
            '--device-id',
            type=str,
            help='Device ID to revoke tokens for'
        )
        
        # Arguments for bulk revocation
        parser.add_argument(
            '--token-ids',
            nargs='+',
            help='List of token IDs to revoke'
        )
        
        # Common arguments
        parser.add_argument(
            '--reason',
            type=str,
            default='manual_cleanup',
            help='Reason for the operation'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without actually doing it'
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
        
        # Arguments for report generation
        parser.add_argument(
            '--days-back',
            type=int,
            default=7,
            help='Number of days to include in report (default: 7)'
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        operation = options['operation']
        
        if options['verbose']:
            logging.basicConfig(level=logging.INFO)
        
        try:
            if operation == 'cleanup-expired':
                self.cleanup_expired_tokens(options)
            elif operation == 'cleanup-old':
                self.cleanup_old_tokens(options)
            elif operation == 'revoke-user':
                self.revoke_user_tokens(options)
            elif operation == 'revoke-device':
                self.revoke_device_tokens(options)
            elif operation == 'bulk-revoke':
                self.bulk_revoke_tokens(options)
            elif operation == 'report':
                self.generate_report(options)
            elif operation == 'stats':
                self.show_stats(options)
            else:
                raise CommandError(f"Unknown operation: {operation}")
                
        except Exception as e:
            raise CommandError(f"Operation failed: {str(e)}")
    
    def cleanup_expired_tokens(self, options: Dict[str, Any]) -> None:
        """Clean up expired blacklisted tokens."""
        self.stdout.write("Cleaning up expired blacklisted tokens...")
        
        if options['dry_run']:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
        
        # Clean up Redis blacklist
        if not options['dry_run']:
            redis_cleaned = jwt_service.cleanup_expired_blacklist_entries()
        else:
            redis_cleaned = 0  # Would need to implement dry-run logic
        
        # Clean up database blacklist entries
        expired_blacklist = TokenBlacklist.objects.filter(
            expires_at__lt=timezone.now()
        )
        db_count = expired_blacklist.count()
        
        if not options['dry_run']:
            db_cleaned = TokenBlacklist.cleanup_expired_entries()
        else:
            db_cleaned = db_count
        
        # Clean up expired refresh tokens
        expired_refresh = RefreshToken.objects.filter(
            expires_at__lt=timezone.now(),
            status='active'
        )
        refresh_count = expired_refresh.count()
        
        if not options['dry_run']:
            expired_refresh.update(status='expired')
            refresh_cleaned = refresh_count
        else:
            refresh_cleaned = refresh_count
        
        self.stdout.write(
            self.style.SUCCESS(
                f"Cleanup completed:\n"
                f"  Redis blacklist entries: {redis_cleaned}\n"
                f"  Database blacklist entries: {db_cleaned}\n"
                f"  Refresh tokens marked expired: {refresh_cleaned}\n"
                f"  Total cleaned: {redis_cleaned + db_cleaned + refresh_cleaned}"
            )
        )
    
    def cleanup_old_tokens(self, options: Dict[str, Any]) -> None:
        """Clean up old tokens that are no longer needed."""
        days_old = options['days_old']
        cutoff_date = timezone.now() - timedelta(days=days_old)
        
        self.stdout.write(f"Cleaning up tokens older than {days_old} days (before {cutoff_date})...")
        
        if options['dry_run']:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
        
        # Find old refresh tokens
        old_refresh_tokens = RefreshToken.objects.filter(
            expires_at__lt=cutoff_date,
            status__in=['expired', 'revoked', 'rotated']
        )
        refresh_count = old_refresh_tokens.count()
        
        # Find old blacklist entries
        old_blacklist = TokenBlacklist.objects.filter(
            expires_at__lt=cutoff_date
        )
        blacklist_count = old_blacklist.count()
        
        if not options['dry_run']:
            with transaction.atomic():
                old_refresh_tokens.delete()
                old_blacklist.delete()
        
        self.stdout.write(
            self.style.SUCCESS(
                f"Old token cleanup completed:\n"
                f"  Refresh tokens deleted: {refresh_count}\n"
                f"  Blacklist entries deleted: {blacklist_count}\n"
                f"  Total deleted: {refresh_count + blacklist_count}"
            )
        )
    
    def revoke_user_tokens(self, options: Dict[str, Any]) -> None:
        """Revoke all tokens for a specific user."""
        user_email = options.get('user_email')
        user_id = options.get('user_id')
        reason = options['reason']
        
        if not user_email and not user_id:
            raise CommandError("Either --user-email or --user-id must be provided")
        
        # Get user
        try:
            if user_email:
                user = UserProfile.objects.get(email=user_email)
            else:
                user = UserProfile.objects.get(id=user_id)
        except UserProfile.DoesNotExist:
            raise CommandError("User not found")
        
        self.stdout.write(f"Revoking all tokens for user: {user.email}")
        
        if options['dry_run']:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
            return
        
        success = jwt_service.revoke_all_user_tokens(str(user.id), reason)
        
        if success:
            self.stdout.write(
                self.style.SUCCESS(f"Successfully revoked all tokens for user {user.email}")
            )
        else:
            raise CommandError("Failed to revoke user tokens")
    
    def revoke_device_tokens(self, options: Dict[str, Any]) -> None:
        """Revoke all tokens for a specific device."""
        device_id = options.get('device_id')
        reason = options['reason']
        
        if not device_id:
            raise CommandError("--device-id must be provided")
        
        self.stdout.write(f"Revoking all tokens for device: {device_id}")
        
        if options['dry_run']:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
            return
        
        success = jwt_service.revoke_device_tokens(device_id, reason)
        
        if success:
            self.stdout.write(
                self.style.SUCCESS(f"Successfully revoked all tokens for device {device_id}")
            )
        else:
            raise CommandError("Failed to revoke device tokens")
    
    def bulk_revoke_tokens(self, options: Dict[str, Any]) -> None:
        """Revoke multiple tokens at once."""
        token_ids = options.get('token_ids')
        reason = options['reason']
        
        if not token_ids:
            raise CommandError("--token-ids must be provided")
        
        self.stdout.write(f"Bulk revoking {len(token_ids)} tokens...")
        
        if options['dry_run']:
            self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
            return
        
        revoked_count = jwt_service.bulk_revoke_tokens(token_ids, reason)
        
        self.stdout.write(
            self.style.SUCCESS(
                f"Bulk revocation completed: {revoked_count}/{len(token_ids)} tokens revoked"
            )
        )
    
    def generate_report(self, options: Dict[str, Any]) -> None:
        """Generate a token blacklist report."""
        days_back = options['days_back']
        start_date = timezone.now() - timedelta(days=days_back)
        
        self.stdout.write(f"Generating token blacklist report for last {days_back} days...")
        
        # Get blacklist statistics
        blacklist_entries = TokenBlacklist.objects.filter(
            blacklisted_at__gte=start_date
        )
        
        # Group by reason
        reason_stats = {}
        for entry in blacklist_entries:
            reason = entry.reason
            reason_stats[reason] = reason_stats.get(reason, 0) + 1
        
        # Group by token type
        type_stats = {}
        for entry in blacklist_entries:
            token_type = entry.token_type
            type_stats[token_type] = type_stats.get(token_type, 0) + 1
        
        # Get refresh token statistics
        refresh_tokens = RefreshToken.objects.filter(
            created_at__gte=start_date
        )
        
        refresh_stats = {
            'total_created': refresh_tokens.count(),
            'active': refresh_tokens.filter(status='active').count(),
            'rotated': refresh_tokens.filter(status='rotated').count(),
            'revoked': refresh_tokens.filter(status='revoked').count(),
            'expired': refresh_tokens.filter(status='expired').count(),
        }
        
        # Display report
        self.stdout.write(
            self.style.SUCCESS(
                f"\nToken Blacklist Report ({start_date.date()} to {timezone.now().date()}):\n"
                f"{'='*60}\n"
                f"Blacklist Statistics:\n"
                f"  Total blacklisted: {blacklist_entries.count()}\n"
                f"  By reason: {reason_stats}\n"
                f"  By type: {type_stats}\n\n"
                f"Refresh Token Statistics:\n"
                f"  Total created: {refresh_stats['total_created']}\n"
                f"  Active: {refresh_stats['active']}\n"
                f"  Rotated: {refresh_stats['rotated']}\n"
                f"  Revoked: {refresh_stats['revoked']}\n"
                f"  Expired: {refresh_stats['expired']}\n"
            )
        )
    
    def show_stats(self, options: Dict[str, Any]) -> None:
        """Show current token statistics."""
        self.stdout.write("Current Token Statistics:")
        self.stdout.write("=" * 40)
        
        # Refresh token stats
        total_refresh = RefreshToken.objects.count()
        active_refresh = RefreshToken.objects.filter(status='active').count()
        expired_refresh = RefreshToken.objects.filter(status='expired').count()
        revoked_refresh = RefreshToken.objects.filter(status='revoked').count()
        rotated_refresh = RefreshToken.objects.filter(status='rotated').count()
        
        # Blacklist stats
        total_blacklist = TokenBlacklist.objects.count()
        recent_blacklist = TokenBlacklist.objects.filter(
            blacklisted_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        self.stdout.write(
            f"Refresh Tokens:\n"
            f"  Total: {total_refresh}\n"
            f"  Active: {active_refresh}\n"
            f"  Expired: {expired_refresh}\n"
            f"  Revoked: {revoked_refresh}\n"
            f"  Rotated: {rotated_refresh}\n\n"
            f"Blacklist Entries:\n"
            f"  Total: {total_blacklist}\n"
            f"  Last 7 days: {recent_blacklist}\n"
        )