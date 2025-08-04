"""
Django management command to rotate JWT signing keys.

This command generates new RSA key pairs for JWT signing and marks
the old keys as rotated. It's useful for scheduled key rotation
and security incident response.
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from enterprise_auth.core.services.jwt_service import JWTKeyManager
from enterprise_auth.core.models.jwt import JWTKeyRotation


class Command(BaseCommand):
    """Management command to rotate JWT signing keys."""
    
    help = 'Rotate JWT signing keys for enhanced security'
    
    def add_arguments(self, parser):
        """Add command arguments."""
        parser.add_argument(
            '--reason',
            type=str,
            default='manual_rotation',
            help='Reason for key rotation (default: manual_rotation)'
        )
        
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force rotation even if current key is recent'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without actually rotating keys'
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        reason = options['reason']
        force = options['force']
        dry_run = options['dry_run']
        
        try:
            # Get current key information
            key_manager = JWTKeyManager()
            current_key_id = key_manager.get_current_key_id()
            
            # Check if we have a current key record in the database
            try:
                current_key_record = JWTKeyRotation.objects.get(key_id=current_key_id)
                key_age = timezone.now() - current_key_record.activated_at
                
                self.stdout.write(
                    f"Current key: {current_key_id[:8]}..."
                )
                self.stdout.write(
                    f"Key age: {key_age.days} days, {key_age.seconds // 3600} hours"
                )
                self.stdout.write(
                    f"Tokens signed: {current_key_record.tokens_signed}"
                )
                
                # Check if rotation is needed
                if not force and key_age.days < 30:
                    self.stdout.write(
                        self.style.WARNING(
                            f"Current key is only {key_age.days} days old. "
                            "Use --force to rotate anyway."
                        )
                    )
                    return
                
            except JWTKeyRotation.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(
                        f"No database record found for current key {current_key_id[:8]}..."
                    )
                )
                
                if not dry_run:
                    # Create a record for the current key
                    JWTKeyRotation.objects.create(
                        key_id=current_key_id,
                        algorithm='RS256',
                        key_size=2048,
                        activated_at=timezone.now(),
                        status='active'
                    )
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Created database record for current key"
                        )
                    )
            
            if dry_run:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"[DRY RUN] Would rotate key {current_key_id[:8]}... "
                        f"with reason: {reason}"
                    )
                )
                return
            
            # Perform the rotation
            self.stdout.write("Rotating JWT signing keys...")
            
            # Mark current key as rotated in database
            try:
                current_key_record = JWTKeyRotation.objects.get(key_id=current_key_id)
                current_key_record.rotate(reason=reason)
                self.stdout.write(
                    f"Marked key {current_key_id[:8]}... as rotated"
                )
            except JWTKeyRotation.DoesNotExist:
                pass
            
            # Generate new key
            new_key_id = key_manager.rotate_keys()
            
            # Create database record for new key
            new_key_record = JWTKeyRotation.objects.create(
                key_id=new_key_id,
                algorithm='RS256',
                key_size=2048,
                activated_at=timezone.now(),
                status='active',
                rotation_reason=reason
            )
            
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully rotated to new key: {new_key_id[:8]}..."
                )
            )
            
            # Show rotation summary
            self.stdout.write("\nRotation Summary:")
            self.stdout.write(f"  Old Key: {current_key_id[:8]}... (rotated)")
            self.stdout.write(f"  New Key: {new_key_id[:8]}... (active)")
            self.stdout.write(f"  Reason: {reason}")
            self.stdout.write(f"  Time: {timezone.now().isoformat()}")
            
            # Show key history
            self.stdout.write("\nRecent Key History:")
            recent_keys = JWTKeyRotation.objects.all().order_by('-activated_at')[:5]
            for key_record in recent_keys:
                status_style = self.style.SUCCESS if key_record.is_active else self.style.WARNING
                self.stdout.write(
                    f"  {key_record.key_id[:8]}... - {status_style(key_record.status)} "
                    f"(activated: {key_record.activated_at.strftime('%Y-%m-%d %H:%M')})"
                )
            
        except Exception as e:
            raise CommandError(f"Failed to rotate JWT keys: {str(e)}")