"""
Management command for zero-downtime database migrations.

This command provides safe migration execution with:
- Pre-migration safety checks
- Automatic backup creation
- Migration validation
- Rollback capabilities
- Detailed logging and monitoring
"""

import json
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from enterprise_auth.core.db.migrations import ZeroDowntimeMigrationRunner, get_migration_status


class Command(BaseCommand):
    help = 'Run database migrations with zero-downtime strategy'

    def add_arguments(self, parser):
        parser.add_argument(
            'app_label',
            nargs='?',
            help='App label of the application to migrate'
        )
        parser.add_argument(
            'migration_name',
            nargs='?',
            help='Database state will be brought to the state after that migration'
        )
        parser.add_argument(
            '--database',
            default='default',
            help='Nominates a database to migrate. Defaults to "default".'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what migrations would be applied without actually running them'
        )
        parser.add_argument(
            '--check-only',
            action='store_true',
            help='Only run pre-migration checks without executing migrations'
        )
        parser.add_argument(
            '--status',
            action='store_true',
            help='Show current migration status for all databases'
        )
        parser.add_argument(
            '--rollback',
            action='store_true',
            help='Rollback to the specified migration'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force migration even if safety checks fail (use with caution)'
        )
        parser.add_argument(
            '--json-output',
            action='store_true',
            help='Output results in JSON format'
        )

    def handle(self, *args, **options):
        database = options['database']
        app_label = options.get('app_label')
        migration_name = options.get('migration_name')
        dry_run = options['dry_run']
        check_only = options['check_only']
        show_status = options['status']
        rollback = options['rollback']
        force = options['force']
        json_output = options['json_output']

        # Validate database exists
        if database not in settings.DATABASES:
            raise CommandError(f'Database "{database}" not found in settings')

        runner = ZeroDowntimeMigrationRunner(database=database)

        try:
            if show_status:
                # Show migration status
                status = get_migration_status()
                if json_output:
                    self.stdout.write(json.dumps(status, indent=2))
                else:
                    self._display_status(status)
                return

            if check_only:
                # Only run pre-migration checks
                checks = runner.strategy.pre_migration_checks()
                if json_output:
                    self.stdout.write(json.dumps({'checks': checks}, indent=2))
                else:
                    self._display_checks(checks)
                return

            if rollback:
                # Perform rollback
                if not app_label or not migration_name:
                    raise CommandError('Both app_label and migration_name are required for rollback')
                
                result = runner.rollback_migration(app_label, migration_name)
                if json_output:
                    self.stdout.write(json.dumps(result, indent=2))
                else:
                    self._display_result(result, 'Rollback')
                return

            # Run migrations
            result = runner.run_migrations(
                app_label=app_label,
                migration_name=migration_name,
                dry_run=dry_run
            )

            # Check if migration should proceed based on safety checks
            if not force and result.get('pre_checks'):
                failed_checks = [check for check in result['pre_checks'] if not check[1]]
                critical_failures = [check for check in failed_checks 
                                   if check[0] in ['connectivity', 'long_transactions']]
                
                if critical_failures:
                    self.stdout.write(
                        self.style.ERROR('Critical safety checks failed. Use --force to override.')
                    )
                    if json_output:
                        self.stdout.write(json.dumps(result, indent=2))
                    else:
                        self._display_checks(result['pre_checks'])
                    return

            if json_output:
                self.stdout.write(json.dumps(result, indent=2))
            else:
                self._display_result(result, 'Migration')

        except Exception as e:
            if json_output:
                self.stdout.write(json.dumps({'error': str(e)}, indent=2))
            else:
                raise CommandError(f'Migration failed: {e}')

    def _display_status(self, status):
        """Display migration status in human-readable format."""
        self.stdout.write(self.style.SUCCESS('Migration Status Report'))
        self.stdout.write('=' * 50)
        
        for db_name, db_status in status.items():
            self.stdout.write(f'\nDatabase: {db_name}')
            
            if 'error' in db_status:
                self.stdout.write(self.style.ERROR(f'  Error: {db_status["error"]}'))
                continue
            
            if db_status['status'] == 'up_to_date':
                self.stdout.write(self.style.SUCCESS('  Status: Up to date'))
            else:
                self.stdout.write(self.style.WARNING(f'  Status: {db_status["pending_migrations"]} pending migrations'))
            
            self.stdout.write(f'  Applied migrations: {db_status["applied_migrations"]}')
            
            if db_status.get('migration_plan'):
                self.stdout.write('  Pending migrations:')
                for migration in db_status['migration_plan']:
                    self.stdout.write(f'    - {migration["app"]}.{migration["name"]}')

    def _display_checks(self, checks):
        """Display safety checks in human-readable format."""
        self.stdout.write(self.style.SUCCESS('Pre-migration Safety Checks'))
        self.stdout.write('=' * 40)
        
        for check_name, passed, message in checks:
            status_style = self.style.SUCCESS if passed else self.style.ERROR
            status_text = 'PASS' if passed else 'FAIL'
            self.stdout.write(f'{status_style(status_text)} {check_name}: {message}')

    def _display_result(self, result, operation_type):
        """Display migration result in human-readable format."""
        self.stdout.write(self.style.SUCCESS(f'{operation_type} Result'))
        self.stdout.write('=' * 30)
        
        # Basic info
        self.stdout.write(f'Database: {result["database"]}')
        self.stdout.write(f'Status: {result["status"]}')
        
        if result.get('app_label'):
            self.stdout.write(f'App: {result["app_label"]}')
        if result.get('migration_name'):
            self.stdout.write(f'Migration: {result["migration_name"]}')
        
        # Timing info
        if result.get('migration_time'):
            self.stdout.write(f'Migration time: {result["migration_time"]:.2f} seconds')
        
        # Pre-checks
        if result.get('pre_checks'):
            self.stdout.write('\nPre-migration checks:')
            for check_name, passed, message in result['pre_checks']:
                status_style = self.style.SUCCESS if passed else self.style.WARNING
                status_text = 'PASS' if passed else 'WARN'
                self.stdout.write(f'  {status_style(status_text)} {check_name}: {message}')
        
        # Backup info
        if result.get('backup'):
            backup = result['backup']
            if backup['status'] == 'completed':
                self.stdout.write(self.style.SUCCESS(f'\nBackup created: {backup.get("backup_file", "N/A")}'))
            else:
                self.stdout.write(self.style.WARNING(f'\nBackup failed: {backup.get("error", "Unknown error")}'))
        
        # Error info
        if result.get('error'):
            self.stdout.write(self.style.ERROR(f'\nError: {result["error"]}'))
        
        # Success message
        if result['status'] == 'completed':
            if result.get('dry_run'):
                self.stdout.write(self.style.SUCCESS(f'\n{operation_type} dry run completed successfully'))
            else:
                self.stdout.write(self.style.SUCCESS(f'\n{operation_type} completed successfully'))
        elif result['status'] == 'failed':
            self.stdout.write(self.style.ERROR(f'\n{operation_type} failed'))