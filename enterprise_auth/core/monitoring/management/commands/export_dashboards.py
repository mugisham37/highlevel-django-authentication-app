"""
Management command to export Grafana dashboard configurations.
"""

import os
import json
from django.core.management.base import BaseCommand
from django.conf import settings
from enterprise_auth.core.monitoring.dashboards import grafana_dashboard_generator


class Command(BaseCommand):
    help = 'Export Grafana dashboard configurations to JSON files'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--output-dir',
            type=str,
            default='dashboards',
            help='Output directory for dashboard JSON files',
        )
        parser.add_argument(
            '--dashboard',
            type=str,
            help='Export specific dashboard by name',
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Export all dashboards',
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        output_dir = options['output_dir']
        dashboard_name = options['dashboard']
        export_all = options['all']
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            self.stdout.write(f'Created output directory: {output_dir}')
        
        try:
            if dashboard_name:
                # Export specific dashboard
                self.export_dashboard(dashboard_name, output_dir)
            elif export_all:
                # Export all dashboards
                self.export_all_dashboards(output_dir)
            else:
                # Show available dashboards
                self.show_available_dashboards()
            
            self.stdout.write(
                self.style.SUCCESS('Dashboard export completed successfully')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Dashboard export failed: {str(e)}')
            )
            raise
    
    def export_dashboard(self, dashboard_name, output_dir):
        """Export a specific dashboard."""
        config = grafana_dashboard_generator.get_dashboard_config(dashboard_name)
        
        if not config:
            self.stdout.write(
                self.style.ERROR(f'Dashboard "{dashboard_name}" not found')
            )
            return
        
        filename = f'{dashboard_name}.json'
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=2)
        
        self.stdout.write(
            self.style.SUCCESS(f'Exported dashboard "{dashboard_name}" to {filepath}')
        )
    
    def export_all_dashboards(self, output_dir):
        """Export all available dashboards."""
        all_dashboards = grafana_dashboard_generator.get_all_dashboards()
        
        for dashboard_name in all_dashboards.keys():
            self.export_dashboard(dashboard_name, output_dir)
        
        # Create index file
        index_data = {
            'dashboards': list(all_dashboards.keys()),
            'exported_at': str(timezone.now()),
            'total_count': len(all_dashboards)
        }
        
        index_filepath = os.path.join(output_dir, 'index.json')
        with open(index_filepath, 'w') as f:
            json.dump(index_data, f, indent=2)
        
        self.stdout.write(
            self.style.SUCCESS(f'Exported {len(all_dashboards)} dashboards to {output_dir}')
        )
    
    def show_available_dashboards(self):
        """Show available dashboards."""
        all_dashboards = grafana_dashboard_generator.get_all_dashboards()
        
        self.stdout.write('Available dashboards:')
        for dashboard_name in all_dashboards.keys():
            self.stdout.write(f'  - {dashboard_name}')
        
        self.stdout.write(f'\nTotal: {len(all_dashboards)} dashboards')
        self.stdout.write('\nUse --dashboard <name> to export a specific dashboard')
        self.stdout.write('Use --all to export all dashboards')