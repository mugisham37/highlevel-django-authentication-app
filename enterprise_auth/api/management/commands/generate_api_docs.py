"""
Management command to generate API documentation.
"""
import json
import os
from django.core.management.base import BaseCommand
from django.conf import settings

from enterprise_auth.api.docs import APIDocumentationGenerator
from enterprise_auth.api.openapi import generate_openapi_spec


class Command(BaseCommand):
    help = 'Generate API documentation files'

    def add_arguments(self, parser):
        parser.add_argument(
            '--output-dir',
            type=str,
            default='docs/api',
            help='Output directory for documentation files'
        )
        parser.add_argument(
            '--format',
            choices=['json', 'yaml'],
            default='json',
            help='Output format for OpenAPI spec'
        )

    def handle(self, *args, **options):
        output_dir = options['output_dir']
        output_format = options['format']

        # Create output directory
        os.makedirs(output_dir, exist_ok=True)

        self.stdout.write('Generating API documentation...')

        # Generate OpenAPI specification
        openapi_spec = generate_openapi_spec()
        
        if output_format == 'json':
            spec_filename = os.path.join(output_dir, 'openapi.json')
            with open(spec_filename, 'w') as f:
                json.dump(openapi_spec, f, indent=2)
        else:
            import yaml
            spec_filename = os.path.join(output_dir, 'openapi.yaml')
            with open(spec_filename, 'w') as f:
                yaml.dump(openapi_spec, f, default_flow_style=False)

        self.stdout.write(
            self.style.SUCCESS(f'OpenAPI specification saved to {spec_filename}')
        )

        # Generate comprehensive documentation
        doc_generator = APIDocumentationGenerator()
        full_docs = doc_generator.generate_full_documentation()

        # Save individual documentation sections
        sections = [
            'getting_started',
            'authentication',
            'api_keys',
            'webhooks',
            'rate_limiting',
            'error_handling',
            'sdk_examples',
            'integration_examples',
            'changelog'
        ]

        for section in sections:
            if section in full_docs:
                section_filename = os.path.join(output_dir, f'{section}.json')
                with open(section_filename, 'w') as f:
                    json.dump(full_docs[section], f, indent=2)
                
                self.stdout.write(f'Generated {section} documentation')

        # Save complete documentation
        complete_filename = os.path.join(output_dir, 'complete_docs.json')
        with open(complete_filename, 'w') as f:
            json.dump(full_docs, f, indent=2)

        self.stdout.write(
            self.style.SUCCESS(f'Complete documentation saved to {complete_filename}')
        )

        # Generate README
        readme_content = self.generate_readme(output_dir)
        readme_filename = os.path.join(output_dir, 'README.md')
        with open(readme_filename, 'w') as f:
            f.write(readme_content)

        self.stdout.write(
            self.style.SUCCESS(f'README generated at {readme_filename}')
        )

        self.stdout.write(
            self.style.SUCCESS('API documentation generation completed!')
        )

    def generate_readme(self, output_dir):
        """Generate README for the documentation."""
        return """# EnterpriseAuth API Documentation

This directory contains comprehensive documentation for the EnterpriseAuth API.

## Files

- `openapi.json` / `openapi.yaml` - OpenAPI 3.0 specification
- `getting_started.json` - Quick start guide
- `authentication.json` - Authentication methods and examples
- `api_keys.json` - API key management guide
- `webhooks.json` - Webhook system documentation
- `rate_limiting.json` - Rate limiting information
- `error_handling.json` - Error handling guide
- `sdk_examples.json` - SDK usage examples
- `integration_examples.json` - Framework integration examples
- `changelog.json` - API version history
- `complete_docs.json` - All documentation in one file

## Usage

### OpenAPI Specification

The OpenAPI specification can be used with tools like:
- Swagger UI for interactive documentation
- Postman for API testing
- Code generators for client libraries

### Documentation Sections

Each JSON file contains structured documentation that can be:
- Rendered in web applications
- Used to generate static documentation sites
- Integrated into developer portals
- Consumed by documentation tools

## Integration

To integrate this documentation into your application:

```python
import json

# Load specific documentation section
with open('getting_started.json') as f:
    getting_started = json.load(f)

# Use in your application
render_documentation(getting_started)
```

## Updates

Regenerate documentation after API changes:

```bash
python manage.py generate_api_docs --output-dir docs/api --format json
```
"""