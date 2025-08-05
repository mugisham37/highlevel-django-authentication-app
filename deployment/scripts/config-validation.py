#!/usr/bin/env python3
"""
Configuration Validation Script for Enterprise Auth Backend
Validates environment configuration before deployment
"""

import os
import sys
import json
import re
import socket
import ssl
import urllib.request
import urllib.error
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ValidationResult:
    """Result of a configuration validation check"""
    name: str
    status: str  # 'pass', 'fail', 'warning'
    message: str
    details: Optional[Dict[str, Any]] = None


class ConfigValidator:
    """Configuration validator for Enterprise Auth Backend"""
    
    def __init__(self, environment: str = 'production'):
        self.environment = environment
        self.results: List[ValidationResult] = []
        self.required_vars = {
            'SECRET_KEY': 'Django secret key',
            'DATABASE_URL': 'Database connection URL',
            'REDIS_URL': 'Redis connection URL',
            'ALLOWED_HOSTS': 'Allowed hosts for Django',
        }
        self.optional_vars = {
            'SENTRY_DSN': 'Sentry error tracking DSN',
            'TWILIO_ACCOUNT_SID': 'Twilio account SID for SMS',
            'TWILIO_AUTH_TOKEN': 'Twilio auth token',
            'EMAIL_HOST': 'SMTP email host',
            'EMAIL_HOST_USER': 'SMTP email username',
            'EMAIL_HOST_PASSWORD': 'SMTP email password',
        }
    
    def validate_required_variables(self) -> None:
        """Validate that all required environment variables are set"""
        for var_name, description in self.required_vars.items():
            value = os.getenv(var_name)
            if not value:
                self.results.append(ValidationResult(
                    name=f"Required Variable: {var_name}",
                    status='fail',
                    message=f"Missing required environment variable: {var_name} ({description})"
                ))
            else:
                self.results.append(ValidationResult(
                    name=f"Required Variable: {var_name}",
                    status='pass',
                    message=f"Required variable {var_name} is set",
                    details={'length': len(value), 'masked_value': value[:4] + '*' * (len(value) - 4) if len(value) > 4 else '****'}
                ))
    
    def validate_secret_key(self) -> None:
        """Validate Django secret key strength"""
        secret_key = os.getenv('SECRET_KEY', '')
        
        if len(secret_key) < 50:
            self.results.append(ValidationResult(
                name="Secret Key Length",
                status='fail',
                message=f"SECRET_KEY is too short ({len(secret_key)} chars). Should be at least 50 characters."
            ))
        elif len(secret_key) < 64:
            self.results.append(ValidationResult(
                name="Secret Key Length",
                status='warning',
                message=f"SECRET_KEY length is acceptable but could be longer ({len(secret_key)} chars). Recommended: 64+ characters."
            ))
        else:
            self.results.append(ValidationResult(
                name="Secret Key Length",
                status='pass',
                message=f"SECRET_KEY length is good ({len(secret_key)} chars)"
            ))
        
        # Check for common weak patterns
        if secret_key.lower() in ['your-secret-key-here', 'change-me', 'secret', 'password']:
            self.results.append(ValidationResult(
                name="Secret Key Strength",
                status='fail',
                message="SECRET_KEY appears to be a default/weak value"
            ))
        else:
            self.results.append(ValidationResult(
                name="Secret Key Strength",
                status='pass',
                message="SECRET_KEY appears to be properly randomized"
            ))
    
    def validate_database_connection(self) -> None:
        """Validate database connection"""
        database_url = os.getenv('DATABASE_URL', '')
        
        if not database_url:
            self.results.append(ValidationResult(
                name="Database Connection",
                status='fail',
                message="DATABASE_URL not configured"
            ))
            return
        
        # Parse database URL
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(database_url)
            
            if parsed.scheme not in ['postgresql', 'postgres']:
                self.results.append(ValidationResult(
                    name="Database Type",
                    status='fail',
                    message=f"Unsupported database type: {parsed.scheme}. Only PostgreSQL is supported."
                ))
                return
            
            # Test connection (simplified - in real deployment, use proper connection testing)
            self.results.append(ValidationResult(
                name="Database Configuration",
                status='pass',
                message=f"Database URL format is valid (host: {parsed.hostname}, port: {parsed.port or 5432})"
            ))
            
        except Exception as e:
            self.results.append(ValidationResult(
                name="Database Connection",
                status='fail',
                message=f"Invalid DATABASE_URL format: {str(e)}"
            ))
    
    def validate_redis_connection(self) -> None:
        """Validate Redis connection"""
        redis_url = os.getenv('REDIS_URL', '')
        
        if not redis_url:
            self.results.append(ValidationResult(
                name="Redis Connection",
                status='fail',
                message="REDIS_URL not configured"
            ))
            return
        
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(redis_url)
            
            if parsed.scheme not in ['redis', 'rediss']:
                self.results.append(ValidationResult(
                    name="Redis Configuration",
                    status='fail',
                    message=f"Invalid Redis URL scheme: {parsed.scheme}"
                ))
                return
            
            self.results.append(ValidationResult(
                name="Redis Configuration",
                status='pass',
                message=f"Redis URL format is valid (host: {parsed.hostname}, port: {parsed.port or 6379})"
            ))
            
        except Exception as e:
            self.results.append(ValidationResult(
                name="Redis Connection",
                status='fail',
                message=f"Invalid REDIS_URL format: {str(e)}"
            ))
    
    def validate_allowed_hosts(self) -> None:
        """Validate Django ALLOWED_HOSTS configuration"""
        allowed_hosts = os.getenv('ALLOWED_HOSTS', '')
        
        if not allowed_hosts:
            self.results.append(ValidationResult(
                name="Allowed Hosts",
                status='fail',
                message="ALLOWED_HOSTS not configured"
            ))
            return
        
        hosts = [host.strip() for host in allowed_hosts.split(',')]
        
        if '*' in hosts and self.environment == 'production':
            self.results.append(ValidationResult(
                name="Allowed Hosts Security",
                status='fail',
                message="ALLOWED_HOSTS contains '*' in production environment - security risk"
            ))
        elif len(hosts) == 0:
            self.results.append(ValidationResult(
                name="Allowed Hosts",
                status='fail',
                message="ALLOWED_HOSTS is empty"
            ))
        else:
            self.results.append(ValidationResult(
                name="Allowed Hosts",
                status='pass',
                message=f"ALLOWED_HOSTS configured with {len(hosts)} host(s): {', '.join(hosts[:3])}{'...' if len(hosts) > 3 else ''}"
            ))
    
    def validate_oauth_configuration(self) -> None:
        """Validate OAuth provider configurations"""
        oauth_providers = {
            'Google': ['GOOGLE_OAUTH_CLIENT_ID', 'GOOGLE_OAUTH_CLIENT_SECRET'],
            'GitHub': ['GITHUB_OAUTH_CLIENT_ID', 'GITHUB_OAUTH_CLIENT_SECRET'],
            'Microsoft': ['MICROSOFT_OAUTH_CLIENT_ID', 'MICROSOFT_OAUTH_CLIENT_SECRET'],
        }
        
        for provider, vars_needed in oauth_providers.items():
            configured_vars = [var for var in vars_needed if os.getenv(var)]
            
            if len(configured_vars) == 0:
                self.results.append(ValidationResult(
                    name=f"OAuth {provider}",
                    status='warning',
                    message=f"{provider} OAuth not configured (optional)"
                ))
            elif len(configured_vars) != len(vars_needed):
                self.results.append(ValidationResult(
                    name=f"OAuth {provider}",
                    status='fail',
                    message=f"{provider} OAuth partially configured. Missing: {set(vars_needed) - set(configured_vars)}"
                ))
            else:
                self.results.append(ValidationResult(
                    name=f"OAuth {provider}",
                    status='pass',
                    message=f"{provider} OAuth fully configured"
                ))
    
    def validate_external_services(self) -> None:
        """Validate external service configurations"""
        # Twilio SMS configuration
        twilio_vars = ['TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER']
        twilio_configured = [var for var in twilio_vars if os.getenv(var)]
        
        if len(twilio_configured) == 0:
            self.results.append(ValidationResult(
                name="Twilio SMS",
                status='warning',
                message="Twilio SMS not configured (MFA SMS will not work)"
            ))
        elif len(twilio_configured) != len(twilio_vars):
            self.results.append(ValidationResult(
                name="Twilio SMS",
                status='fail',
                message=f"Twilio SMS partially configured. Missing: {set(twilio_vars) - set(twilio_configured)}"
            ))
        else:
            self.results.append(ValidationResult(
                name="Twilio SMS",
                status='pass',
                message="Twilio SMS fully configured"
            ))
        
        # Email configuration
        email_vars = ['EMAIL_HOST', 'EMAIL_HOST_USER', 'EMAIL_HOST_PASSWORD']
        email_configured = [var for var in email_vars if os.getenv(var)]
        
        if len(email_configured) == 0:
            self.results.append(ValidationResult(
                name="Email Service",
                status='warning',
                message="Email service not configured (email notifications will not work)"
            ))
        elif len(email_configured) != len(email_vars):
            self.results.append(ValidationResult(
                name="Email Service",
                status='fail',
                message=f"Email service partially configured. Missing: {set(email_vars) - set(email_configured)}"
            ))
        else:
            self.results.append(ValidationResult(
                name="Email Service",
                status='pass',
                message="Email service fully configured"
            ))
    
    def validate_security_configuration(self) -> None:
        """Validate security-related configurations"""
        # JWT keys
        jwt_private_key = os.getenv('JWT_PRIVATE_KEY', '')
        jwt_public_key = os.getenv('JWT_PUBLIC_KEY', '')
        
        if not jwt_private_key or not jwt_public_key:
            self.results.append(ValidationResult(
                name="JWT Keys",
                status='fail',
                message="JWT private/public keys not configured"
            ))
        else:
            # Basic validation of key format
            if '-----BEGIN' in jwt_private_key and '-----END' in jwt_private_key:
                self.results.append(ValidationResult(
                    name="JWT Private Key",
                    status='pass',
                    message="JWT private key format appears valid"
                ))
            else:
                self.results.append(ValidationResult(
                    name="JWT Private Key",
                    status='fail',
                    message="JWT private key format appears invalid"
                ))
            
            if '-----BEGIN' in jwt_public_key and '-----END' in jwt_public_key:
                self.results.append(ValidationResult(
                    name="JWT Public Key",
                    status='pass',
                    message="JWT public key format appears valid"
                ))
            else:
                self.results.append(ValidationResult(
                    name="JWT Public Key",
                    status='fail',
                    message="JWT public key format appears invalid"
                ))
        
        # Field encryption key
        field_encryption_key = os.getenv('FIELD_ENCRYPTION_KEY', '')
        if not field_encryption_key:
            self.results.append(ValidationResult(
                name="Field Encryption",
                status='fail',
                message="FIELD_ENCRYPTION_KEY not configured"
            ))
        elif len(field_encryption_key) < 32:
            self.results.append(ValidationResult(
                name="Field Encryption",
                status='fail',
                message=f"FIELD_ENCRYPTION_KEY too short ({len(field_encryption_key)} chars). Should be at least 32 characters."
            ))
        else:
            self.results.append(ValidationResult(
                name="Field Encryption",
                status='pass',
                message="Field encryption key properly configured"
            ))
    
    def validate_monitoring_configuration(self) -> None:
        """Validate monitoring and logging configurations"""
        sentry_dsn = os.getenv('SENTRY_DSN', '')
        
        if not sentry_dsn:
            self.results.append(ValidationResult(
                name="Sentry Monitoring",
                status='warning',
                message="Sentry DSN not configured (error tracking disabled)"
            ))
        else:
            if sentry_dsn.startswith('https://') and '@sentry.io' in sentry_dsn:
                self.results.append(ValidationResult(
                    name="Sentry Monitoring",
                    status='pass',
                    message="Sentry DSN format appears valid"
                ))
            else:
                self.results.append(ValidationResult(
                    name="Sentry Monitoring",
                    status='warning',
                    message="Sentry DSN format may be invalid"
                ))
    
    def validate_environment_specific(self) -> None:
        """Validate environment-specific configurations"""
        debug = os.getenv('DEBUG', 'False').lower()
        
        if self.environment == 'production' and debug == 'true':
            self.results.append(ValidationResult(
                name="Debug Mode",
                status='fail',
                message="DEBUG=True in production environment - security risk"
            ))
        else:
            self.results.append(ValidationResult(
                name="Debug Mode",
                status='pass',
                message=f"DEBUG mode appropriately configured for {self.environment}"
            ))
        
        # Check SSL/TLS configuration for production
        if self.environment == 'production':
            secure_ssl_redirect = os.getenv('SECURE_SSL_REDIRECT', 'False').lower()
            if secure_ssl_redirect != 'true':
                self.results.append(ValidationResult(
                    name="SSL Redirect",
                    status='warning',
                    message="SECURE_SSL_REDIRECT not enabled in production"
                ))
            else:
                self.results.append(ValidationResult(
                    name="SSL Redirect",
                    status='pass',
                    message="SSL redirect properly configured"
                ))
    
    def run_all_validations(self) -> None:
        """Run all validation checks"""
        print(f"Running configuration validation for {self.environment} environment...")
        print("=" * 60)
        
        self.validate_required_variables()
        self.validate_secret_key()
        self.validate_database_connection()
        self.validate_redis_connection()
        self.validate_allowed_hosts()
        self.validate_oauth_configuration()
        self.validate_external_services()
        self.validate_security_configuration()
        self.validate_monitoring_configuration()
        self.validate_environment_specific()
    
    def print_results(self) -> bool:
        """Print validation results and return success status"""
        passed = 0
        failed = 0
        warnings = 0
        
        for result in self.results:
            status_symbol = {
                'pass': '✓',
                'fail': '✗',
                'warning': '⚠'
            }.get(result.status, '?')
            
            status_color = {
                'pass': '\033[92m',  # Green
                'fail': '\033[91m',  # Red
                'warning': '\033[93m'  # Yellow
            }.get(result.status, '')
            
            print(f"{status_color}{status_symbol} {result.name}: {result.message}\033[0m")
            
            if result.details:
                for key, value in result.details.items():
                    print(f"    {key}: {value}")
            
            if result.status == 'pass':
                passed += 1
            elif result.status == 'fail':
                failed += 1
            else:
                warnings += 1
        
        print("\n" + "=" * 60)
        print(f"Validation Summary:")
        print(f"  ✓ Passed: {passed}")
        print(f"  ⚠ Warnings: {warnings}")
        print(f"  ✗ Failed: {failed}")
        print(f"  Total: {len(self.results)}")
        
        if failed > 0:
            print(f"\n❌ Configuration validation FAILED with {failed} error(s)")
            return False
        elif warnings > 0:
            print(f"\n⚠️  Configuration validation PASSED with {warnings} warning(s)")
            return True
        else:
            print(f"\n✅ Configuration validation PASSED")
            return True
    
    def export_results(self, output_file: str) -> None:
        """Export validation results to JSON file"""
        results_data = {
            'environment': self.environment,
            'timestamp': str(datetime.now()),
            'summary': {
                'total': len(self.results),
                'passed': len([r for r in self.results if r.status == 'pass']),
                'failed': len([r for r in self.results if r.status == 'fail']),
                'warnings': len([r for r in self.results if r.status == 'warning'])
            },
            'results': [
                {
                    'name': r.name,
                    'status': r.status,
                    'message': r.message,
                    'details': r.details
                }
                for r in self.results
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(results_data, f, indent=2)
        
        print(f"Results exported to: {output_file}")


def main():
    """Main function"""
    import argparse
    from datetime import datetime
    
    parser = argparse.ArgumentParser(description='Validate Enterprise Auth Backend configuration')
    parser.add_argument('--environment', '-e', default='production',
                       choices=['development', 'staging', 'production'],
                       help='Target environment')
    parser.add_argument('--env-file', '-f', help='Load environment variables from file')
    parser.add_argument('--export', '-o', help='Export results to JSON file')
    parser.add_argument('--fail-on-warnings', action='store_true',
                       help='Treat warnings as failures')
    
    args = parser.parse_args()
    
    # Load environment file if specified
    if args.env_file:
        if not os.path.exists(args.env_file):
            print(f"Error: Environment file not found: {args.env_file}")
            sys.exit(1)
        
        with open(args.env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value
    
    # Run validation
    validator = ConfigValidator(args.environment)
    validator.run_all_validations()
    success = validator.print_results()
    
    # Export results if requested
    if args.export:
        validator.export_results(args.export)
    
    # Check for warnings if fail-on-warnings is set
    if args.fail_on_warnings:
        warnings = len([r for r in validator.results if r.status == 'warning'])
        if warnings > 0:
            success = False
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()