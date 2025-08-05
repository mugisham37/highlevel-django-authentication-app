"""
Security compliance monitoring service for OWASP guidelines and vulnerability management.
"""

import json
import logging
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError

from ..models.compliance import SecurityVulnerability, ComplianceReport, ComplianceAuditLog
from .compliance_service import SOC2AuditService

User = get_user_model()
logger = logging.getLogger(__name__)


class SecurityComplianceService:
    """
    Service for security compliance monitoring, vulnerability management, and OWASP guidelines.
    """
    
    OWASP_TOP_10_2021 = {
        'A01:2021': {
            'name': 'Broken Access Control',
            'description': 'Restrictions on what authenticated users are allowed to do are often not properly enforced.',
            'risk_level': 'high'
        },
        'A02:2021': {
            'name': 'Cryptographic Failures',
            'description': 'Failures related to cryptography which often leads to sensitive data exposure.',
            'risk_level': 'high'
        },
        'A03:2021': {
            'name': 'Injection',
            'description': 'Application is vulnerable to injection attacks.',
            'risk_level': 'high'
        },
        'A04:2021': {
            'name': 'Insecure Design',
            'description': 'Risks related to design flaws and missing or ineffective control design.',
            'risk_level': 'medium'
        },
        'A05:2021': {
            'name': 'Security Misconfiguration',
            'description': 'Security misconfiguration is commonly a result of insecure default configurations.',
            'risk_level': 'medium'
        },
        'A06:2021': {
            'name': 'Vulnerable and Outdated Components',
            'description': 'Components with known vulnerabilities that may undermine application defenses.',
            'risk_level': 'high'
        },
        'A07:2021': {
            'name': 'Identification and Authentication Failures',
            'description': 'Confirmation of the user\'s identity, authentication, and session management.',
            'risk_level': 'high'
        },
        'A08:2021': {
            'name': 'Software and Data Integrity Failures',
            'description': 'Code and infrastructure that does not protect against integrity violations.',
            'risk_level': 'medium'
        },
        'A09:2021': {
            'name': 'Security Logging and Monitoring Failures',
            'description': 'Insufficient logging and monitoring, coupled with missing or ineffective integration.',
            'risk_level': 'medium'
        },
        'A10:2021': {
            'name': 'Server-Side Request Forgery',
            'description': 'SSRF flaws occur whenever a web application is fetching a remote resource.',
            'risk_level': 'medium'
        }
    }
    
    def __init__(self):
        self.audit_service = SOC2AuditService()
    
    def create_vulnerability(self, vulnerability_data: Dict[str, Any], discovered_by: str = 'system') -> SecurityVulnerability:
        """
        Create a new security vulnerability record.
        """
        try:
            with transaction.atomic():
                vulnerability = SecurityVulnerability.objects.create(
                    vulnerability_id=vulnerability_data['vulnerability_id'],
                    title=vulnerability_data['title'],
                    description=vulnerability_data['description'],
                    severity=vulnerability_data['severity'],
                    cve_id=vulnerability_data.get('cve_id', ''),
                    owasp_category=vulnerability_data.get('owasp_category', ''),
                    affected_components=vulnerability_data.get('affected_components', []),
                    discovery_method=vulnerability_data['discovery_method'],
                    discovered_by=discovered_by,
                    remediation_plan=vulnerability_data.get('remediation_plan', ''),
                    remediation_deadline=vulnerability_data.get('remediation_deadline')
                )
                
                # Log vulnerability creation
                self.audit_service.create_audit_log(
                    activity_type='security_event',
                    action='vulnerability_created',
                    resource='security_vulnerability',
                    outcome='success',
                    severity=vulnerability_data['severity'],
                    details={
                        'vulnerability_id': vulnerability_data['vulnerability_id'],
                        'title': vulnerability_data['title'],
                        'severity': vulnerability_data['severity'],
                        'owasp_category': vulnerability_data.get('owasp_category', ''),
                        'discovery_method': vulnerability_data['discovery_method'],
                        'discovered_by': discovered_by
                    }
                )
                
                logger.info(f"Created vulnerability: {vulnerability.vulnerability_id}")
                return vulnerability
                
        except Exception as e:
            logger.error(f"Failed to create vulnerability: {str(e)}")
            raise
    
    def update_vulnerability_status(self, vulnerability_id: str, status: str, 
                                  resolved_by: User = None, resolution_notes: str = '') -> SecurityVulnerability:
        """
        Update vulnerability status and resolution information.
        """
        try:
            with transaction.atomic():
                vulnerability = SecurityVulnerability.objects.get(vulnerability_id=vulnerability_id)
                old_status = vulnerability.status
                
                vulnerability.status = status
                
                if status == 'resolved':
                    vulnerability.resolved_at = timezone.now()
                    vulnerability.resolved_by = resolved_by
                    vulnerability.resolution_notes = resolution_notes
                
                vulnerability.save()
                
                # Log status update
                self.audit_service.create_audit_log(
                    activity_type='security_event',
                    user=resolved_by,
                    action='vulnerability_status_updated',
                    resource='security_vulnerability',
                    outcome='success',
                    details={
                        'vulnerability_id': vulnerability_id,
                        'old_status': old_status,
                        'new_status': status,
                        'resolution_notes': resolution_notes,
                        'resolution_time': (vulnerability.resolved_at - vulnerability.discovered_at).total_seconds() if vulnerability.resolved_at else None
                    }
                )
                
                logger.info(f"Updated vulnerability {vulnerability_id} status: {old_status} -> {status}")
                return vulnerability
                
        except SecurityVulnerability.DoesNotExist:
            logger.error(f"Vulnerability not found: {vulnerability_id}")
            raise ValidationError(f"Vulnerability not found: {vulnerability_id}")
        except Exception as e:
            logger.error(f"Failed to update vulnerability status: {str(e)}")
            raise
    
    def run_security_scan(self, scan_type: str = 'comprehensive') -> Dict[str, Any]:
        """
        Run automated security scanning and vulnerability assessment.
        """
        try:
            scan_results = {
                'scan_id': f"scan_{timezone.now().strftime('%Y%m%d_%H%M%S')}",
                'scan_type': scan_type,
                'started_at': timezone.now().isoformat(),
                'vulnerabilities_found': [],
                'owasp_compliance': {},
                'recommendations': [],
                'scan_summary': {}
            }
            
            # Run different types of scans based on scan_type
            if scan_type in ['comprehensive', 'dependency']:
                dependency_results = self._scan_dependencies()
                scan_results['vulnerabilities_found'].extend(dependency_results['vulnerabilities'])
                scan_results['recommendations'].extend(dependency_results['recommendations'])
            
            if scan_type in ['comprehensive', 'static']:
                static_results = self._run_static_analysis()
                scan_results['vulnerabilities_found'].extend(static_results['vulnerabilities'])
                scan_results['recommendations'].extend(static_results['recommendations'])
            
            if scan_type in ['comprehensive', 'configuration']:
                config_results = self._scan_security_configuration()
                scan_results['vulnerabilities_found'].extend(config_results['vulnerabilities'])
                scan_results['recommendations'].extend(config_results['recommendations'])
            
            # Generate OWASP compliance report
            scan_results['owasp_compliance'] = self.get_owasp_compliance_status()
            
            # Create vulnerability records for new findings
            for vuln_data in scan_results['vulnerabilities_found']:
                try:
                    self.create_vulnerability(vuln_data, discovered_by='automated_scan')
                except Exception as e:
                    logger.warning(f"Failed to create vulnerability record: {str(e)}")
            
            # Generate scan summary
            scan_results['scan_summary'] = {
                'total_vulnerabilities': len(scan_results['vulnerabilities_found']),
                'critical_vulnerabilities': len([v for v in scan_results['vulnerabilities_found'] if v['severity'] == 'critical']),
                'high_vulnerabilities': len([v for v in scan_results['vulnerabilities_found'] if v['severity'] == 'high']),
                'medium_vulnerabilities': len([v for v in scan_results['vulnerabilities_found'] if v['severity'] == 'medium']),
                'low_vulnerabilities': len([v for v in scan_results['vulnerabilities_found'] if v['severity'] == 'low']),
                'completed_at': timezone.now().isoformat()
            }
            
            # Log scan completion
            self.audit_service.create_audit_log(
                activity_type='security_event',
                action='security_scan_completed',
                resource='security_scan',
                outcome='success',
                details=scan_results['scan_summary']
            )
            
            logger.info(f"Security scan completed: {scan_results['scan_id']}")
            return scan_results
            
        except Exception as e:
            logger.error(f"Failed to run security scan: {str(e)}")
            raise
    
    def _scan_dependencies(self) -> Dict[str, Any]:
        """
        Scan for vulnerable dependencies using safety.
        """
        results = {
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Run safety check for Python dependencies
            result = subprocess.run(
                ['safety', 'check', '--json'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                # No vulnerabilities found
                results['recommendations'].append({
                    'type': 'dependency_scan',
                    'message': 'All dependencies are up to date and secure',
                    'priority': 'info'
                })
            else:
                # Parse safety output
                try:
                    safety_data = json.loads(result.stdout)
                    for vuln in safety_data:
                        vulnerability = {
                            'vulnerability_id': f"DEP_{vuln.get('id', 'unknown')}",
                            'title': f"Vulnerable dependency: {vuln.get('package_name', 'unknown')}",
                            'description': vuln.get('advisory', 'No description available'),
                            'severity': self._map_safety_severity(vuln.get('severity', 'medium')),
                            'cve_id': vuln.get('cve', ''),
                            'owasp_category': 'A06:2021',  # Vulnerable and Outdated Components
                            'affected_components': [vuln.get('package_name', 'unknown')],
                            'discovery_method': 'dependency_scan',
                            'remediation_plan': f"Update {vuln.get('package_name')} to version {vuln.get('safe_versions', ['latest'])[0] if vuln.get('safe_versions') else 'latest'}"
                        }
                        results['vulnerabilities'].append(vulnerability)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse safety output")
                
        except subprocess.TimeoutExpired:
            logger.warning("Dependency scan timed out")
            results['recommendations'].append({
                'type': 'dependency_scan',
                'message': 'Dependency scan timed out - consider running manually',
                'priority': 'warning'
            })
        except FileNotFoundError:
            logger.warning("Safety tool not found - install with: pip install safety")
            results['recommendations'].append({
                'type': 'dependency_scan',
                'message': 'Install safety tool for dependency vulnerability scanning',
                'priority': 'warning'
            })
        except Exception as e:
            logger.error(f"Dependency scan failed: {str(e)}")
        
        return results
    
    def _run_static_analysis(self) -> Dict[str, Any]:
        """
        Run static code analysis using bandit.
        """
        results = {
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Run bandit for Python security analysis
            result = subprocess.run(
                ['bandit', '-r', '.', '-f', 'json', '-ll'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            try:
                bandit_data = json.loads(result.stdout)
                
                for issue in bandit_data.get('results', []):
                    vulnerability = {
                        'vulnerability_id': f"STATIC_{issue.get('test_id', 'unknown')}_{hash(issue.get('filename', '') + str(issue.get('line_number', 0)))}",
                        'title': f"Static analysis issue: {issue.get('test_name', 'Unknown')}",
                        'description': issue.get('issue_text', 'No description available'),
                        'severity': self._map_bandit_severity(issue.get('issue_severity', 'MEDIUM')),
                        'owasp_category': self._map_bandit_to_owasp(issue.get('test_id', '')),
                        'affected_components': [issue.get('filename', 'unknown')],
                        'discovery_method': 'static_analysis',
                        'remediation_plan': f"Review code at {issue.get('filename', 'unknown')}:{issue.get('line_number', 0)}"
                    }
                    results['vulnerabilities'].append(vulnerability)
                
                # Add summary recommendation
                total_issues = len(bandit_data.get('results', []))
                if total_issues == 0:
                    results['recommendations'].append({
                        'type': 'static_analysis',
                        'message': 'No static analysis issues found',
                        'priority': 'info'
                    })
                else:
                    results['recommendations'].append({
                        'type': 'static_analysis',
                        'message': f'Found {total_issues} static analysis issues that need review',
                        'priority': 'medium'
                    })
                    
            except json.JSONDecodeError:
                logger.warning("Failed to parse bandit output")
                
        except subprocess.TimeoutExpired:
            logger.warning("Static analysis timed out")
        except FileNotFoundError:
            logger.warning("Bandit tool not found - install with: pip install bandit")
            results['recommendations'].append({
                'type': 'static_analysis',
                'message': 'Install bandit tool for static security analysis',
                'priority': 'warning'
            })
        except Exception as e:
            logger.error(f"Static analysis failed: {str(e)}")
        
        return results
    
    def _scan_security_configuration(self) -> Dict[str, Any]:
        """
        Scan security configuration settings.
        """
        results = {
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Check Django security settings
            security_checks = [
                self._check_debug_setting(),
                self._check_secret_key(),
                self._check_allowed_hosts(),
                self._check_https_settings(),
                self._check_csrf_settings(),
                self._check_session_settings(),
                self._check_password_validators()
            ]
            
            for check_result in security_checks:
                if check_result['status'] == 'fail':
                    vulnerability = {
                        'vulnerability_id': f"CONFIG_{check_result['check_id']}",
                        'title': f"Security configuration issue: {check_result['title']}",
                        'description': check_result['description'],
                        'severity': check_result['severity'],
                        'owasp_category': check_result.get('owasp_category', 'A05:2021'),
                        'affected_components': ['django_settings'],
                        'discovery_method': 'configuration_scan',
                        'remediation_plan': check_result['remediation']
                    }
                    results['vulnerabilities'].append(vulnerability)
                elif check_result['status'] == 'warning':
                    results['recommendations'].append({
                        'type': 'configuration',
                        'message': check_result['description'],
                        'priority': 'medium'
                    })
            
        except Exception as e:
            logger.error(f"Configuration scan failed: {str(e)}")
        
        return results
    
    def _check_debug_setting(self) -> Dict[str, Any]:
        """
        Check if DEBUG is disabled in production.
        """
        debug_enabled = getattr(settings, 'DEBUG', True)
        
        if debug_enabled:
            return {
                'check_id': 'DEBUG_ENABLED',
                'title': 'Debug mode enabled',
                'description': 'DEBUG setting is enabled which can expose sensitive information',
                'severity': 'high',
                'status': 'fail',
                'owasp_category': 'A05:2021',
                'remediation': 'Set DEBUG = False in production settings'
            }
        else:
            return {
                'check_id': 'DEBUG_ENABLED',
                'title': 'Debug mode disabled',
                'status': 'pass'
            }
    
    def _check_secret_key(self) -> Dict[str, Any]:
        """
        Check SECRET_KEY configuration.
        """
        secret_key = getattr(settings, 'SECRET_KEY', '')
        
        if not secret_key:
            return {
                'check_id': 'SECRET_KEY_MISSING',
                'title': 'Secret key missing',
                'description': 'SECRET_KEY is not configured',
                'severity': 'critical',
                'status': 'fail',
                'owasp_category': 'A02:2021',
                'remediation': 'Configure a strong SECRET_KEY'
            }
        elif len(secret_key) < 50:
            return {
                'check_id': 'SECRET_KEY_WEAK',
                'title': 'Weak secret key',
                'description': 'SECRET_KEY is too short',
                'severity': 'medium',
                'status': 'warning',
                'owasp_category': 'A02:2021',
                'remediation': 'Use a longer, more complex SECRET_KEY'
            }
        else:
            return {
                'check_id': 'SECRET_KEY_STRONG',
                'title': 'Secret key configured',
                'status': 'pass'
            }
    
    def _check_allowed_hosts(self) -> Dict[str, Any]:
        """
        Check ALLOWED_HOSTS configuration.
        """
        allowed_hosts = getattr(settings, 'ALLOWED_HOSTS', [])
        
        if not allowed_hosts or '*' in allowed_hosts:
            return {
                'check_id': 'ALLOWED_HOSTS_INSECURE',
                'title': 'Insecure ALLOWED_HOSTS',
                'description': 'ALLOWED_HOSTS is not properly configured',
                'severity': 'medium',
                'status': 'fail',
                'owasp_category': 'A05:2021',
                'remediation': 'Configure specific hostnames in ALLOWED_HOSTS'
            }
        else:
            return {
                'check_id': 'ALLOWED_HOSTS_SECURE',
                'title': 'ALLOWED_HOSTS configured',
                'status': 'pass'
            }
    
    def _check_https_settings(self) -> Dict[str, Any]:
        """
        Check HTTPS security settings.
        """
        secure_ssl_redirect = getattr(settings, 'SECURE_SSL_REDIRECT', False)
        secure_hsts_seconds = getattr(settings, 'SECURE_HSTS_SECONDS', 0)
        
        if not secure_ssl_redirect or secure_hsts_seconds < 31536000:  # 1 year
            return {
                'check_id': 'HTTPS_SETTINGS_WEAK',
                'title': 'Weak HTTPS settings',
                'description': 'HTTPS security settings are not properly configured',
                'severity': 'medium',
                'status': 'warning',
                'owasp_category': 'A02:2021',
                'remediation': 'Enable SECURE_SSL_REDIRECT and set SECURE_HSTS_SECONDS to at least 31536000'
            }
        else:
            return {
                'check_id': 'HTTPS_SETTINGS_SECURE',
                'title': 'HTTPS settings configured',
                'status': 'pass'
            }
    
    def _check_csrf_settings(self) -> Dict[str, Any]:
        """
        Check CSRF protection settings.
        """
        csrf_cookie_secure = getattr(settings, 'CSRF_COOKIE_SECURE', False)
        csrf_cookie_httponly = getattr(settings, 'CSRF_COOKIE_HTTPONLY', False)
        
        if not csrf_cookie_secure or not csrf_cookie_httponly:
            return {
                'check_id': 'CSRF_SETTINGS_WEAK',
                'title': 'Weak CSRF settings',
                'description': 'CSRF cookie settings are not secure',
                'severity': 'medium',
                'status': 'warning',
                'owasp_category': 'A01:2021',
                'remediation': 'Set CSRF_COOKIE_SECURE and CSRF_COOKIE_HTTPONLY to True'
            }
        else:
            return {
                'check_id': 'CSRF_SETTINGS_SECURE',
                'title': 'CSRF settings configured',
                'status': 'pass'
            }
    
    def _check_session_settings(self) -> Dict[str, Any]:
        """
        Check session security settings.
        """
        session_cookie_secure = getattr(settings, 'SESSION_COOKIE_SECURE', False)
        session_cookie_httponly = getattr(settings, 'SESSION_COOKIE_HTTPONLY', True)
        session_cookie_age = getattr(settings, 'SESSION_COOKIE_AGE', 1209600)  # 2 weeks
        
        if not session_cookie_secure or not session_cookie_httponly or session_cookie_age > 86400:  # 1 day
            return {
                'check_id': 'SESSION_SETTINGS_WEAK',
                'title': 'Weak session settings',
                'description': 'Session cookie settings are not secure',
                'severity': 'medium',
                'status': 'warning',
                'owasp_category': 'A07:2021',
                'remediation': 'Configure secure session cookie settings'
            }
        else:
            return {
                'check_id': 'SESSION_SETTINGS_SECURE',
                'title': 'Session settings configured',
                'status': 'pass'
            }
    
    def _check_password_validators(self) -> Dict[str, Any]:
        """
        Check password validation settings.
        """
        password_validators = getattr(settings, 'AUTH_PASSWORD_VALIDATORS', [])
        
        if len(password_validators) < 3:
            return {
                'check_id': 'PASSWORD_VALIDATORS_WEAK',
                'title': 'Weak password validation',
                'description': 'Insufficient password validators configured',
                'severity': 'medium',
                'status': 'warning',
                'owasp_category': 'A07:2021',
                'remediation': 'Configure comprehensive password validators'
            }
        else:
            return {
                'check_id': 'PASSWORD_VALIDATORS_STRONG',
                'title': 'Password validators configured',
                'status': 'pass'
            }
    
    def _map_safety_severity(self, safety_severity: str) -> str:
        """
        Map safety severity to our severity levels.
        """
        mapping = {
            'high': 'high',
            'medium': 'medium',
            'low': 'low'
        }
        return mapping.get(safety_severity.lower(), 'medium')
    
    def _map_bandit_severity(self, bandit_severity: str) -> str:
        """
        Map bandit severity to our severity levels.
        """
        mapping = {
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        return mapping.get(bandit_severity.upper(), 'medium')
    
    def _map_bandit_to_owasp(self, test_id: str) -> str:
        """
        Map bandit test IDs to OWASP categories.
        """
        mapping = {
            'B101': 'A03:2021',  # assert_used - Injection
            'B102': 'A03:2021',  # exec_used - Injection
            'B103': 'A05:2021',  # set_bad_file_permissions - Security Misconfiguration
            'B104': 'A01:2021',  # hardcoded_bind_all_interfaces - Broken Access Control
            'B105': 'A02:2021',  # hardcoded_password_string - Cryptographic Failures
            'B106': 'A02:2021',  # hardcoded_password_funcarg - Cryptographic Failures
            'B107': 'A02:2021',  # hardcoded_password_default - Cryptographic Failures
            'B108': 'A05:2021',  # hardcoded_tmp_directory - Security Misconfiguration
            'B110': 'A03:2021',  # try_except_pass - Injection
            'B112': 'A03:2021',  # try_except_continue - Injection
        }
        return mapping.get(test_id, 'A05:2021')  # Default to Security Misconfiguration
    
    def get_owasp_compliance_status(self) -> Dict[str, Any]:
        """
        Get OWASP Top 10 compliance status.
        """
        try:
            compliance_status = {}
            
            for owasp_id, owasp_info in self.OWASP_TOP_10_2021.items():
                # Get vulnerability counts for this OWASP category
                open_vulns = SecurityVulnerability.objects.filter(
                    owasp_category=owasp_id,
                    status='open'
                ).count()
                
                total_vulns = SecurityVulnerability.objects.filter(
                    owasp_category=owasp_id
                ).count()
                
                resolved_vulns = total_vulns - open_vulns
                compliance_score = (resolved_vulns / max(total_vulns, 1)) * 100
                
                compliance_status[owasp_id] = {
                    'name': owasp_info['name'],
                    'description': owasp_info['description'],
                    'risk_level': owasp_info['risk_level'],
                    'open_vulnerabilities': open_vulns,
                    'total_vulnerabilities': total_vulns,
                    'resolved_vulnerabilities': resolved_vulns,
                    'compliance_score': round(compliance_score, 2),
                    'status': 'compliant' if open_vulns == 0 else 'non_compliant'
                }
            
            # Calculate overall compliance score
            total_score = sum(cat['compliance_score'] for cat in compliance_status.values())
            overall_score = total_score / len(self.OWASP_TOP_10_2021)
            
            return {
                'overall_compliance_score': round(overall_score, 2),
                'overall_status': 'compliant' if overall_score >= 95 else 'non_compliant',
                'categories': compliance_status,
                'last_updated': timezone.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get OWASP compliance status: {str(e)}")
            raise
    
    def generate_security_report(self, report_period_days: int = 30) -> Dict[str, Any]:
        """
        Generate comprehensive security compliance report.
        """
        try:
            end_date = timezone.now()
            start_date = end_date - timedelta(days=report_period_days)
            
            report = {
                'report_id': f"security_report_{end_date.strftime('%Y%m%d_%H%M%S')}",
                'period': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'days': report_period_days
                },
                'vulnerability_summary': self._get_vulnerability_summary(start_date, end_date),
                'owasp_compliance': self.get_owasp_compliance_status(),
                'security_events': self._get_security_events_summary(start_date, end_date),
                'recommendations': self._generate_security_recommendations(),
                'generated_at': timezone.now().isoformat()
            }
            
            # Log report generation
            self.audit_service.create_audit_log(
                activity_type='compliance_action',
                action='security_report_generated',
                resource='security_report',
                outcome='success',
                details={
                    'report_id': report['report_id'],
                    'period_days': report_period_days,
                    'vulnerability_count': report['vulnerability_summary']['total_vulnerabilities']
                }
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate security report: {str(e)}")
            raise
    
    def _get_vulnerability_summary(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Get vulnerability summary for the specified period.
        """
        vulnerabilities = SecurityVulnerability.objects.filter(
            discovered_at__range=[start_date, end_date]
        )
        
        return {
            'total_vulnerabilities': vulnerabilities.count(),
            'critical_vulnerabilities': vulnerabilities.filter(severity='critical').count(),
            'high_vulnerabilities': vulnerabilities.filter(severity='high').count(),
            'medium_vulnerabilities': vulnerabilities.filter(severity='medium').count(),
            'low_vulnerabilities': vulnerabilities.filter(severity='low').count(),
            'resolved_vulnerabilities': vulnerabilities.filter(status='resolved').count(),
            'open_vulnerabilities': vulnerabilities.filter(status='open').count()
        }
    
    def _get_security_events_summary(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """
        Get security events summary for the specified period.
        """
        security_events = ComplianceAuditLog.objects.filter(
            activity_type='security_event',
            timestamp__range=[start_date, end_date]
        )
        
        return {
            'total_events': security_events.count(),
            'critical_events': security_events.filter(severity='critical').count(),
            'high_events': security_events.filter(severity='high').count(),
            'medium_events': security_events.filter(severity='medium').count(),
            'low_events': security_events.filter(severity='low').count()
        }
    
    def _generate_security_recommendations(self) -> List[Dict[str, Any]]:
        """
        Generate security recommendations based on current state.
        """
        recommendations = []
        
        # Check for open critical vulnerabilities
        critical_vulns = SecurityVulnerability.objects.filter(
            severity='critical',
            status='open'
        ).count()
        
        if critical_vulns > 0:
            recommendations.append({
                'priority': 'critical',
                'category': 'vulnerability_management',
                'title': 'Address Critical Vulnerabilities',
                'description': f'{critical_vulns} critical vulnerabilities require immediate attention',
                'action': 'Review and remediate all critical vulnerabilities'
            })
        
        # Check for overdue vulnerabilities
        overdue_vulns = SecurityVulnerability.objects.filter(
            status='open',
            remediation_deadline__lt=timezone.now()
        ).count()
        
        if overdue_vulns > 0:
            recommendations.append({
                'priority': 'high',
                'category': 'vulnerability_management',
                'title': 'Address Overdue Vulnerabilities',
                'description': f'{overdue_vulns} vulnerabilities are past their remediation deadline',
                'action': 'Update remediation plans and resolve overdue vulnerabilities'
            })
        
        # Check OWASP compliance
        owasp_status = self.get_owasp_compliance_status()
        if owasp_status['overall_compliance_score'] < 95:
            recommendations.append({
                'priority': 'medium',
                'category': 'owasp_compliance',
                'title': 'Improve OWASP Compliance',
                'description': f'Overall OWASP compliance score is {owasp_status["overall_compliance_score"]}%',
                'action': 'Focus on categories with low compliance scores'
            })
        
        return recommendations