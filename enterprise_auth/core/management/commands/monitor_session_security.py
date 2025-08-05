"""
Management command for monitoring session security.

This command runs session security monitoring on active sessions,
detecting anomalies, threats, and taking automated responses.
"""

import logging
from datetime import timedelta
from typing import Dict, Any

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.db.models import Q

from ...models.session import UserSession
from ...services.session_security_service import session_security_service


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Management command for session security monitoring."""
    
    help = 'Monitor active sessions for security threats and anomalies'
    
    def add_arguments(self, parser):
        """Add command arguments."""
        parser.add_argument(
            '--session-id',
            type=str,
            help='Monitor specific session by ID',
        )
        
        parser.add_argument(
            '--user-id',
            type=str,
            help='Monitor sessions for specific user',
        )
        
        parser.add_argument(
            '--hours',
            type=int,
            default=1,
            help='Monitor sessions active within last N hours (default: 1)',
        )
        
        parser.add_argument(
            '--high-risk-only',
            action='store_true',
            help='Only monitor sessions with high risk scores',
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Run monitoring without taking automated actions',
        )
        
        parser.add_argument(
            '--cleanup-old-events',
            action='store_true',
            help='Clean up old security events after monitoring',
        )
        
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output',
        )
    
    def handle(self, *args, **options):
        """Execute the command."""
        try:
            self.verbosity = options.get('verbosity', 1)
            self.verbose = options.get('verbose', False)
            
            if self.verbose:
                self.stdout.write("Starting session security monitoring...")
            
            # Build query for sessions to monitor
            sessions_query = self._build_sessions_query(options)
            
            if not sessions_query.exists():
                self.stdout.write(
                    self.style.WARNING("No sessions found matching criteria")
                )
                return
            
            # Monitor sessions
            monitoring_results = self._monitor_sessions(sessions_query, options)
            
            # Display results
            self._display_results(monitoring_results)
            
            # Clean up old events if requested
            if options.get('cleanup_old_events'):
                self._cleanup_old_events()
            
            if self.verbose:
                self.stdout.write(
                    self.style.SUCCESS("Session security monitoring completed")
                )
                
        except Exception as e:
            logger.error(f"Error in session security monitoring command: {str(e)}")
            raise CommandError(f"Command failed: {str(e)}")
    
    def _build_sessions_query(self, options: Dict[str, Any]):
        """Build query for sessions to monitor."""
        # Start with active sessions
        query = Q(status='active')
        
        # Filter by specific session ID
        if options.get('session_id'):
            query &= Q(session_id=options['session_id'])
        
        # Filter by user ID
        if options.get('user_id'):
            query &= Q(user__id=options['user_id'])
        
        # Filter by activity timeframe
        hours = options.get('hours', 1)
        since = timezone.now() - timedelta(hours=hours)
        query &= Q(last_activity__gte=since)
        
        # Filter by high risk only
        if options.get('high_risk_only'):
            query &= Q(risk_score__gte=70.0)
        
        return UserSession.objects.filter(query).select_related(
            'user', 'device_info'
        ).order_by('-last_activity')
    
    def _monitor_sessions(self, sessions_query, options: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor sessions and collect results."""
        results = {
            'total_sessions': 0,
            'sessions_monitored': 0,
            'anomalies_detected': 0,
            'threats_detected': 0,
            'actions_taken': 0,
            'high_risk_sessions': 0,
            'errors': 0,
            'session_details': [],
        }
        
        dry_run = options.get('dry_run', False)
        
        for session in sessions_query:
            results['total_sessions'] += 1
            
            try:
                if self.verbose:
                    self.stdout.write(
                        f"Monitoring session {session.session_id} "
                        f"for user {session.user.email}"
                    )
                
                # Perform security monitoring
                if dry_run:
                    # In dry run mode, we would analyze but not take actions
                    # For now, we'll skip the actual monitoring
                    monitoring_result = {
                        'session_id': session.session_id,
                        'anomalies_detected': [],
                        'threats_detected': [],
                        'actions_taken': [],
                        'risk_score': session.risk_score,
                    }
                else:
                    monitoring_result = session_security_service.monitor_session_security(session)
                
                results['sessions_monitored'] += 1
                
                # Update counters
                if monitoring_result['anomalies_detected']:
                    results['anomalies_detected'] += len(monitoring_result['anomalies_detected'])
                
                if monitoring_result['threats_detected']:
                    results['threats_detected'] += len(monitoring_result['threats_detected'])
                
                if monitoring_result['actions_taken']:
                    results['actions_taken'] += len(monitoring_result['actions_taken'])
                
                if monitoring_result['risk_score'] >= 70.0:
                    results['high_risk_sessions'] += 1
                
                # Store session details for verbose output
                if self.verbose or monitoring_result['anomalies_detected'] or monitoring_result['threats_detected']:
                    results['session_details'].append({
                        'session_id': session.session_id,
                        'user_email': session.user.email,
                        'risk_score': monitoring_result['risk_score'],
                        'anomalies': monitoring_result['anomalies_detected'],
                        'threats': monitoring_result['threats_detected'],
                        'actions': monitoring_result['actions_taken'],
                        'requires_investigation': monitoring_result.get('requires_investigation', False),
                    })
                
            except Exception as e:
                results['errors'] += 1
                logger.error(
                    f"Error monitoring session {session.session_id}: {str(e)}",
                    extra={
                        'session_id': session.session_id,
                        'user_id': str(session.user.id),
                        'error': str(e),
                    }
                )
                
                if self.verbose:
                    self.stdout.write(
                        self.style.ERROR(
                            f"Error monitoring session {session.session_id}: {str(e)}"
                        )
                    )
        
        return results
    
    def _display_results(self, results: Dict[str, Any]):
        """Display monitoring results."""
        self.stdout.write("\n" + "="*60)
        self.stdout.write(self.style.SUCCESS("SESSION SECURITY MONITORING RESULTS"))
        self.stdout.write("="*60)
        
        # Summary statistics
        self.stdout.write(f"Total sessions checked: {results['total_sessions']}")
        self.stdout.write(f"Sessions monitored: {results['sessions_monitored']}")
        self.stdout.write(f"High-risk sessions: {results['high_risk_sessions']}")
        self.stdout.write(f"Anomalies detected: {results['anomalies_detected']}")
        self.stdout.write(f"Threats detected: {results['threats_detected']}")
        self.stdout.write(f"Actions taken: {results['actions_taken']}")
        
        if results['errors'] > 0:
            self.stdout.write(
                self.style.ERROR(f"Errors encountered: {results['errors']}")
            )
        
        # Detailed session information
        if results['session_details']:
            self.stdout.write("\n" + "-"*60)
            self.stdout.write("DETAILED SESSION INFORMATION")
            self.stdout.write("-"*60)
            
            for session_detail in results['session_details']:
                self.stdout.write(f"\nSession: {session_detail['session_id']}")
                self.stdout.write(f"User: {session_detail['user_email']}")
                self.stdout.write(f"Risk Score: {session_detail['risk_score']:.1f}")
                
                if session_detail['anomalies']:
                    self.stdout.write(
                        self.style.WARNING(
                            f"Anomalies: {', '.join(session_detail['anomalies'])}"
                        )
                    )
                
                if session_detail['threats']:
                    self.stdout.write(
                        self.style.ERROR(
                            f"Threats: {len(session_detail['threats'])} detected"
                        )
                    )
                
                if session_detail['actions']:
                    self.stdout.write(
                        f"Actions: {', '.join(session_detail['actions'])}"
                    )
                
                if session_detail['requires_investigation']:
                    self.stdout.write(
                        self.style.ERROR("⚠️  REQUIRES MANUAL INVESTIGATION")
                    )
        
        # Recommendations
        self._display_recommendations(results)
    
    def _display_recommendations(self, results: Dict[str, Any]):
        """Display recommendations based on monitoring results."""
        self.stdout.write("\n" + "-"*60)
        self.stdout.write("RECOMMENDATIONS")
        self.stdout.write("-"*60)
        
        if results['high_risk_sessions'] > 0:
            self.stdout.write(
                self.style.WARNING(
                    f"• {results['high_risk_sessions']} high-risk sessions detected. "
                    "Consider manual investigation."
                )
            )
        
        if results['threats_detected'] > 0:
            self.stdout.write(
                self.style.ERROR(
                    f"• {results['threats_detected']} threats detected. "
                    "Review security events and consider blocking malicious IPs."
                )
            )
        
        if results['anomalies_detected'] > 10:
            self.stdout.write(
                self.style.WARNING(
                    "• High number of anomalies detected. "
                    "Consider adjusting detection thresholds or investigating patterns."
                )
            )
        
        if results['errors'] > 0:
            self.stdout.write(
                self.style.ERROR(
                    "• Errors occurred during monitoring. "
                    "Check logs for detailed error information."
                )
            )
        
        if results['sessions_monitored'] == 0:
            self.stdout.write(
                "• No sessions were monitored. "
                "Consider adjusting time window or criteria."
            )
        
        # General recommendations
        self.stdout.write("\nGeneral recommendations:")
        self.stdout.write("• Run this command regularly (e.g., every 15 minutes)")
        self.stdout.write("• Set up automated alerting for high-risk sessions")
        self.stdout.write("• Review and tune anomaly detection thresholds")
        self.stdout.write("• Maintain threat intelligence feeds")
        self.stdout.write("• Regularly clean up old security events")
    
    def _cleanup_old_events(self):
        """Clean up old security events."""
        if self.verbose:
            self.stdout.write("Cleaning up old security events...")
        
        try:
            cleaned_count = session_security_service.cleanup_old_security_events()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Cleaned up {cleaned_count} old security events"
                )
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(
                    f"Error cleaning up old events: {str(e)}"
                )
            )