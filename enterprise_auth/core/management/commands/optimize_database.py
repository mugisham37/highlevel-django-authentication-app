"""
Django management command for database optimization.
Provides database index analysis, query optimization, and performance tuning.
"""

import logging
from typing import Dict, List, Any
from django.core.management.base import BaseCommand, CommandError
from django.db import connections, transaction
from django.conf import settings
from django.utils import timezone
from ...db.optimization import db_performance_monitor, QueryAnalyzer, IndexOptimizer, ConnectionPoolMonitor

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Optimize database performance through index analysis and query optimization'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--analyze-indexes',
            action='store_true',
            help='Analyze database indexes and provide recommendations'
        )
        
        parser.add_argument(
            '--analyze-queries',
            action='store_true',
            help='Analyze slow queries and provide optimization suggestions'
        )
        
        parser.add_argument(
            '--check-connections',
            action='store_true',
            help='Check database connection pool health'
        )
        
        parser.add_argument(
            '--create-indexes',
            action='store_true',
            help='Create recommended indexes (use with caution in production)'
        )
        
        parser.add_argument(
            '--vacuum-analyze',
            action='store_true',
            help='Run VACUUM ANALYZE on PostgreSQL databases'
        )
        
        parser.add_argument(
            '--update-statistics',
            action='store_true',
            help='Update database statistics for query optimization'
        )
        
        parser.add_argument(
            '--database',
            type=str,
            default='default',
            help='Database connection to optimize (default: default)'
        )
        
        parser.add_argument(
            '--report-only',
            action='store_true',
            help='Generate reports without making any changes'
        )
        
        parser.add_argument(
            '--output-format',
            choices=['text', 'json'],
            default='text',
            help='Output format for reports'
        )
    
    def handle(self, *args, **options):
        """Main command handler."""
        self.verbosity = options['verbosity']
        self.database = options['database']
        self.report_only = options['report_only']
        self.output_format = options['output_format']
        
        # Validate database connection
        if self.database not in connections:
            raise CommandError(f"Database connection '{self.database}' not found")
        
        self.stdout.write(
            self.style.SUCCESS(f"Starting database optimization for '{self.database}'")
        )
        
        results = {}
        
        try:
            # Analyze indexes
            if options['analyze_indexes']:
                results['index_analysis'] = self._analyze_indexes()
            
            # Analyze queries
            if options['analyze_queries']:
                results['query_analysis'] = self._analyze_queries()
            
            # Check connections
            if options['check_connections']:
                results['connection_analysis'] = self._check_connections()
            
            # Create indexes
            if options['create_indexes'] and not self.report_only:
                results['index_creation'] = self._create_recommended_indexes()
            
            # Vacuum analyze
            if options['vacuum_analyze'] and not self.report_only:
                results['vacuum_analyze'] = self._vacuum_analyze()
            
            # Update statistics
            if options['update_statistics'] and not self.report_only:
                results['statistics_update'] = self._update_statistics()
            
            # If no specific action requested, run comprehensive analysis
            if not any([
                options['analyze_indexes'], options['analyze_queries'],
                options['check_connections'], options['create_indexes'],
                options['vacuum_analyze'], options['update_statistics']
            ]):
                results = self._comprehensive_analysis()
            
            # Output results
            self._output_results(results)
            
        except Exception as e:
            logger.error(f"Database optimization failed: {e}")
            raise CommandError(f"Optimization failed: {e}")
        
        self.stdout.write(
            self.style.SUCCESS("Database optimization completed successfully")
        )
    
    def _analyze_indexes(self) -> Dict[str, Any]:
        """Analyze database indexes and provide recommendations."""
        self.stdout.write("Analyzing database indexes...")
        
        index_optimizer = IndexOptimizer()
        
        # Get missing index recommendations
        missing_indexes = index_optimizer.analyze_missing_indexes(self.database)
        
        # Get index usage statistics
        index_stats = index_optimizer.get_index_usage_stats(self.database)
        
        # Analyze index effectiveness
        effectiveness_analysis = self._analyze_index_effectiveness(index_stats)
        
        analysis_result = {
            'missing_indexes': missing_indexes,
            'index_statistics': index_stats,
            'effectiveness_analysis': effectiveness_analysis,
            'recommendations': self._generate_index_recommendations(missing_indexes, index_stats),
            'timestamp': timezone.now().isoformat()
        }
        
        if self.verbosity >= 2:
            self._print_index_analysis(analysis_result)
        
        return analysis_result
    
    def _analyze_queries(self) -> Dict[str, Any]:
        """Analyze slow queries and provide optimization suggestions."""
        self.stdout.write("Analyzing database queries...")
        
        query_analyzer = QueryAnalyzer()
        
        # Get slow queries report
        slow_queries_report = query_analyzer.get_slow_queries_report(hours=24)
        
        # Get overall query statistics
        query_stats = query_analyzer.get_query_statistics()
        
        # Generate optimization recommendations
        query_recommendations = self._generate_query_recommendations(slow_queries_report, query_stats)
        
        analysis_result = {
            'slow_queries': slow_queries_report,
            'query_statistics': query_stats,
            'recommendations': query_recommendations,
            'timestamp': timezone.now().isoformat()
        }
        
        if self.verbosity >= 2:
            self._print_query_analysis(analysis_result)
        
        return analysis_result
    
    def _check_connections(self) -> Dict[str, Any]:
        """Check database connection pool health."""
        self.stdout.write("Checking database connections...")
        
        connection_monitor = ConnectionPoolMonitor()
        
        # Get connection pool statistics
        pool_stats = connection_monitor.get_connection_pool_stats()
        
        # Check connection health
        health_check = connection_monitor.check_connection_health(self.database)
        
        # Analyze connection performance
        connection_analysis = self._analyze_connection_performance(pool_stats, health_check)
        
        analysis_result = {
            'pool_statistics': pool_stats,
            'health_check': health_check,
            'performance_analysis': connection_analysis,
            'recommendations': self._generate_connection_recommendations(pool_stats, health_check),
            'timestamp': timezone.now().isoformat()
        }
        
        if self.verbosity >= 2:
            self._print_connection_analysis(analysis_result)
        
        return analysis_result
    
    def _create_recommended_indexes(self) -> Dict[str, Any]:
        """Create recommended database indexes."""
        if self.report_only:
            self.stdout.write("Skipping index creation (report-only mode)")
            return {'skipped': True}
        
        self.stdout.write("Creating recommended indexes...")
        
        # Get index recommendations
        index_optimizer = IndexOptimizer()
        recommendations = index_optimizer.analyze_missing_indexes(self.database)
        
        created_indexes = []
        failed_indexes = []
        
        with connections[self.database].cursor() as cursor:
            for recommendation in recommendations:
                if recommendation['type'] == 'missing_index':
                    try:
                        # Generate index creation SQL
                        index_sql = self._generate_index_sql(recommendation)
                        
                        if index_sql:
                            self.stdout.write(f"Creating index: {index_sql}")
                            cursor.execute(index_sql)
                            created_indexes.append({
                                'table': recommendation['table'],
                                'sql': index_sql,
                                'reason': recommendation['reason']
                            })
                        
                    except Exception as e:
                        failed_indexes.append({
                            'table': recommendation['table'],
                            'error': str(e),
                            'recommendation': recommendation
                        })
                        logger.error(f"Failed to create index for {recommendation['table']}: {e}")
        
        result = {
            'created_indexes': created_indexes,
            'failed_indexes': failed_indexes,
            'total_created': len(created_indexes),
            'total_failed': len(failed_indexes),
            'timestamp': timezone.now().isoformat()
        }
        
        self.stdout.write(
            self.style.SUCCESS(f"Created {len(created_indexes)} indexes, {len(failed_indexes)} failed")
        )
        
        return result
    
    def _vacuum_analyze(self) -> Dict[str, Any]:
        """Run VACUUM ANALYZE on PostgreSQL databases."""
        if self.report_only:
            self.stdout.write("Skipping VACUUM ANALYZE (report-only mode)")
            return {'skipped': True}
        
        connection = connections[self.database]
        
        # Check if this is PostgreSQL
        if 'postgresql' not in connection.settings_dict['ENGINE']:
            self.stdout.write("VACUUM ANALYZE is only supported for PostgreSQL databases")
            return {'skipped': True, 'reason': 'Not PostgreSQL'}
        
        self.stdout.write("Running VACUUM ANALYZE...")
        
        vacuum_results = []
        
        try:
            with connection.cursor() as cursor:
                # Get list of user tables
                cursor.execute("""
                    SELECT schemaname, tablename 
                    FROM pg_tables 
                    WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
                    ORDER BY schemaname, tablename;
                """)
                
                tables = cursor.fetchall()
                
                for schema, table in tables:
                    try:
                        table_name = f"{schema}.{table}"
                        self.stdout.write(f"VACUUM ANALYZE {table_name}...")
                        
                        # Run VACUUM ANALYZE on the table
                        cursor.execute(f'VACUUM ANALYZE "{schema}"."{table}";')
                        
                        vacuum_results.append({
                            'table': table_name,
                            'status': 'success'
                        })
                        
                    except Exception as e:
                        vacuum_results.append({
                            'table': table_name,
                            'status': 'failed',
                            'error': str(e)
                        })
                        logger.error(f"VACUUM ANALYZE failed for {table_name}: {e}")
        
        except Exception as e:
            logger.error(f"VACUUM ANALYZE operation failed: {e}")
            return {'error': str(e)}
        
        successful = sum(1 for r in vacuum_results if r['status'] == 'success')
        failed = sum(1 for r in vacuum_results if r['status'] == 'failed')
        
        self.stdout.write(
            self.style.SUCCESS(f"VACUUM ANALYZE completed: {successful} successful, {failed} failed")
        )
        
        return {
            'results': vacuum_results,
            'successful': successful,
            'failed': failed,
            'timestamp': timezone.now().isoformat()
        }
    
    def _update_statistics(self) -> Dict[str, Any]:
        """Update database statistics for query optimization."""
        if self.report_only:
            self.stdout.write("Skipping statistics update (report-only mode)")
            return {'skipped': True}
        
        self.stdout.write("Updating database statistics...")
        
        connection = connections[self.database]
        
        try:
            with connection.cursor() as cursor:
                if 'postgresql' in connection.settings_dict['ENGINE']:
                    # PostgreSQL: Update statistics
                    cursor.execute("ANALYZE;")
                    result = {'database': 'postgresql', 'operation': 'ANALYZE', 'status': 'success'}
                
                elif 'mysql' in connection.settings_dict['ENGINE']:
                    # MySQL: Update statistics
                    cursor.execute("ANALYZE TABLE;")
                    result = {'database': 'mysql', 'operation': 'ANALYZE TABLE', 'status': 'success'}
                
                else:
                    result = {'status': 'skipped', 'reason': 'Unsupported database engine'}
            
            self.stdout.write(self.style.SUCCESS("Database statistics updated successfully"))
            
        except Exception as e:
            logger.error(f"Statistics update failed: {e}")
            result = {'status': 'failed', 'error': str(e)}
        
        result['timestamp'] = timezone.now().isoformat()
        return result
    
    def _comprehensive_analysis(self) -> Dict[str, Any]:
        """Run comprehensive database analysis."""
        self.stdout.write("Running comprehensive database analysis...")
        
        return {
            'index_analysis': self._analyze_indexes(),
            'query_analysis': self._analyze_queries(),
            'connection_analysis': self._check_connections(),
            'performance_report': db_performance_monitor.get_performance_report(hours=24),
            'timestamp': timezone.now().isoformat()
        }
    
    def _analyze_index_effectiveness(self, index_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze index effectiveness."""
        if not index_stats or 'indexes' not in index_stats:
            return {'error': 'No index statistics available'}
        
        indexes = index_stats['indexes']
        
        # Categorize indexes by usage
        highly_used = [idx for idx in indexes if idx['scans'] > 1000]
        moderately_used = [idx for idx in indexes if 100 <= idx['scans'] <= 1000]
        rarely_used = [idx for idx in indexes if 10 <= idx['scans'] < 100]
        unused = [idx for idx in indexes if idx['scans'] < 10]
        
        # Calculate efficiency metrics
        efficient_indexes = [idx for idx in indexes if idx['efficiency'] > 0.8]
        inefficient_indexes = [idx for idx in indexes if idx['efficiency'] < 0.3]
        
        return {
            'usage_categories': {
                'highly_used': len(highly_used),
                'moderately_used': len(moderately_used),
                'rarely_used': len(rarely_used),
                'unused': len(unused)
            },
            'efficiency_metrics': {
                'efficient_indexes': len(efficient_indexes),
                'inefficient_indexes': len(inefficient_indexes),
                'total_indexes': len(indexes)
            },
            'recommendations': {
                'consider_dropping': len(unused),
                'review_efficiency': len(inefficient_indexes)
            }
        }
    
    def _analyze_connection_performance(self, pool_stats: Dict, health_check: Dict) -> Dict[str, Any]:
        """Analyze connection pool performance."""
        analysis = {
            'health_status': health_check.get('status', 'unknown'),
            'response_time_ms': health_check.get('response_time_ms', 0),
            'issues': [],
            'recommendations': []
        }
        
        # Analyze response time
        response_time = health_check.get('response_time_ms', 0)
        if response_time > 100:
            analysis['issues'].append('High database response time')
            analysis['recommendations'].append('Check database server performance and network latency')
        
        # Analyze connection pool usage
        connections_data = pool_stats.get('connections', {})
        for conn_name, stats in connections_data.items():
            active_connections = stats.get('active_connections', 0)
            max_connections = stats.get('max_connections_used', 0)
            
            if max_connections > 80:  # Assuming 100 max connections
                analysis['issues'].append(f'High connection pool usage for {conn_name}')
                analysis['recommendations'].append(f'Consider increasing connection pool size for {conn_name}')
            
            connection_errors = stats.get('connection_errors', 0)
            if connection_errors > 5:
                analysis['issues'].append(f'High connection errors for {conn_name}')
                analysis['recommendations'].append(f'Investigate connection stability for {conn_name}')
        
        return analysis
    
    def _generate_index_recommendations(self, missing_indexes: List, index_stats: Dict) -> List[str]:
        """Generate index optimization recommendations."""
        recommendations = []
        
        # Missing index recommendations
        high_priority_missing = [idx for idx in missing_indexes if idx.get('priority') == 'high']
        if high_priority_missing:
            recommendations.append(f"Create {len(high_priority_missing)} high-priority missing indexes")
        
        # Unused index recommendations
        if index_stats and 'indexes' in index_stats:
            unused_indexes = [idx for idx in index_stats['indexes'] if idx['scans'] < 10]
            if unused_indexes:
                recommendations.append(f"Consider dropping {len(unused_indexes)} unused indexes")
        
        return recommendations
    
    def _generate_query_recommendations(self, slow_queries: Dict, query_stats: Dict) -> List[str]:
        """Generate query optimization recommendations."""
        recommendations = []
        
        total_slow_queries = slow_queries.get('total_slow_queries', 0)
        if total_slow_queries > 10:
            recommendations.append("High number of slow queries detected - review query optimization")
        
        avg_query_time = query_stats.get('avg_query_time', 0)
        if avg_query_time > 0.1:  # 100ms
            recommendations.append("Average query time is high - consider query optimization")
        
        return recommendations
    
    def _generate_connection_recommendations(self, pool_stats: Dict, health_check: Dict) -> List[str]:
        """Generate connection optimization recommendations."""
        recommendations = []
        
        response_time = health_check.get('response_time_ms', 0)
        if response_time > 50:
            recommendations.append("Database response time is high - check server performance")
        
        return recommendations
    
    def _generate_index_sql(self, recommendation: Dict) -> str:
        """Generate SQL for creating recommended index."""
        # This is a simplified implementation
        # In production, you'd need more sophisticated logic
        table = recommendation['table']
        
        # Basic index creation based on recommendation type
        if 'missing_where_clause' in recommendation.get('reason', ''):
            # This would require more context about which columns to index
            return None
        
        # Return None for now - index creation requires more specific analysis
        return None
    
    def _print_index_analysis(self, analysis: Dict):
        """Print index analysis results."""
        self.stdout.write("\n" + "="*50)
        self.stdout.write("INDEX ANALYSIS RESULTS")
        self.stdout.write("="*50)
        
        missing = analysis.get('missing_indexes', [])
        if missing:
            self.stdout.write(f"\nMissing Indexes: {len(missing)}")
            for idx in missing[:5]:  # Show first 5
                self.stdout.write(f"  - {idx['table']}: {idx['reason']}")
        
        effectiveness = analysis.get('effectiveness_analysis', {})
        if effectiveness:
            usage = effectiveness.get('usage_categories', {})
            self.stdout.write(f"\nIndex Usage:")
            self.stdout.write(f"  - Highly used: {usage.get('highly_used', 0)}")
            self.stdout.write(f"  - Unused: {usage.get('unused', 0)}")
    
    def _print_query_analysis(self, analysis: Dict):
        """Print query analysis results."""
        self.stdout.write("\n" + "="*50)
        self.stdout.write("QUERY ANALYSIS RESULTS")
        self.stdout.write("="*50)
        
        slow_queries = analysis.get('slow_queries', {})
        total_slow = slow_queries.get('total_slow_queries', 0)
        self.stdout.write(f"\nSlow Queries: {total_slow}")
        
        if total_slow > 0:
            queries = slow_queries.get('queries', [])
            for query in queries[:3]:  # Show first 3
                self.stdout.write(f"  - {query['normalized_sql'][:100]}...")
                self.stdout.write(f"    Count: {query['count']}, Avg: {query['avg_duration']:.3f}s")
    
    def _print_connection_analysis(self, analysis: Dict):
        """Print connection analysis results."""
        self.stdout.write("\n" + "="*50)
        self.stdout.write("CONNECTION ANALYSIS RESULTS")
        self.stdout.write("="*50)
        
        health = analysis.get('health_check', {})
        self.stdout.write(f"\nConnection Health: {health.get('status', 'unknown')}")
        self.stdout.write(f"Response Time: {health.get('response_time_ms', 0):.2f}ms")
        
        perf_analysis = analysis.get('performance_analysis', {})
        issues = perf_analysis.get('issues', [])
        if issues:
            self.stdout.write(f"\nIssues Found: {len(issues)}")
            for issue in issues:
                self.stdout.write(f"  - {issue}")
    
    def _output_results(self, results: Dict[str, Any]):
        """Output results in the specified format."""
        if self.output_format == 'json':
            import json
            self.stdout.write(json.dumps(results, indent=2, default=str))
        else:
            # Text format output is handled by individual print methods
            if self.verbosity >= 1:
                self.stdout.write(f"\nOptimization completed at {timezone.now()}")
                self.stdout.write(f"Results available for: {', '.join(results.keys())}")