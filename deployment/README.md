# Enterprise Auth Deployment Guide

This directory contains comprehensive deployment and operations configurations for the Enterprise Authentication Backend.

## Directory Structure

```
deployment/
├── environments/           # Environment-specific configurations
│   ├── development.env    # Development environment settings
│   ├── staging.env        # Staging environment settings
│   └── production.env     # Production environment settings
├── kubernetes/            # Kubernetes manifests
│   ├── namespace.yaml     # Namespace and resource quotas
│   ├── secrets.yaml       # Secret configurations
│   ├── configmap.yaml     # Configuration maps
│   ├── rbac.yaml          # RBAC and network policies
│   ├── postgres.yaml      # PostgreSQL deployment
│   ├── redis.yaml         # Redis deployment
│   ├── web-deployment.yaml # Web application deployment
│   ├── celery-deployment.yaml # Celery worker deployment
│   ├── nginx-deployment.yaml # Nginx proxy deployment
│   └── hpa.yaml           # Horizontal Pod Autoscaler
├── scripts/               # Deployment and operations scripts
│   ├── backup-database.sh # Database backup script
│   ├── restore-database.sh # Database restore script
│   ├── deploy.sh          # Zero-downtime deployment script
│   ├── validate-config.sh # Configuration validation script
│   ├── security-scan.sh   # Security scanning script
│   └── monitor-deployment.sh # Deployment monitoring script
└── README.md              # This file
```

## Prerequisites

### Required Tools

- Docker and Docker Compose
- Kubernetes cluster (1.24+)
- kubectl configured for your cluster
- Helm (optional, for package management)
- AWS CLI (for S3 backup storage)

### Required Dependencies for Scripts

```bash
# Security scanning tools
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
pip install bandit safety semgrep

# Configuration validation tools
pip install yq

# Make scripts executable (Linux/macOS)
chmod +x deployment/scripts/*.sh
```

## Quick Start

### 1. Environment Setup

Choose your target environment and copy the appropriate configuration:

```bash
# For staging
cp deployment/environments/staging.env .env

# For production
cp deployment/environments/production.env .env
```

Update the configuration file with your actual values:

- Replace all `REPLACE_WITH_*` placeholders
- Configure OAuth provider credentials
- Set up external service credentials (Twilio, AWS, etc.)
- Generate secure encryption keys

### 2. Kubernetes Deployment

Deploy to Kubernetes using the deployment script:

```bash
# Deploy to staging
./deployment/scripts/deploy.sh --environment staging --tag v1.0.0

# Deploy to production
./deployment/scripts/deploy.sh --environment production --tag v1.0.0

# Dry run (test without actual deployment)
./deployment/scripts/deploy.sh --environment staging --tag v1.0.0 --dry-run
```

### 3. Manual Kubernetes Deployment

If you prefer manual deployment:

```bash
# Create namespace and basic resources
kubectl apply -f deployment/kubernetes/namespace.yaml
kubectl apply -f deployment/kubernetes/secrets.yaml
kubectl apply -f deployment/kubernetes/configmap.yaml
kubectl apply -f deployment/kubernetes/rbac.yaml

# Deploy infrastructure
kubectl apply -f deployment/kubernetes/postgres.yaml
kubectl apply -f deployment/kubernetes/redis.yaml

# Wait for infrastructure to be ready
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgres -n enterprise-auth --timeout=300s
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n enterprise-auth --timeout=300s

# Deploy application
kubectl apply -f deployment/kubernetes/web-deployment.yaml
kubectl apply -f deployment/kubernetes/celery-deployment.yaml
kubectl apply -f deployment/kubernetes/nginx-deployment.yaml
kubectl apply -f deployment/kubernetes/hpa.yaml

# Wait for application to be ready
kubectl rollout status deployment/enterprise-auth-web -n enterprise-auth --timeout=600s
```

## Configuration Management

### Environment Variables

Each environment has its own configuration file in `deployment/environments/`:

- **development.env**: Local development settings with relaxed security
- **staging.env**: Staging environment with production-like security
- **production.env**: Production settings with maximum security

### Secrets Management

Secrets are managed through Kubernetes secrets. Update `deployment/kubernetes/secrets.yaml` with your actual secrets:

```bash
# Create secrets from environment file
kubectl create secret generic enterprise-auth-secrets \
  --from-env-file=deployment/environments/production.env \
  --namespace=enterprise-auth
```

### Configuration Validation

Validate your configuration before deployment:

```bash
# Validate staging configuration
./deployment/scripts/validate-config.sh --environment staging --verbose

# Validate production configuration
./deployment/scripts/validate-config.sh --environment production
```

## Database Management

### Automated Backups

Set up automated database backups:

```bash
# Create backup
./deployment/scripts/backup-database.sh

# Configure automated backups (add to crontab)
0 2 * * * /path/to/deployment/scripts/backup-database.sh
```

### Database Restore

Restore from backup:

```bash
# List available backups
./deployment/scripts/restore-database.sh --list

# Restore from local backup
./deployment/scripts/restore-database.sh --file /backups/enterprise_auth_2024-01-15_10-30-00.sql.gz.enc

# Restore from S3 backup
./deployment/scripts/restore-database.sh --s3-key database-backups/enterprise_auth_2024-01-15_10-30-00.sql.gz.enc

# Point-in-time recovery
./deployment/scripts/restore-database.sh --target-time "2024-01-15 10:30:00"
```

## Security

### Security Scanning

Run comprehensive security scans:

```bash
# Scan container vulnerabilities
./deployment/scripts/security-scan.sh --image enterprise-auth --tag v1.0.0 --scan-type container

# Scan code security
./deployment/scripts/security-scan.sh --scan-type code

# Full security scan
./deployment/scripts/security-scan.sh --image enterprise-auth --tag v1.0.0 --scan-type all
```

### Security Best Practices

1. **Secrets Management**: Never commit secrets to version control
2. **Network Policies**: Use Kubernetes network policies to restrict traffic
3. **RBAC**: Implement least-privilege access controls
4. **Container Security**: Run containers as non-root users
5. **TLS**: Use TLS for all external communications
6. **Regular Updates**: Keep base images and dependencies updated

## Monitoring and Observability

### Deployment Monitoring

Monitor deployment health:

```bash
# Monitor deployment for 10 minutes
./deployment/scripts/monitor-deployment.sh --environment production --duration 600

# Monitor with custom thresholds
./deployment/scripts/monitor-deployment.sh --threshold 5 --interval 60
```

### Health Checks

The application provides several health check endpoints:

- `/health/` - Basic health check
- `/health/ready/` - Readiness probe
- `/health/startup/` - Startup probe
- `/metrics` - Prometheus metrics

### Logging

Structured logging is configured with:

- JSON format for machine parsing
- Correlation IDs for request tracking
- Centralized log aggregation support
- Configurable log levels

## Scaling

### Horizontal Pod Autoscaler

HPA is configured to scale based on:

- CPU utilization (70% threshold)
- Memory utilization (80% threshold)
- Custom metrics (requests per second)

### Manual Scaling

Scale deployments manually:

```bash
# Scale web deployment
kubectl scale deployment enterprise-auth-web --replicas=5 -n enterprise-auth

# Scale Celery workers
kubectl scale deployment enterprise-auth-celery-worker --replicas=3 -n enterprise-auth
```

## Troubleshooting

### Common Issues

1. **Pod Startup Issues**

   ```bash
   kubectl describe pod <pod-name> -n enterprise-auth
   kubectl logs <pod-name> -n enterprise-auth
   ```

2. **Database Connection Issues**

   ```bash
   kubectl exec -it <postgres-pod> -n enterprise-auth -- psql -U enterprise_auth_user -d enterprise_auth
   ```

3. **Redis Connection Issues**

   ```bash
   kubectl exec -it <redis-pod> -n enterprise-auth -- redis-cli ping
   ```

4. **Service Discovery Issues**
   ```bash
   kubectl get endpoints -n enterprise-auth
   kubectl get services -n enterprise-auth
   ```

### Rollback Procedures

Rollback deployment if issues occur:

```bash
# Automatic rollback (if monitoring detects issues)
./deployment/scripts/monitor-deployment.sh --environment production

# Manual rollback
kubectl rollout undo deployment/enterprise-auth-web -n enterprise-auth
kubectl rollout undo deployment/enterprise-auth-celery-worker -n enterprise-auth
```

## CI/CD Integration

The deployment system integrates with GitHub Actions for automated deployments:

- **Staging**: Automatic deployment on `develop` branch
- **Production**: Automatic deployment on release tags
- **Security Scanning**: Automated security scans on all builds
- **Rollback**: Automatic rollback on deployment failures

## Performance Optimization

### Resource Limits

Configured resource limits:

- **Web pods**: 2Gi memory, 1 CPU limit
- **Celery workers**: 1Gi memory, 500m CPU limit
- **Database**: 4Gi memory, 2 CPU limit
- **Redis**: 2Gi memory, 1 CPU limit

### Caching Strategy

Multi-layer caching:

- **Application cache**: Redis-based caching
- **Database cache**: Query result caching
- **CDN cache**: Static asset caching
- **Session cache**: Redis session storage

## Disaster Recovery

### Backup Strategy

- **Database**: Daily automated backups with 30-day retention
- **Cross-region**: S3 cross-region replication
- **Point-in-time**: WAL-based point-in-time recovery
- **Testing**: Monthly disaster recovery testing

### Recovery Procedures

1. **Database Recovery**: Use restore scripts
2. **Application Recovery**: Redeploy from known good image
3. **Configuration Recovery**: Restore from version control
4. **Monitoring**: Verify all systems after recovery

## Support and Maintenance

### Regular Maintenance Tasks

1. **Weekly**: Review security scan results
2. **Monthly**: Update base images and dependencies
3. **Quarterly**: Disaster recovery testing
4. **Annually**: Security audit and penetration testing

### Getting Help

For deployment issues:

1. Check the logs in `/tmp/enterprise-auth-*.log`
2. Review Kubernetes events: `kubectl get events -n enterprise-auth`
3. Check application logs: `kubectl logs -f deployment/enterprise-auth-web -n enterprise-auth`
4. Consult the troubleshooting section above

## License

This deployment configuration is part of the Enterprise Authentication Backend project.
