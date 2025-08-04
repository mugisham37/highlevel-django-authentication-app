# Enterprise-Grade Authentication Backend

A comprehensive, enterprise-grade authentication backend built with Django, designed to handle millions of users with sub-100ms response times.

## Features

- **Multi-Environment Configuration**: Separate settings for development, production, and testing
- **Structured Logging**: JSON-formatted logs with correlation IDs for distributed tracing
- **Security-First Design**: Built-in security headers, rate limiting, and threat detection
- **Scalable Architecture**: Redis caching, Celery background tasks, and database optimization
- **OAuth2/OpenID Connect**: Support for Google, GitHub, Microsoft, and other providers
- **Multi-Factor Authentication**: TOTP, SMS, email, and backup codes
- **Advanced Session Management**: Device tracking, concurrent session limits, and risk scoring
- **Role-Based Access Control**: Hierarchical roles and fine-grained permissions
- **Comprehensive Monitoring**: Health checks, metrics, and observability

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 13+ (for production)
- Redis 6+ (for production)

### Installation

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd enterprise-auth-backend
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Configuration**

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run migrations**

   ```bash
   python manage.py migrate
   ```

5. **Check setup**

   ```bash
   python manage.py check_setup
   ```

6. **Start development server**
   ```bash
   python manage.py runserver
   ```

## Project Structure

```
enterprise_auth/
├── enterprise_auth/           # Main Django project
│   ├── settings/             # Environment-specific settings
│   │   ├── base.py          # Base configuration
│   │   ├── development.py   # Development settings
│   │   ├── production.py    # Production settings
│   │   └── testing.py       # Testing settings
│   ├── core/                # Core utilities
│   │   ├── logging.py       # Structured logging
│   │   └── middleware.py    # Custom middleware
│   ├── management/          # Management commands
│   ├── celery.py           # Celery configuration
│   ├── urls.py             # URL configuration
│   ├── wsgi.py             # WSGI application
│   └── asgi.py             # ASGI application
├── logs/                   # Log files
├── static/                 # Static files
├── media/                  # Media files
├── templates/              # Django templates
├── requirements.txt        # Python dependencies
├── .env.example           # Environment variables template
└── manage.py              # Django management script
```

## Configuration

### Environment Variables

The application uses environment variables for configuration. Copy `.env.example` to `.env` and customize:

- **Django Settings**: `SECRET_KEY`, `DEBUG`, `ALLOWED_HOSTS`
- **Database**: `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`
- **Redis**: `REDIS_URL`, `REDIS_SESSION_URL`
- **Email**: `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`
- **OAuth**: Provider client IDs and secrets
- **Security**: JWT secrets, rate limiting, MFA settings

### Settings Structure

The project uses a structured settings approach:

- **`base.py`**: Common settings for all environments
- **`development.py`**: Development-specific settings (SQLite, debug toolbar)
- **`production.py`**: Production settings (PostgreSQL, Redis, security headers)
- **`testing.py`**: Testing settings (in-memory database, fast password hashing)

## Health Checks

The application provides health check endpoints:

- **`/health/`**: Basic health check
- **`/ready/`**: Readiness check (database and cache connectivity)

## Logging

The application uses structured logging with correlation IDs:

- **Security Events**: Authentication attempts, MFA, suspicious activity
- **Audit Events**: User management, role assignments, data access
- **Request Logging**: HTTP requests with performance metrics
- **Error Tracking**: Unhandled exceptions with context

## Development

### Running Tests

```bash
# Set testing environment
export DJANGO_SETTINGS_MODULE=enterprise_auth.settings.testing

# Run tests
python manage.py test
```

### Management Commands

- **`check_setup`**: Verify Django configuration
- **`collectstatic`**: Collect static files
- **`migrate`**: Run database migrations

### Background Tasks

Start Celery worker for background tasks:

```bash
celery -A enterprise_auth worker -l info
```

Start Celery beat for periodic tasks:

```bash
celery -A enterprise_auth beat -l info
```

## Deployment

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV DJANGO_SETTINGS_MODULE=enterprise_auth.settings.production
CMD ["gunicorn", "enterprise_auth.wsgi:application"]
```

### Kubernetes

Health check endpoints are configured for Kubernetes:

```yaml
livenessProbe:
  httpGet:
    path: /health/
    port: 8000
readinessProbe:
  httpGet:
    path: /ready/
    port: 8000
```

## Security

- **HTTPS Enforcement**: Secure cookies and headers in production
- **CORS Configuration**: Configurable allowed origins
- **Rate Limiting**: Multi-level rate limiting (IP, user, endpoint)
- **Security Headers**: CSP, HSTS, XSS protection
- **Input Validation**: Comprehensive request validation
- **Audit Logging**: Complete audit trail for compliance

## Monitoring

- **Structured Logs**: JSON-formatted logs with correlation IDs
- **Health Checks**: Application and dependency health monitoring
- **Performance Metrics**: Response times and resource usage
- **Error Tracking**: Integration with Sentry for error monitoring

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
