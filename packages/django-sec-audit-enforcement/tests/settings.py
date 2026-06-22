"""Minimal Django settings for the enforcement test suite (sqlite in-memory)."""

SECRET_KEY = 'test-secret-key'
DEBUG = False
USE_TZ = True
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'sec_audit.django',
    'sec_audit.django_enforcement',
]

MIDDLEWARE = [
    'sec_audit.django_enforcement.middleware.EnforcementMiddleware',
    'sec_audit.django.middleware.AuditMiddleware',
]

SEC_AUDIT = {
    'logging': {'schema_version': '1.0'},
}

# Off by default; individual tests build their own runtime/config explicitly.
SEC_AUDIT_ENFORCEMENT = {
    'enabled': False,
}

# Tests configure logging explicitly where needed.
LOGGING_CONFIG = None
