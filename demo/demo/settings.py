import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

SECRET_KEY = os.environ.get(
    'DJANGO_SECRET_KEY',
    'django-insecure-local-demo-only',
)
DEBUG = os.environ.get('DJANGO_DEBUG', 'true').lower() in {'1', 'true', 'yes', 'on'}
ALLOWED_HOSTS = ['127.0.0.1', 'localhost', 'testserver']

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.admin',
    'django.contrib.staticfiles',
    'auditlog',
    'rest_framework',
    'sec_audit.django',
    'sec_audit.django_enforcement',
    'fintech',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.common.CommonMiddleware',
    # Above AuditMiddleware: the ingress block check short-circuits before audit
    # work (system check sec_audit_enforcement.E002).
    'sec_audit.django_enforcement.middleware.EnforcementMiddleware',
    'sec_audit.django.middleware.AuditMiddleware',
]

ROOT_URLCONF = 'demo.urls'
WSGI_APPLICATION = 'demo.wsgi.application'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    }
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'django-sec-audit-demo-default',
        'TIMEOUT': 300,
    },
    'sec_audit': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'sec-audit-demo',
        'TIMEOUT': 300,
    },
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
USE_TZ = True
TIME_ZONE = 'UTC'
LANGUAGE_CODE = 'en-us'
STATIC_URL = 'static/'

LOG_DIR = BASE_DIR / 'logs'
LOG_DIR.mkdir(exist_ok=True)
AUDIT_LOG_PATH = os.environ.get(
    'SEC_AUDIT_LOG_PATH',
    str(LOG_DIR / 'sec-audit.jsonl'),
)
AUDIT_LOG_BODY_PATHS = [
    r'^/auth/login/',
    r'^/transfers/',
    r'^/profile/update/',
]
AUDIT_IGNORE_PATHS = [r'^/static/']
# Matched as case-insensitive substrings of a compacted key, so each entry
# covers every variant: 'token' catches access_token/refresh_token/
# csrfmiddlewaretoken, 'api_key' catches apiKey, 'bank_account' catches
# bank_account_number. Card numbers are caught by the value pattern below.
AUDIT_SENSITIVE_KEYS = [
    'password',
    'secret',
    'token',
    'api_key',
    'authorization',
    'cookie',
    'sessionid',
    'csrf',
    'credit_card',
    'ssn',
    'bank_account',
    'account_number',
    'national_id',
]
AUDIT_SENSITIVE_VALUE_PATTERNS = [
    r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
    r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b',
    r'\b\d{3}-\d{2}-\d{4}\b',
    r'\bNID-\d{6,}\b',
]

SEC_AUDIT = {
    'core': {
        'source': 'sec-audit',
        'log_ok_responses': True,
        'log_request_bodies': True,
        'log_body_paths': AUDIT_LOG_BODY_PATHS,
        'body_field_allowlist': ['amount', 'recipient_id', 'username', 'email'],
        'max_body_bytes': 4096,
        'ignore_paths': AUDIT_IGNORE_PATHS,
        'sensitive_keys': AUDIT_SENSITIVE_KEYS,
        'sensitive_value_patterns': AUDIT_SENSITIVE_VALUE_PATTERNS,
    },
    'logging': {
        'schema_version': '1.0',
    },
    'django': {
        'filters': [],
        'enrichers': [],
        'include_usernames': False,
        'emit_session_id': True,
        'drf_enabled': True,
        'model_events_enabled': True,
    },
}

# Enforcement: enabled with the tiered store (Redis for temp blocks + detection
# state, SQLite via the Postgres tier for durable permanent blocks). Redis lets
# block state survive across processes, so blocks seeded by `manage.py
# seed_fintech_demo` / `seed_demo_blocks` show up in the running admin and
# temp-block management (create / list / edit / revoke) is fully exercisable at
# /admin/sec_audit_enforcement/permanentblock/manage/. Point at your own Redis
# via SEC_AUDIT_DEMO_REDIS_URL. With `fail_open` defaulting to True, a missing
# Redis degrades gracefully (no enforcement / empty temp list) rather than
# bricking the demo. See packages/django-sec-audit-enforcement/docs/operations.md.
SEC_AUDIT_DEMO_REDIS_URL = os.environ.get(
    'SEC_AUDIT_DEMO_REDIS_URL', 'redis://127.0.0.1:6379/0'
)
# No detectors run unless registered: `rules` opts the deployment into the rules
# it wants (built-in or custom). The built-ins below are wired to scope-safe
# default actions via DEFAULT_RULE_ACTIONS once registered.
SEC_AUDIT_ENFORCEMENT = {
    'enabled': True,
    'redis_url': SEC_AUDIT_DEMO_REDIS_URL,
    'rules': [
        'sec_audit.rules.builtins.BruteForceLoginRule',
        'sec_audit.rules.builtins.LoginThrottleRule',
        'sec_audit.rules.builtins.RepeatedClientErrorRule',
        'sec_audit.rules.builtins.ResourceEnumerationRule',
        # User-authored detector reading the custom-event model from history.
        'fintech.audit_events.TransferVelocityRule',
    ],
    # User-authored EventSchema: derives the 'account_id' scope, persists 'amount'
    # to history, and redacts 'destination_alias' in the history store.
    'schema_specs': [
        'fintech.audit_events.TRANSFER_SCHEMA',
    ],
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        # The factory injects the resolved SEC_AUDIT core config + projection
        # limits at construction. stdout is the supported production path
        # (stdout JSONL -> Alloy -> Loki); the file handler below uses the same
        # canonical formatter so the local monitoring stack can tail the JSONL.
        'audit_jsonl': {
            '()': 'sec_audit.django.logging.formatters.audit_jsonl_formatter',
        },
    },
    'handlers': {
        'audit_stdout': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
            'formatter': 'audit_jsonl',
        },
        'audit_file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': AUDIT_LOG_PATH,
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 3,
            'formatter': 'audit_jsonl',
        },
        'console': {
            'class': 'logging.StreamHandler',
            'level': 'INFO',
        },
    },
    'loggers': {
        'sec_audit.audit': {
            'handlers': ['audit_stdout', 'audit_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'sec_audit.internal': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}
