from django.apps import AppConfig


class SecAuditEnforcementConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'sec_audit.django_enforcement'
    label = 'sec_audit_enforcement'
    verbose_name = 'Sec Audit Enforcement'

    def ready(self):
        # System checks self-register on import (available to manage.py check
        # regardless of runtime outcome).
        from sec_audit.django_enforcement import checks  # noqa: F401
        from sec_audit.django_enforcement.runtime import setup_enforcement

        # Validate config fail-fast and (when enabled) register the record()
        # consumer. Store construction / Redis connection are deferred to first
        # use so migrate/check/collectstatic work even when Redis is down.
        setup_enforcement()
