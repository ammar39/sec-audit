from django.apps import AppConfig


class SecAuditConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'sec_audit.django'
    label = 'sec_audit_django'
    verbose_name = 'Sec Audit'

    def ready(self):
        from django.conf import settings

        from sec_audit.django.runtime import _build_runtime, _set_runtime

        # Register system checks (the @register decorators self-register on
        # import) before the runtime build so they are available to
        # ``manage.py check`` regardless of runtime outcome.
        import sec_audit.django.checks  # noqa: F401

        runtime = _build_runtime(settings)
        _set_runtime(runtime)
        import sec_audit.django.logging.auth  # noqa: F401

        # model-event forwarding is opt-in. Only import the auditlog
        # forwarder when the operator explicitly enables it, so installing
        # django-auditlog no longer implicitly registers receivers. Missing
        # explicitly enabled dependencies fail clearly during runtime build.
        if runtime.config.django.model_events_enabled:
            import sec_audit.django.logging.model  # noqa: F401
