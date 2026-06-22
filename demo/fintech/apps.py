from django.apps import AppConfig


class FintechConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'fintech'

    def ready(self):
        from auditlog.registry import auditlog

        from fintech.models import (
            Account,
            AdminAction,
            CustomerProfile,
            RiskReviewCase,
            Transfer,
        )

        for model in (CustomerProfile, Account, Transfer, RiskReviewCase, AdminAction):
            try:
                auditlog.register(model)
            except Exception:
                pass
