from django.conf import settings
from django.db import models


class CustomerProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    display_name = models.CharField(max_length=120)
    email = models.EmailField()
    phone = models.CharField(max_length=32, blank=True)
    national_id = models.CharField(max_length=64, blank=True)
    api_key = models.CharField(max_length=120, blank=True)

    def __str__(self):
        return self.display_name


class Account(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    account_id = models.CharField(max_length=40, unique=True)
    display_name = models.CharField(max_length=120)
    account_number = models.CharField(max_length=80)
    balance = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    risk_tier = models.CharField(max_length=20, default='low')
    is_flagged = models.BooleanField(default=False)

    def __str__(self):
        return self.account_id


class Transfer(models.Model):
    STATUS_CREATED = 'created'
    STATUS_PENDING_REVIEW = 'pending_review'
    STATUS_BLOCKED = 'blocked'

    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    transaction_id = models.CharField(max_length=40, unique=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    risk_score = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=32, default=STATUS_CREATED)
    destination_alias = models.CharField(max_length=120, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.transaction_id


class RiskReviewCase(models.Model):
    transfer = models.ForeignKey(
        Transfer,
        on_delete=models.CASCADE,
        related_name='risk_cases',
    )
    case_id = models.CharField(max_length=40, unique=True)
    reason = models.CharField(max_length=240)
    severity = models.CharField(max_length=20, default='high')
    status = models.CharField(max_length=32, default='open')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.case_id


class AdminAction(models.Model):
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    account = models.ForeignKey(Account, on_delete=models.CASCADE)
    action = models.CharField(max_length=80)
    reason = models.CharField(max_length=240)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.actor}:{self.action}:{self.account_id}'
