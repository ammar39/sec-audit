from rest_framework import serializers

from fintech.models import (
    Account,
    AdminAction,
    CustomerProfile,
    RiskReviewCase,
    Transfer,
)


class AccountSerializer(serializers.ModelSerializer):
    owner = serializers.CharField(source='owner.username')

    class Meta:
        model = Account
        fields = [
            'account_id',
            'owner',
            'display_name',
            'balance',
            'currency',
            'risk_tier',
            'is_flagged',
        ]


class TransferCreateSerializer(serializers.Serializer):
    account_id = serializers.CharField(default='acct-demo-1001')
    amount = serializers.DecimalField(max_digits=12, decimal_places=2)
    currency = serializers.CharField(default='USD', max_length=3)
    destination_alias = serializers.CharField(default='Demo Vendor', max_length=120)


class TransferSerializer(serializers.ModelSerializer):
    account_id = serializers.CharField(source='account.account_id')

    class Meta:
        model = Transfer
        fields = [
            'transaction_id',
            'account_id',
            'amount',
            'currency',
            'risk_score',
            'status',
            'destination_alias',
            'created_at',
        ]


class ProfileUpdateSerializer(serializers.ModelSerializer):
    token = serializers.CharField(write_only=True, required=False, allow_blank=True)
    bank_account_number = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True,
    )
    card_number = serializers.CharField(
        write_only=True, required=False, allow_blank=True
    )

    class Meta:
        model = CustomerProfile
        fields = [
            'email',
            'phone',
            'national_id',
            'api_key',
            'token',
            'bank_account_number',
            'card_number',
        ]


class RiskReviewCaseSerializer(serializers.ModelSerializer):
    transaction_id = serializers.CharField(source='transfer.transaction_id')
    account_id = serializers.CharField(source='transfer.account.account_id')

    class Meta:
        model = RiskReviewCase
        fields = [
            'case_id',
            'transaction_id',
            'account_id',
            'reason',
            'severity',
            'status',
        ]


class AdminActionSerializer(serializers.ModelSerializer):
    actor = serializers.CharField(source='actor.username')
    account_id = serializers.CharField(source='account.account_id')

    class Meta:
        model = AdminAction
        fields = ['actor', 'account_id', 'action', 'reason', 'created_at']
