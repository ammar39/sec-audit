from __future__ import annotations

import uuid

from auditlog.signals import accessed
from django.contrib.auth import authenticate, login
from django.contrib.auth.signals import user_login_failed
from django.db import transaction
from django.http import Http404
from rest_framework.decorators import api_view
from rest_framework.response import Response

from fintech.api.serializers import (
    AccountSerializer,
    AdminActionSerializer,
    ProfileUpdateSerializer,
    RiskReviewCaseSerializer,
    TransferCreateSerializer,
    TransferSerializer,
)
from fintech.models import (
    Account,
    AdminAction,
    CustomerProfile,
    RiskReviewCase,
    Transfer,
)
from fintech.traffic import generate_demo_events


@api_view(['GET'])
def accounts(request):
    queryset = Account.objects.select_related('owner').order_by('account_id')
    for account in queryset:
        accessed.send(sender=Account, instance=account)
    return Response({'accounts': AccountSerializer(queryset, many=True).data})


@api_view(['GET'])
def account_detail(request, account_id):
    try:
        account = Account.objects.select_related('owner').get(account_id=account_id)
    except Account.DoesNotExist:
        raise Http404('Account not found')
    accessed.send(sender=Account, instance=account)
    return Response(AccountSerializer(account).data)


@api_view(['POST'])
def transfer(request):
    serializer = TransferCreateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    account = Account.objects.get(account_id=serializer.validated_data['account_id'])
    transfer_obj = Transfer.objects.create(
        account=account,
        transaction_id=_transaction_id(),
        amount=serializer.validated_data['amount'],
        currency=serializer.validated_data['currency'],
        risk_score=18,
        status=Transfer.STATUS_CREATED,
        destination_alias=serializer.validated_data['destination_alias'],
    )
    return Response(TransferSerializer(transfer_obj).data, status=201)


@api_view(['POST'])
def high_risk_transfer(request):
    serializer = TransferCreateSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    account = Account.objects.get(account_id=serializer.validated_data['account_id'])
    with transaction.atomic():
        transfer_obj = Transfer.objects.create(
            account=account,
            transaction_id=_transaction_id(),
            amount=serializer.validated_data['amount'],
            currency=serializer.validated_data['currency'],
            risk_score=92,
            status=Transfer.STATUS_PENDING_REVIEW,
            destination_alias=serializer.validated_data['destination_alias'],
        )
        case = RiskReviewCase.objects.create(
            transfer=transfer_obj,
            case_id=f'risk-{uuid.uuid4().hex[:10]}',
            reason='High-value transfer requires analyst review',
            severity='high',
        )
    return Response(
        {
            'transfer': TransferSerializer(transfer_obj).data,
            'risk_case': RiskReviewCaseSerializer(case).data,
        },
        status=202,
    )


@api_view(['POST'])
def blocked_transfer(request):
    account = Account.objects.get(account_id='acct-demo-4040')
    transfer_obj = Transfer.objects.create(
        account=account,
        transaction_id=_transaction_id(),
        amount=request.data.get('amount', '75000.00'),
        currency=request.data.get('currency', 'USD'),
        risk_score=99,
        status=Transfer.STATUS_BLOCKED,
        destination_alias=request.data.get(
            'destination_alias', 'Blocked Demo Recipient'
        ),
    )
    return Response(
        {
            'status': 'blocked',
            'transaction_id': transfer_obj.transaction_id,
            'message': 'Transfer rejected by demo business policy.',
        },
        status=429,
    )


@api_view(['POST'])
def fake_login(request):
    username = str(request.data.get('username', 'maya'))
    password = str(request.data.get('password', 'demo-password'))
    user = authenticate(request, username=username, password=password)
    if user is None:
        return Response({'status': 'failed'}, status=401)
    login(request, user)
    return Response({'status': 'ok', 'username': user.username})


@api_view(['POST'])
def suspicious_login(request):
    username = str(request.data.get('username', 'synthetic-attacker'))
    for index in range(5):
        user_login_failed.send(
            sender=__name__,
            credentials={'username': username, 'password': f'bad-pass-{index}'},
            request=request,
        )
    return Response({'status': 'simulated', 'attempts': 5})


@api_view(['POST'])
def profile_update(request):
    profile = CustomerProfile.objects.select_related('user').get(user__username='maya')
    serializer = ProfileUpdateSerializer(profile, data=request.data, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response({'status': 'updated', 'email': profile.email})


@api_view(['GET'])
def risk_review(request):
    cases = RiskReviewCase.objects.select_related(
        'transfer', 'transfer__account'
    ).order_by('-created_at')
    return Response({'reviews': RiskReviewCaseSerializer(cases, many=True).data})


@api_view(['POST'])
def flag_account(request):
    account_id = request.data.get('account_id', 'acct-demo-2002')
    account = Account.objects.get(account_id=account_id)
    account.is_flagged = True
    account.risk_tier = 'high'
    account.save()
    actor = account.owner
    action = AdminAction.objects.create(
        actor=actor,
        account=account,
        action='flag-account',
        reason=request.data.get('reason', 'Manual risk review'),
    )
    return Response(AdminActionSerializer(action).data)


@api_view(['GET'])
def generate_events(request):
    summary = generate_demo_events(request)
    return Response(summary)


def _transaction_id():
    return f'txn-demo-{uuid.uuid4().hex[:12]}'
