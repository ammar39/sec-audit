from django.urls import path

from fintech.api import views

urlpatterns = [
    path('accounts/', views.accounts, name='accounts'),
    path('accounts/<str:account_id>/', views.account_detail, name='account-detail'),
    path('transfers/', views.transfer, name='transfer'),
    path('transfers/high-risk/', views.high_risk_transfer, name='high-risk-transfer'),
    path('transfers/blocked/', views.blocked_transfer, name='blocked-transfer'),
    path('auth/login/', views.fake_login, name='fake-login'),
    path('auth/login/suspicious/', views.suspicious_login, name='suspicious-login'),
    path('profile/update/', views.profile_update, name='profile-update'),
    path('admin/risk-review/', views.risk_review, name='risk-review'),
    path('admin/risk-review/flag-account/', views.flag_account, name='flag-account'),
    path('demo/generate-events/', views.generate_events, name='generate-events'),
]
