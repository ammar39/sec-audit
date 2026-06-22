from django.urls import include, path

urlpatterns = [
    path('', include('fintech.urls')),
    path('', include('fintech.api.urls')),
]
