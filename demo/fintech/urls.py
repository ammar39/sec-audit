from django.urls import path

from fintech import views

urlpatterns = [
    path('', views.index, name='index'),
]
