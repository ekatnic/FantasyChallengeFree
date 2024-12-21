# fantasy_football_app/urls/signup.py
from django.urls import path
from .. import views  # Go up one level to access the 'views' module

urlpatterns = [
    path('', views.signup, name='signup'),
]
