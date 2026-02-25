from django.urls import path
from . import views
from .views import google_login, verify_email, login_history

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('forgot-password/', views.forgot_password),
    path('reset-password/<str:token>/', views.reset_password),
    path('google-login/', google_login),
    path('verify-email/<str:token>/', verify_email),
    path('login-history/', login_history),
    path('send-otp/', views.send_mobile_otp),
    path('verify-otp/', views.verify_mobile_otp),
]
