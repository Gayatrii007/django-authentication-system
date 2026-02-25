from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import timedelta

class User(AbstractUser):
    email = models.EmailField(unique=True)
    mobile_number = models.CharField(
    max_length=15,
    unique=True,
    null=True,
    blank=True
)
    is_verified = models.BooleanField(default=False)

    #email verification
    email_verify_token = models.CharField(max_length=255, blank=True, null=True)
    email_verify_token_expiry = models.DateTimeField(blank=True, null=True)

    # OTP fields
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)

    #acc lockout
    failed_login_attempts = models.PositiveIntegerField(default=0)
    lock_until = models.DateTimeField(blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def is_locked(self):
        return self.lock_until and timezone.now() < self.lock_until

    def is_email_token_valid(self):
        return (
            self.email_verify_token and
            self.email_verify_token_expiry and
            timezone.now() < self.email_verify_token_expiry
        )

class LoginActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    login_time = models.DateTimeField(auto_now_add=True)
    successful = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.email} - {self.ip_address}"
