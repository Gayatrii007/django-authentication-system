from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from .models import User
from django.utils import timezone
from datetime import timedelta

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)

    def validate_password(self, value):
        validate_password(value)
        return value

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "User already exists. Please login."
            )
        return value

    def validate_password(self, value):
        validate_password(value)   # Django strong password rules
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                "User not registered. Please sign up."
            )

        # 🔒 Account locked?
        if user.is_locked():
            raise serializers.ValidationError(
                "Account temporarily locked. Try again later."
            )

        user_auth = authenticate(email=email, password=password)

        # ❌ Wrong password
        if not user_auth:
            user.failed_login_attempts += 1

            if user.failed_login_attempts >= 5:
                user.lock_until = timezone.now() + timedelta(minutes=15)

            user.save()

            raise serializers.ValidationError("Invalid credentials")

        # ✅ Successful login → reset counters
        user.failed_login_attempts = 0
        user.lock_until = None
        user.save()

        data['user'] = user
        return data


class GoogleLoginSerializer(serializers.Serializer):
    token = serializers.CharField()
