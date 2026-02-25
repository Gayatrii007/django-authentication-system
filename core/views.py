from django.utils.crypto import get_random_string
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.utils import timezone
from datetime import timedelta
import uuid
from rest_framework_simplejwt.tokens import RefreshToken
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.conf import settings
from .serializers import GoogleLoginSerializer
from rest_framework.permissions import IsAuthenticated
from .models import User
from .serializers import ForgotPasswordSerializer, ResetPasswordSerializer, LoginSerializer, RegisterSerializer
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from rest_framework.decorators import throttle_classes
from .throttles import LoginRateThrottle
from .models import LoginActivity
from django.views.decorators.csrf import csrf_exempt
from .utils import generate_otp, send_otp_sms

@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()

    token = uuid.uuid4().hex
    user.email_verify_token = token
    user.email_verify_token_expiry = timezone.now() + timedelta(hours=24)
    user.save()

    verify_link = f"http://127.0.0.1:8000/auth/verify-email/{token}/"

    send_mail(
        "Verify your email",
        f"Click to verify your email: {verify_link}",
        "noreply@auth.com",
        [user.email],
    )

    return Response({
        "message": "Registration successful. Please verify your email."
    }, status=201)


@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request, token):
    try:
        user = User.objects.get(email_verify_token=token)
    except User.DoesNotExist:
        return Response({"error": "Invalid verification link"}, status=400)

    if not user.is_email_token_valid():
        return Response({"error": "Verification link expired"}, status=400)

    user.is_verified = True
    user.email_verify_token = None
    user.email_verify_token_expiry = None
    user.save()

    return Response({
        "message": "Email verified successfully. You can now login."
    })

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def login(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.validated_data['user']
    tokens = get_tokens(user)

    return Response({
        "message": "Login successful",
        "tokens": tokens,
        "login_methods": ["email", "google"]
    })

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(request):
    serializer = ForgotPasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    email = serializer.validated_data['email']

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"message": "If email exists, reset link sent"})

    token = uuid.uuid4().hex
    user.reset_token = token
    user.reset_token_expiry = timezone.now() + timedelta(minutes=15)
    user.save()

    reset_link = f"http://127.0.0.1:8000/auth/reset-password/{token}/"

    send_mail(
        "Reset your password",
        reset_link,
        "noreply@auth.com",
        [user.email]
    )

    return Response({"message": "Reset link sent"})

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request, token):
    serializer = ResetPasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    try:
        user = User.objects.get(reset_token=token)
    except User.DoesNotExist:
        return Response({"error": "Invalid token"}, status=400)

    if not user.is_reset_token_valid():
        return Response({"error": "Token expired"}, status=400)

    user.password = make_password(serializer.validated_data['password'])
    user.reset_token = None
    user.reset_token_expiry = None
    user.save()

    return Response({"message": "Password reset successful"})

def get_tokens(user):
    refresh = RefreshToken.for_user(user)
    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh),
    }

@api_view(['POST'])
@permission_classes([AllowAny])
def google_login(request):
    serializer = GoogleLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    token = serializer.validated_data['token']

    try:
        idinfo = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            settings.GOOGLE_CLIENT_ID
        )
    except Exception:
        return Response({"error": "Invalid Google token"}, status=400)

    email = idinfo.get('email')
    name = idinfo.get('name', '')

    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            "username": email.split('@')[0],
            "is_verified": True
        }
    )

    tokens = get_tokens(user)

    return Response({
        "message": "Google login successful",
        "new_user": created,
        "tokens": tokens
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        refresh_token = request.data.get("refresh")
        token = RefreshToken(refresh_token)
        token.blacklist()
    except Exception:
        return Response({"error": "Invalid token"}, status=400)

    return Response({
        "message": "Logout successful"
    })

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def login_history(request):
    logs = LoginActivity.objects.filter(
        user=request.user
    ).order_by('-login_time')[:10]

    data = [
        {
            "ip": log.ip_address,
            "device": log.user_agent,
            "time": log.login_time,
            "success": log.successful
        }
        for log in logs
    ]

    return Response(data)


@api_view(['POST'])
@permission_classes([AllowAny])
def send_mobile_otp(request):
    mobile = request.data.get("mobile")

    if not mobile:
        return Response({"error": "Mobile required"}, status=400)

    mobile = str(mobile)
    # User already hai ya nahi check
    user = User.objects.filter(mobile_number=mobile).first()

    # Agar nahi hai → auto create
    if not user:
        user = User.objects.create(
            mobile_number=mobile,
            username=f"user_{mobile[-4:]}"  # temp username
        )

    otp = generate_otp()

    user.otp = otp
    user.otp_expiry = timezone.now() + timedelta(minutes=5)
    user.save()

    print("OTP:", otp)  # testing

    return Response({"message": "OTP sent"})


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_mobile_otp(request):
    mobile = request.data.get("mobile")

    if not mobile:
        return Response({"error": "Mobile required"}, status=400)

    otp = str(request.data.get("otp"))
    mobile = str(request.data.get("mobile"))

    user = User.objects.filter(mobile_number=mobile).first()

    if not user:
        return Response({"error": "User not found"})

    if user.otp != otp:
        return Response({"error": "Invalid OTP"})

    if timezone.now() > user.otp_expiry:
        return Response({"error": "OTP expired"})

    # OTP clear
    user.otp = None
    user.otp_expiry = None
    user.save()

    tokens = get_tokens(user)

    return Response({
        "message": "Login successful",
        "tokens": tokens
    })

@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_username(request):
    new_username = request.data.get("username")

    if not new_username:
        return Response({"error": "Username required"})

    request.user.username = new_username
    request.user.save()

    return Response({"message": "Username updated"})