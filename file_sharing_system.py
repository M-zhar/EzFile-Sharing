# File: requirements.txt
Django==4.2.7
djangorestframework==3.14.0
djangorestframework-simplejwt==5.3.0
python-decouple==3.8
cryptography==41.0.7
celery==5.3.4
redis==5.0.1
django-cors-headers==4.3.1
Pillow==10.1.0

# File: manage.py
#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

if __name__ == '__main__':
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'file_sharing.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)

# File: file_sharing/__init__.py
# Empty file for package initialization

# File: file_sharing/settings.py
import os
from pathlib import Path
from decouple import config
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-your-secret-key-here')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=lambda v: [s.strip() for s in v.split(',')])

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'accounts',
    'files',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'file_sharing.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'file_sharing.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.MultiPartParser',
        'rest_framework.parsers.FormParser',
    ],
}

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': False,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JWK_URL': None,
    'LEEWAY': 0,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'JTI_CLAIM': 'jti',
    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': timedelta(days=1),
}

# Email configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@example.com')

# File upload settings
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB

# Celery Configuration (for background tasks)
CELERY_BROKER_URL = config('CELERY_BROKER_URL', default='redis://localhost:6379')
CELERY_RESULT_BACKEND = config('CELERY_RESULT_BACKEND', default='redis://localhost:6379')
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE

# CORS settings
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Security settings
SECURE_DOWNLOAD_URL_EXPIRY = 3600  # 1 hour in seconds

# File: file_sharing/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('accounts.urls')),
    path('api/files/', include('files.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# File: file_sharing/wsgi.py
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'file_sharing.settings')
application = get_wsgi_application()

# File: accounts/__init__.py
# Empty file for package initialization

# File: accounts/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import uuid

class User(AbstractUser):
    USER_TYPE_CHOICES = [
        ('ops', 'Operations User'),
        ('client', 'Client User'),
    ]
    
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES)
    email = models.EmailField(unique=True)
    is_email_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'user_type']
    
    def __str__(self):
        return f"{self.email} ({self.get_user_type_display()})"

class EmailVerificationToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='verification_tokens')
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=24)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def __str__(self):
        return f"Verification token for {self.user.email}"

# File: accounts/serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import User

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'user_type']
        extra_kwargs = {
            'user_type': {'required': True}
        }
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        
        if attrs['user_type'] != 'client':
            raise serializers.ValidationError("Only client users can register through this endpoint.")
        
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            user = authenticate(request=self.context.get('request'),
                              username=email, password=password)
            
            if not user:
                raise serializers.ValidationError('Invalid email or password.')
            
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled.')
            
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError('Must include email and password.')

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'user_type', 'is_email_verified', 'created_at']
        read_only_fields = ['id', 'created_at', 'is_email_verified']

# File: accounts/views.py
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from cryptography.fernet import Fernet
import base64
import json

from .models import User, EmailVerificationToken
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserSerializer

def generate_encrypted_url(data):
    """Generate encrypted URL for email verification"""
    key = base64.urlsafe_b64encode(settings.SECRET_KEY.encode()[:32])
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())
    return base64.urlsafe_b64encode(encrypted_data).decode()

def decrypt_url_data(encrypted_data):
    """Decrypt URL data"""
    try:
        key = base64.urlsafe_b64encode(settings.SECRET_KEY.encode()[:32])
        f = Fernet(key)
        decrypted_data = f.decrypt(base64.urlsafe_b64decode(encrypted_data.encode()))
        return json.loads(decrypted_data.decode())
    except Exception:
        return None

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register(request):
    """Client user registration endpoint"""
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        
        # Create email verification token
        token = EmailVerificationToken.objects.create(user=user)
        
        # Generate encrypted verification URL
        verification_data = {
            'user_id': user.id,
            'token': str(token.token),
            'timestamp': timezone.now().isoformat()
        }
        encrypted_url = generate_encrypted_url(verification_data)
        
        # Send verification email
        verification_url = f"{request.build_absolute_uri('/api/auth/verify-email/')}?token={encrypted_url}"
        
        try:
            send_mail(
                subject='Verify Your Email Address',
                message=f'Please click the following link to verify your email: {verification_url}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
        except Exception as e:
            # Log email sending error but don't fail registration
            pass
        
        return Response({
            'message': 'Registration successful. Please check your email for verification.',
            'encrypted_verification_url': encrypted_url,
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def verify_email(request):
    """Email verification endpoint"""
    encrypted_token = request.GET.get('token')
    if not encrypted_token:
        return Response({'error': 'Verification token is required'}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    # Decrypt token data
    token_data = decrypt_url_data(encrypted_token)
    if not token_data:
        return Response({'error': 'Invalid verification token'}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(id=token_data['user_id'])
        token = EmailVerificationToken.objects.get(
            user=user, 
            token=token_data['token'],
            is_used=False
        )
        
        if token.is_expired():
            return Response({'error': 'Verification token has expired'}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        # Mark email as verified
        user.is_email_verified = True
        user.save()
        
        # Mark token as used
        token.is_used = True
        token.save()
        
        return Response({'message': 'Email verified successfully'}, 
                       status=status.HTTP_200_OK)
        
    except (User.DoesNotExist, EmailVerificationToken.DoesNotExist):
        return Response({'error': 'Invalid verification token'}, 
                       status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login(request):
    """User login endpoint"""
    serializer = UserLoginSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Check if client user has verified email
        if user.user_type == 'client' and not user.is_email_verified:
            return Response({'error': 'Please verify your email before logging in'}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'message': 'Login successful',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'user': UserSerializer(user).data
        }, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def profile(request):
    """Get user profile"""
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

# File: accounts/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('verify-email/', views.verify_email, name='verify-email'),
    path('login/', views.login, name='login'),
    path('profile/', views.profile, name='profile'),
]

# File: accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, EmailVerificationToken

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ['email', 'username', 'user_type', 'is_email_verified', 'is_active', 'created_at']
    list_filter = ['user_type', 'is_email_verified', 'is_active', 'created_at']
    search_fields = ['email', 'username']
    ordering = ['-created_at']
    
    fieldsets = UserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('user_type', 'is_email_verified', 'created_at', 'updated_at')
        }),
    )
    readonly_fields = ['created_at', 'updated_at']

@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'token', 'created_at', 'expires_at', 'is_used']
    list_filter = ['is_used', 'created_at', 'expires_at']
    search_fields = ['user__email', 'token']
    readonly_fields = ['token', 'created_at']

# File: accounts/apps.py
from django.apps import AppConfig

class AccountsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'accounts'

# File: files/__init__.py
# Empty file for package initialization

# File: files/models.py
from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid
import os

def upload_to(instance, filename):
    """Generate file path for uploaded files"""
    ext = filename.split('.')[-1]
    filename = f"{uuid.uuid4().hex}.{ext}"
    return os.path.join('uploads', filename)

class UploadedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    original_filename = models.CharField(max_length=255)
    file = models.FileField(upload_to=upload_to)
    file_size = models.BigIntegerField()
    file_type = models.CharField(max_length=10)
    upload_date = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.original_filename} - {self.uploaded_by.email}"
    
    def get_file_extension(self):
        return self.original_filename.split('.')[-1].lower()
    
    class Meta:
        ordering = ['-upload_date']

class SecureDownloadToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(
                seconds=settings.SECURE_DOWNLOAD_URL_EXPIRY
            )
        super().save(*args, **kwargs)
    
    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def __str__(self):
        return f"Download token for {self.file.original_filename}"

# File: files/serializers.py
from rest_framework import serializers
from .models import UploadedFile

class FileUploadSerializer(serializers.ModelSerializer):
    file = serializers.FileField()
    
    class Meta:
        model = UploadedFile
        fields = ['file', 'original_filename']
        extra_kwargs = {
            'original_filename': {'required': False}
        }
    
    def validate_file(self, value):
        """Validate file type and size"""
        # Check file extension
        allowed_extensions = ['pptx', 'docx', 'xlsx']
        file_extension = value.name.split('.')[-1].lower()
        
        if file_extension not in allowed_extensions:
            raise serializers.ValidationError(
                f"Only {', '.join(allowed_extensions)} files are allowed."
            )
        
        # Check file size (10MB limit)
        if value.size > 10 * 1024 * 1024:
            raise serializers.ValidationError("File size cannot exceed 10MB.")
        
        return value
    
    def create(self, validated_data):
        file_obj = validated_data['file']
        
        # Set original filename if not provided
        if not validated_data.get('original_filename'):
            validated_data['original_filename'] = file_obj.name
        
        # Set file metadata
        validated_data['file_size'] = file_obj.size
        validated_data['file_type'] = file_obj.name.split('.')[-1].lower()
        validated_data['uploaded_by'] = self.context['request'].user
        
        return super().create(validated_data)

class FileListSerializer(serializers.ModelSerializer):
    uploaded_by = serializers.CharField(source='uploaded_by.email', read_only=True)
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = UploadedFile
        fields = [
            'id', 'original_filename', 'file_size', 'file_type', 
            'upload_date', 'uploaded_by', 'file_url'
        ]
    
    def get_file_url(self, obj):
        request = self.context.get('request')
        if request:
            return request.build_absolute_uri(obj.file.url)
        return obj.file.url

# File: files/views.py
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from django.http import HttpResponse, Http404
from django.conf import settings
from django.utils import timezone
from cryptography.fernet import Fernet
import base64
import json
import os

from .models import UploadedFile, SecureDownloadToken
from .serializers import FileUploadSerializer, FileListSerializer

class IsOpsUser(permissions.BasePermission):
    """Custom permission to only allow ops users to upload files"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.user_type == 'ops'

class IsClientUser(permissions.BasePermission):
    """Custom permission to only allow client users to download files"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.user_type == 'client'

def generate_secure_token(data):
    """Generate secure encrypted token"""
    key = base64.urlsafe_b64encode(settings.SECRET_KEY.encode()[:32])
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(data).encode())
    return base64.urlsafe_b64encode(encrypted_data).decode()

def decrypt_token_data(encrypted_data):
    """Decrypt token data"""
    try:
        key = base64.urlsafe_b64encode(settings.SECRET_KEY.encode()[:32])
        f = Fernet(key)
        decrypted_data = f.decrypt(base64.urlsafe_b64decode(encrypted_data.encode()))
        return json.loads(decrypted_data.decode())
    except Exception:
        return None

@api_view(['POST'])
@permission_classes([IsOpsUser])
@parser_classes([MultiPartParser, FormParser])
def upload_file(request):
    """File upload endpoint for ops users"""
    serializer = FileUploadSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        file_obj = serializer.save()
        return Response({
            'message': 'File uploaded successfully',
            'file_id': str(file_obj.id),
            'filename': file_obj.original_filename,
            'file_size': file_obj.file_size,
            'upload_date': file_obj.upload_date
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsClientUser])
def list_files(request):
    """List all uploaded files for client users"""
    files = UploadedFile.objects.filter(is_active=True)
    serializer = FileListSerializer(files, many=True, context={'request': request})
    return Response({
        'message': 'Files retrieved successfully',
        'files': serializer.data
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsClientUser])
def download_file(request, file_id):
    """Generate secure download URL for client users"""
    try:
        file_obj = UploadedFile.objects.get(id=file_id, is_active=True)
    except UploadedFile.DoesNotExist:
        return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)
    
    # Generate secure download token
    token_data = {
        'file_id': str(file_obj.id),
        'user_id': request.user.id,
        'timestamp': timezone.now().isoformat()
    }
    encrypted_token = generate_secure_token(token_data)
    
    # Save token to database
    download_token = SecureDownloadToken.objects.create(
        file=file_obj,
        user=request.user,
        token=encrypted_token
    )
    
    # Generate secure download URL
    download_url = request.build_absolute_uri(
        f'/api/files/secure-download/{encrypted_token}/'
    )
    
    return Response({
        'download_link': download_url,
        'message': 'success',
        'expires_at': download_token.expires_at,
        'file_info': {
            'filename': file_obj.original_filename,
            'file_size': file_obj.file_size,
            'file_type': file_obj.file_type
        }
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def secure_download(request, token):
    """Secure file download endpoint"""
    # Decrypt token data
    token_data = decrypt_token_data(token)
    if not token_data:
        return Response({'error': 'Invalid download token'}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Verify token in database
        download_token = SecureDownloadToken.objects.get(
            token=token,
            is_used=False
        )
        
        if download_token.is_expired():
            return Response({'error': 'Download token has expired'}, 
                           status=status.HTTP_400_BAD_REQUEST)
        
        # Verify user access (only client users can download)
        if not request.user.is_authenticated or request.user.user_type != 'client':
            return Response({'error': 'Access denied. Only client users can download files.'}, 
                           status=status.HTTP_403_FORBIDDEN)
        
        # Verify user owns the token
        if request.user.id != download_token.user.id:
            return Response({'error': 'Access denied. Invalid user.'}, 
                           status=status.HTTP_403_FORBIDDEN)
        
        # Get file
        file_obj = download_token.file
        
        if not file_obj.is_active:
            return Response({'error': 'File is no longer available'}, 
                           status=status.HTTP_404_NOT_FOUND)
        
        # Mark token as used
        download_token.is_used = True
        download_token.save()
        
        # Serve file
        if os.path.exists(file_obj.file.path):
            with open(file_obj.file.path, 'rb') as f:
                response = HttpResponse(f.read(), content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename="{file_obj.original_filename}"'
                response['Content-Length'] = file_obj.file_size
                return response
        else:
            return Response({'error': 'File not found on server'}, 
                           status=status.HTTP_404_NOT_FOUND)
        
    except SecureDownloadToken.DoesNotExist:
        return Response({'error': 'Invalid download token'}, 
                       status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({'error': 'An error occurred while downloading the file'}, 
                       status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# File: files/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('upload/', views.upload_file, name='upload-file'),
    path('list/', views.list_files, name='list-files'),
    path('download-file/<uuid:file_id>/', views.download_file, name='download-file'),
    path('secure-download/<str:token>/', views.secure_download, name='secure-download'),
]

# File: files/admin.py
from django.contrib import admin
from .models import UploadedFile, SecureDownloadToken

@admin.register(UploadedFile)
class UploadedFileAdmin(admin.ModelAdmin):
    list_display = ['original_filename', 'uploaded_by', 'file_type', 'file_size', 'upload_date', 'is_active']
    list_filter = ['file_type', 'upload_date', 'is_active', 'uploaded_by__user_type']
    search_fields = ['original_filename', 'uploaded_by__email']
    readonly_fields = ['id', 'upload_date', 'file_size']
    ordering = ['-upload_date']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('uploaded_by')

@admin.register(SecureDownloadToken)
class SecureDownloadTokenAdmin(admin.ModelAdmin):
    list_display = ['file', 'user', 'created_at', 'expires_at', 'is_used']
    list_filter = ['is_used', 'created_at', 'expires_at']
    search_fields = ['file__original_filename', 'user__email']
    readonly_fields = ['id', 'token', 'created_at']
    ordering = ['-created_at']
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('file', 'user')

# File: files/apps.py
from django.apps import AppConfig

class FilesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'files'

# File: .env.example
# Copy this file to .env and fill in your actual values

# Django Settings
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database (if using PostgreSQL instead of SQLite)
# DATABASE_URL=postgresql://user:password@localhost:5432/file_sharing_db

# Email Settings
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=noreply@yourapp.com

# Celery Settings (for background tasks)
CELERY_BROKER_URL=redis://localhost:6379
CELERY_RESULT_BACKEND=redis://localhost:6379

# File: celery_app.py
from celery import Celery
import os
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'file_sharing.settings')

app = Celery('file_sharing')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')

# File: files/permissions.py
from rest_framework import permissions

class IsOpsUserOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow ops users to create/edit files,
    but allow client users to read.
    """
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated and request.user.user_type == 'client'
        return request.user.is_authenticated and request.user.user_type == 'ops'

class IsClientUserOnly(permissions.BasePermission):
    """
    Custom permission to only allow client users.
    """
    def has_permission(self, request, view):
        return (request.user.is_authenticated and 
                request.user.user_type == 'client' and 
                request.user.is_email_verified)

# File: files/utils.py
import os
import mimetypes
from django.conf import settings
from django.core.exceptions import ValidationError

def validate_file_type(file):
    """Validate uploaded file type"""
    allowed_extensions = ['pptx', 'docx', 'xlsx']
    allowed_mime_types = [
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',  # pptx
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',    # docx
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',         # xlsx
    ]
    
    # Check file extension
    file_extension = file.name.split('.')[-1].lower()
    if file_extension not in allowed_extensions:
        raise ValidationError(f"File type '{file_extension}' is not allowed. Only {', '.join(allowed_extensions)} files are permitted.")
    
    # Check MIME type
    mime_type, _ = mimetypes.guess_type(file.name)
    if mime_type not in allowed_mime_types:
        raise ValidationError(f"File MIME type '{mime_type}' is not allowed.")
    
    return True

def get_file_size_display(size_bytes):
    """Convert file size to human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

# File: files/tasks.py
from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)

@shared_task
def send_file_upload_notification(file_id, uploader_email, filename):
    """Send notification email when file is uploaded"""
    try:
        subject = f"New File Uploaded: {filename}"
        message = f"""
        A new file has been uploaded to the file sharing system.
        
        File: {filename}
        Uploaded by: {uploader_email}
        Upload time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        File ID: {file_id}
        """
        
        # Send to admin or configured recipients
        recipient_list = ['admin@yourapp.com']  # Configure as needed
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=recipient_list,
            fail_silently=False,
        )
        
        logger.info(f"Upload notification sent for file {file_id}")
        
    except Exception as e:
        logger.error(f"Failed to send upload notification: {str(e)}")

@shared_task
def cleanup_expired_tokens():
    """Clean up expired download tokens"""
    from .models import SecureDownloadToken
    
    try:
        expired_tokens = SecureDownloadToken.objects.filter(
            expires_at__lt=timezone.now()
        )
        count = expired_tokens.count()
        expired_tokens.delete()
        
        logger.info(f"Cleaned up {count} expired download tokens")
        return count
        
    except Exception as e:
        logger.error(f"Failed to cleanup expired tokens: {str(e)}")
        return 0

# File: files/management/__init__.py
# Empty file for package initialization

# File: files/management/commands/__init__.py
# Empty file for package initialization

# File: files/management/commands/cleanup_expired_tokens.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from files.models import SecureDownloadToken

class Command(BaseCommand):
    help = 'Clean up expired download tokens'

    def handle(self, *args, **options):
        expired_tokens = SecureDownloadToken.objects.filter(
            expires_at__lt=timezone.now()
        )
        count = expired_tokens.count()
        expired_tokens.delete()
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully cleaned up {count} expired download tokens')
        )

# File: files/management/commands/create_ops_user.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

User = get_user_model()

class Command(BaseCommand):
    help = 'Create an operations user'

    def add_arguments(self, parser):
        parser.add_argument('--email', required=True, help='Email address for the ops user')
        parser.add_argument('--username', required=True, help='Username for the ops user')
        parser.add_argument('--password', required=True, help='Password for the ops user')

    def handle(self, *args, **options):
        email = options['email']
        username = options['username']
        password = options['password']
        
        if User.objects.filter(email=email).exists():
            self.stdout.write(
                self.style.ERROR(f'User with email {email} already exists')
            )
            return
        
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                user_type='ops',
                is_email_verified=True  # Ops users don't need email verification
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully created ops user: {email}')
            )
            
        except ValidationError as e:
            self.stdout.write(
                self.style.ERROR(f'Error creating user: {e}')
            )

# File: api_documentation.md
# File Sharing System API Documentation

## Authentication
All authenticated endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

## Endpoints

### Authentication Endpoints

#### 1. Client User Registration
- **URL**: `/api/auth/register/`
- **Method**: `POST`
- **Permission**: Public
- **Request Body**:
```json
{
    "username": "client_user",
    "email": "client@example.com",
    "password": "securepassword123",
    "password_confirm": "securepassword123",
    "user_type": "client"
}
```
- **Response**:
```json
{
    "message": "Registration successful. Please check your email for verification.",
    "encrypted_verification_url": "encrypted_url_here",
    "user": {
        "id": 1,
        "username": "client_user",
        "email": "client@example.com",
        "user_type": "client",
        "is_email_verified": false,
        "created_at": "2024-01-01T12:00:00Z"
    }
}
```

#### 2. Email Verification
- **URL**: `/api/auth/verify-email/`
- **Method**: `GET`
- **Permission**: Public
- **Query Parameters**: `?token=<encrypted_token>`
- **Response**:
```json
{
    "message": "Email verified successfully"
}
```

#### 3. User Login
- **URL**: `/api/auth/login/`
- **Method**: `POST`
- **Permission**: Public
- **Request Body**:
```json
{
    "email": "user@example.com",
    "password": "password123"
}
```
- **Response**:
```json
{
    "message": "Login successful",
    "access_token": "jwt_access_token",
    "refresh_token": "jwt_refresh_token",
    "user": {
        "id": 1,
        "username": "user",
        "email": "user@example.com",
        "user_type": "client",
        "is_email_verified": true,
        "created_at": "2024-01-01T12:00:00Z"
    }
}
```

#### 4. Get User Profile
- **URL**: `/api/auth/profile/`
- **Method**: `GET`
- **Permission**: Authenticated users
- **Response**:
```json
{
    "id": 1,
    "username": "user",
    "email": "user@example.com",
    "user_type": "client",
    "is_email_verified": true,
    "created_at": "2024-01-01T12:00:00Z"
}
```

### File Management Endpoints

#### 5. Upload File (Operations Users Only)
- **URL**: `/api/files/upload/`
- **Method**: `POST`
- **Permission**: Operations users only
- **Content-Type**: `multipart/form-data`
- **Request Body**:
```
file: <file_object>  (Required - must be .pptx, .docx, or .xlsx)
original_filename: <string>  (Optional - will use file name if not provided)
```
- **Response**:
```json
{
    "message": "File uploaded successfully",
    "file_id": "uuid-string",
    "filename": "document.docx",
    "file_size": 1024000,
    "upload_date": "2024-01-01T12:00:00Z"
}
```

#### 6. List Files (Client Users Only)
- **URL**: `/api/files/list/`
- **Method**: `GET`
- **Permission**: Client users only
- **Response**:
```json
{
    "message": "Files retrieved successfully",
    "files": [
        {
            "id": "uuid-string",
            "original_filename": "document.docx",
            "file_size": 1024000,
            "file_type": "docx",
            "upload_date": "2024-01-01T12:00:00Z",
            "uploaded_by": "ops@example.com",
            "file_url": "http://localhost:8000/media/uploads/filename.docx"
        }
    ]
}
```

#### 7. Get Download Link (Client Users Only)
- **URL**: `/api/files/download-file/<file_id>/`
- **Method**: `GET`
- **Permission**: Client users only
- **Response**:
```json
{
    "download_link": "http://localhost:8000/api/files/secure-download/encrypted_token/",
    "message": "success",
    "expires_at": "2024-01-01T13:00:00Z",
    "file_info": {
        "filename": "document.docx",
        "file_size": 1024000,
        "file_type": "docx"
    }
}
```

#### 8. Secure File Download
- **URL**: `/api/files/secure-download/<encrypted_token>/`
- **Method**: `GET`
- **Permission**: Client users only (verified through token)
- **Response**: File download (binary data)

## Error Responses

All endpoints return appropriate HTTP status codes and error messages:

```json
{
    "error": "Error message describing what went wrong"
}
```

Common status codes:
- `200`: Success
- `201`: Created successfully
- `400`: Bad request (validation errors)
- `401`: Unauthorized (missing or invalid token)
- `403`: Forbidden (insufficient permissions)
- `404`: Not found
- `500`: Internal server error

## Setup Instructions

1. **Install Dependencies**:
```bash
pip install -r requirements.txt
```

2. **Environment Setup**:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Database Setup**:
```bash
python manage.py makemigrations
python manage.py migrate
```

4. **Create Operations User**:
```bash
python manage.py create_ops_user --email ops@example.com --username ops_user --password secure123
```

5. **Run Server**:
```bash
python manage.py runserver
```

6. **Optional - Setup Celery for Background Tasks**:
```bash
# Terminal 1: Start Redis
redis-server

# Terminal 2: Start Celery Worker
celery -A file_sharing worker --loglevel=info

# Terminal 3: Start Celery Beat (for periodic tasks)
celery -A file_sharing beat --loglevel=info
```

## Security Features

1. **JWT Authentication**: Secure token-based authentication
2. **File Type Validation**: Only .pptx, .docx, .xlsx files allowed
3. **User Role Separation**: Operations users can only upload, Client users can only download
4. **Email Verification**: Client users must verify email before accessing files
5. **Encrypted Download URLs**: Temporary, encrypted URLs for secure file downloads
6. **Token Expiration**: Download tokens expire after 1 hour
7. **File Size Limits**: Maximum 10MB per file
8. **Access Control**: Download URLs can only be accessed by the requesting client user

## File Structure
```
file_sharing/
├── manage.py
├── requirements.txt
├── .env.example
├── celery_app.py
├── file_sharing/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── accounts/
│   ├── __init__.py
│   ├── models.py
│   ├── serializers.py
│   ├── views.py
│   ├── urls.py
│   ├── admin.py
│   └── apps.py
└── files/
    ├── __init__.py
    ├── models.py
    ├── serializers.py
    ├── views.py
    ├── urls.py
    ├── admin.py
    ├── apps.py
    ├── permissions.py
    ├── utils.py
    ├── tasks.py
    └── management/
        ├── __init__.py
        └── commands/
            ├── __init__.py
            ├── cleanup_expired_tokens.py
            └── create_ops_user.py
```