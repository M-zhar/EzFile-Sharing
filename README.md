# EzFile-Sharing
This is simole file sharing platform given as assigment by the EZ for backend role.

Secure File Sharing System
A Django-based secure file sharing system with role-based access control, supporting Operations users (file uploaders) and Client users (file downloaders) with encrypted download URLs.
🚀 Features
🔐 Security Features

JWT Authentication - Secure token-based authentication
Role-Based Access Control - Separate permissions for Operations and Client users
Email Verification - Client users must verify email before accessing files
Encrypted Download URLs - Temporary, secure download links with expiration
File Type Validation - Only .pptx, .docx, .xlsx files allowed
File Size Limits - Maximum 10MB per file
Token Expiration - Download tokens automatically expire after 1 hour

👥 User Management

Operations Users - Can login and upload files only
Client Users - Can register, verify email, login, list files, and download files
Email Verification System - Automated email verification for client users

📁 File Management

Secure File Upload - With comprehensive validation
File Listing - View all available files with metadata
Encrypted Downloads - Generate secure, temporary download URLs
Automatic Cleanup - Expired tokens are automatically cleaned up

🏗️ System Architecture
file_sharing/
├── manage.py
├── requirements.txt
├── .env.example
├── celery_app.py
├── file_sharing/          # Main project configuration
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── accounts/              # User authentication & management
│   ├── models.py
│   ├── serializers.py
│   ├── views.py
│   ├── urls.py
│   └── admin.py
└── files/                 # File management & downloads
    ├── models.py
    ├── serializers.py
    ├── views.py
    ├── urls.py
    ├── admin.py
    ├── permissions.py
    ├── utils.py
    ├── tasks.py
    └── management/
        └── commands/
            ├── cleanup_expired_tokens.py
            └── create_ops_user.py
🛠️ Installation & Setup
Prerequisites

Python 3.8+
Redis (for Celery tasks)
SQLite (default) or PostgreSQL

1. Clone the Repository
bashgit clone <your-repo-url>
cd file_sharing
2. Create Virtual Environment
bashpython -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
3. Install Dependencies
bashpip install -r requirements.txt
4. Environment Configuration
bashcp .env.example .env
Edit .env file with your configuration:
envSECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=noreply@yourapp.com

# Redis Configuration (for Celery)
CELERY_BROKER_URL=redis://localhost:6379
CELERY_RESULT_BACKEND=redis://localhost:6379
5. Database Setup
bashpython manage.py makemigrations
python manage.py migrate
6. Create Operations User
bashpython manage.py create_ops_user --email ops@example.com --username ops_user --password secure123
7. Create Superuser (Optional)
bashpython manage.py createsuperuser
8. Run the Server
bashpython manage.py runserver
The application will be available at http://localhost:8000
🔧 Optional: Celery Setup (Background Tasks)
Start Redis Server
bashredis-server
Start Celery Worker
bashcelery -A file_sharing worker --loglevel=info
Start Celery Beat (Periodic Tasks)
bashcelery -A file_sharing beat --loglevel=info
📚 API Documentation
Base URL
http://localhost:8000/api/
Authentication
All authenticated endpoints require a Bearer token:
Authorization: Bearer <your_jwt_token>
🔐 Authentication Endpoints
1. Client User Registration
httpPOST /api/auth/register/
Content-Type: application/json

{
    "username": "client_user",
    "email": "client@example.com",
    "password": "securepassword123",
    "password_confirm": "securepassword123",
    "user_type": "client"
}
Response:
json{
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
2. Email Verification
httpGET /api/auth/verify-email/?token=<encrypted_token>
3. User Login
httpPOST /api/auth/login/
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "password123"
}
Response:
json{
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
📁 File Management Endpoints
4. Upload File (Operations Users Only)
httpPOST /api/files/upload/
Content-Type: multipart/form-data
Authorization: Bearer <ops_user_token>

file: <file_object>  (Required - must be .pptx, .docx, or .xlsx)
original_filename: <string>  (Optional)
Response:
json{
    "message": "File uploaded successfully",
    "file_id": "uuid-string",
    "filename": "document.docx",
    "file_size": 1024000,
    "upload_date": "2024-01-01T12:00:00Z"
}
5. List Files (Client Users Only)
httpGET /api/files/list/
Authorization: Bearer <client_user_token>
Response:
json{
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
6. Get Download Link (Client Users Only)
httpGET /api/files/download-file/<file_id>/
Authorization: Bearer <client_user_token>
Response:
json{
    "download_link": "http://localhost:8000/api/files/secure-download/encrypted_token/",
    "message": "success",
    "expires_at": "2024-01-01T13:00:00Z",
    "file_info": {
        "filename": "document.docx",
        "file_size": 1024000,
        "file_type": "docx"
    }
}
7. Secure File Download
httpGET /api/files/secure-download/<encrypted_token>/
Authorization: Bearer <client_user_token>
Response: File download (binary data)
🔒 Security Implementation
File Access Control

Operations Users: Can only upload files (.pptx, .docx, .xlsx)
Client Users: Can only download files through encrypted URLs
No Direct Access: Files cannot be accessed directly without proper authentication

Download URL Security

Encrypted Tokens: Download URLs contain encrypted tokens using Fernet encryption
User Verification: Only the requesting client user can access their download URLs
Token Expiration: Download tokens expire after 1 hour
One-Time Use: Tokens are marked as used after successful download

Data Protection

JWT Tokens: Secure authentication with configurable expiration
Password Validation: Strong password requirements enforced
Email Verification: Client users must verify email before accessing files
File Validation: Comprehensive file type and size validation

🗄️ Database Models
User Model

Extended Django User model with user_type field
Supports Operations and Client user types
Email verification tracking

UploadedFile Model

Stores file metadata and references
UUID primary keys for security
File type and size validation

SecureDownloadToken Model

Manages encrypted download tokens
Automatic expiration handling
User and file relationship tracking

EmailVerificationToken Model

Handles email verification process
Token expiration and usage tracking

🔧 Management Commands
Create Operations User
bashpython manage.py create_ops_user --email ops@example.com --username ops_user --password secure123
Cleanup Expired Tokens
bashpython manage.py cleanup_expired_tokens
🚀 Production Deployment
Environment Variables
Set the following in production:
envSECRET_KEY=your-production-secret-key
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
DATABASE_URL=postgresql://user:password@localhost:5432/file_sharing_db
Database Configuration
For PostgreSQL:
pythonDATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'file_sharing_db',
        'USER': 'your_db_user',
        'PASSWORD': 'your_db_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
Static Files
bashpython manage.py collectstatic
Security Checklist

 Set DEBUG=False in production
 Configure proper ALLOWED_HOSTS
 Use HTTPS in production
 Set up proper email configuration
 Configure Redis for Celery
 Set up proper file storage (e.g., AWS S3)
 Configure proper logging
 Set up database backups

🐛 Troubleshooting
Common Issues
Email Verification Not Working

Check email configuration in .env
Verify SMTP settings
Check spam/junk folders

File Upload Fails

Verify file type is .pptx, .docx, or .xlsx
Check file size (max 10MB)
Ensure Operations user is logged in

Download Links Not Working

Check token expiration
Verify client user authentication
Ensure token hasn't been used already

Celery Tasks Not Running

Verify Redis is running
Check Celery worker is started
Verify CELERY_BROKER_URL configuration

📝 Testing
Run Tests
bashpython manage.py test
Test API Endpoints
Use tools like Postman or curl to test the API endpoints with the provided examples.
🤝 Contributing

Fork the repository
Create a feature branch
Make your changes
Add tests for new features
Submit a pull request

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
🆘 Support
For support and questions:

Create an issue in the GitHub repository
Check the troubleshooting section
Review the API documentation

📋 Changelog
v1.0.0

Initial release
JWT authentication system
Role-based access control
Secure file upload and download
Email verification system
Encrypted download URLs
