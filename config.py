import os

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_NAME = os.environ.get('DB_NAME', 'admission_db')
DB_USER = os.environ.get('DB_USER', 'admission_user')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'student@123')
UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'static/uploads/student_images')
ALLOWED_IMAGE_EXT = {'png','jpg','jpeg','gif'}
