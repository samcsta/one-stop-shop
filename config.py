import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-for-ford-red-team-garage'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
    WORDLISTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wordlists')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload
