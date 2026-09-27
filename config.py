import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """
    Central application configuration.

    Holds Flask core settings, the database URI, upload-folder path,
    allowed file extensions, maximum upload size, and cookie/session
    security flags. Keeping all of this in one place makes it easy to
    override values (e.g. via environment variables) for production.
    """

    # Secret key used to sign session cookies and CSRF tokens.
    # IMPORTANT: override this with a strong random value in production,
    # e.g. via `export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")`
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-change-this-secret-key')

    # SQLite database stored inside the instance/ folder (kept outside
    # version control by convention).
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'student_portal.db')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File upload settings.
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'pdf', 'docx'}
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB hard limit per request

    # Cookie / session hardening.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False  # set True once served over HTTPS
    REMEMBER_COOKIE_HTTPONLY = True

    # Flask-WTF CSRF protection is on by default when CSRFProtect is
    # initialized in app.py; this flag documents that intent.
    WTF_CSRF_ENABLED = True
