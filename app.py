"""
Student Account Portal - main Flask application.

Provides:
    - User registration / login / logout (Flask-Login + hashed passwords)
    - Student profile management
    - Scholarship application form with file uploads (valid ID +
      optional supporting documents), validated by extension and size
    - Secure, per-user document download (no insecure direct object access)

Run locally with:
    python app.py
"""

import os
import uuid
from functools import wraps

from flask import (
    Flask, render_template, redirect, url_for, flash, request, abort,
    send_from_directory
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)
from flask_wtf import CSRFProtect
from werkzeug.utils import secure_filename

from config import Config
from models import db, User, Student, ScholarshipApplication, Document
from forms import (
    RegistrationForm, LoginForm, StudentProfileForm, ScholarshipForm, AdminActionForm
)


def create_app():
    """
    Application factory: builds and configures the Flask app.

    Loads configuration from Config, initializes SQLAlchemy,
    CSRF protection, and Flask-Login, ensures the instance/ and
    uploads/ directories and database tables exist, and registers
    every route on the app.

    Parameters:
        None.

    Returns:
        Flask: The fully configured Flask application instance.
    """
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)

    # Ensure required directories exist before anything tries to write to them.
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    CSRFProtect(app)  # Enables CSRF tokens for every FlaskForm automatically.

    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        """
        Flask-Login callback that reloads a User object from the ID
        stored in the encrypted session cookie on every request.

        Parameters:
            user_id (str): The user's primary key, as a string.

        Returns:
            User | None: The matching User row, or None if not found.
        """
        return User.query.get(int(user_id))

    def admin_required(view_func):
        """
        Route decorator: only allow access to users flagged is_admin.
        Must be paired with @login_required (checked first below).
        """
        @wraps(view_func)
        @login_required
        def wrapped(*args, **kwargs):
            if not current_user.is_admin:
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped

    def allowed_file(filename):
        """
        Check whether a filename's extension is in the configured
        whitelist of permitted upload types.

        Parameters:
            filename (str): The original filename submitted by the client.

        Returns:
            bool: True if the extension is allowed, False otherwise
                (also False if there is no extension at all).
        """
        return (
            '.' in filename
            and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
        )

    def save_uploaded_file(file_storage):
        """
        Safely persist one uploaded file to disk.

        The original filename is sanitized with secure_filename() purely
        for display purposes; the file is actually saved under a fresh
        random UUID-based name so that user-supplied names can never
        cause a path-traversal or filename-collision issue. Overall
        request size (and therefore each file) is already capped by
        MAX_CONTENT_LENGTH, which Flask enforces before this code runs.

        Parameters:
            file_storage (werkzeug.datastructures.FileStorage): The
                incoming file object from a submitted multipart form.

        Returns:
            tuple(str | None, str | None): (original_filename,
                stored_filename) on success, or (None, None) if the file
                is missing or its extension is not allowed.
        """
        if not file_storage or file_storage.filename == '':
            return None, None
        if not allowed_file(file_storage.filename):
            return None, None

        original_filename = secure_filename(file_storage.filename)
        extension = original_filename.rsplit('.', 1)[1].lower()
        stored_filename = f'{uuid.uuid4().hex}.{extension}'
        file_storage.save(os.path.join(app.config['UPLOAD_FOLDER'], stored_filename))
        return original_filename, stored_filename

    # -----------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------

    @app.route('/')
    def index():
        """
        Landing route. Sends authenticated users to their dashboard and
        everyone else to the login page.

        Returns:
            Response: A redirect to 'dashboard' or 'login'.
        """
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """
        Display and process the registration form.

        On a valid POST, checks that the username and email are not
        already taken, hashes the submitted password with Werkzeug, and
        creates the new User row.

        Returns:
            Response: The rendered registration page, or a redirect to
                'login' once registration succeeds.
        """
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        form = RegistrationForm()
        if form.validate_on_submit():
            duplicate = User.query.filter(
                (User.username == form.username.data) | (User.email == form.email.data)
            ).first()
            if duplicate:
                flash('That username or email is already registered.', 'danger')
                return render_template('register.html', form=form)

            new_user = User(username=form.username.data, email=form.email.data)
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
        Display and process the login form.

        On a valid POST, looks up the user by username and verifies the
        submitted password against the stored hash before starting a
        Flask-Login session.

        Returns:
            Response: The rendered login page, or a redirect to
                'dashboard' (or the originally requested page) once
                authentication succeeds.
        """
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))

        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user is not None and user.check_password(form.password.data):
                login_user(user)
                flash('Logged in successfully.', 'success')
                next_page = request.args.get('next')
                # Only honor relative "next" paths to avoid open-redirects.
                if next_page and not next_page.startswith('/'):
                    next_page = None
                return redirect(next_page or url_for('dashboard'))
            flash('Invalid username or password.', 'danger')

        return render_template('login.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        """
        End the current user's session.

        Returns:
            Response: A redirect to the login page.
        """
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('login'))

    @app.route('/dashboard', methods=['GET', 'POST'])
    @login_required
    def dashboard():
        """
        Authenticated home page: lets the student create or update their
        profile and lists their past scholarship applications.

        On a valid POST, creates the Student row if it doesn't exist yet
        (checking the student number is unique) or updates the existing
        one.

        Returns:
            Response: The rendered dashboard page with the profile form
                and the student's list of applications.
        """
        student = current_user.student
        form = StudentProfileForm(obj=student)

        if form.validate_on_submit():
            duplicate_number = Student.query.filter(
                Student.student_number == form.student_number.data,
                Student.user_id != current_user.id
            ).first()
            if duplicate_number:
                flash('That student number is already in use.', 'danger')
                return render_template(
                    'dashboard.html', form=form, student=student,
                    applications=student.scholarships if student else []
                )

            if student is None:
                student = Student(user_id=current_user.id)
                db.session.add(student)

            student.full_name = form.full_name.data
            student.student_number = form.student_number.data
            student.program = form.program.data
            student.year_level = form.year_level.data
            student.contact_number = form.contact_number.data
            student.address = form.address.data
            db.session.commit()

            flash('Profile saved.', 'success')
            return redirect(url_for('dashboard'))

        applications = student.scholarships if student else []
        return render_template(
            'dashboard.html', form=form, student=student, applications=applications
        )

    @app.route('/scholarship/apply', methods=['GET', 'POST'])
    @login_required
    def scholarship_apply():
        """
        Display and process the scholarship application form, including
        the required valid-ID upload and any optional supporting
        documents.

        Files are validated by extension (via allowed_file /
        FileAllowed) and by overall size (via MAX_CONTENT_LENGTH), saved
        to disk under randomized names, and linked to the new
        ScholarshipApplication through Document rows.

        Returns:
            Response: The rendered scholarship form, or a redirect to
                'dashboard' once the application is submitted.
        """
        student = current_user.student
        if student is None:
            flash('Please complete your student profile before applying.', 'warning')
            return redirect(url_for('dashboard'))

        form = ScholarshipForm()
        if form.validate_on_submit():
            application = ScholarshipApplication(
                student_id=student.id,
                scholarship_name=form.scholarship_name.data,
                gpa=form.gpa.data,
                reason=form.reason.data,
            )
            db.session.add(application)
            db.session.flush()  # populate application.id before commit

            original_name, stored_name = save_uploaded_file(form.valid_id.data)
            if not stored_name:
                db.session.rollback()
                flash('Valid ID upload failed or has an invalid file type.', 'danger')
                return render_template('scholarship_form.html', form=form)

            db.session.add(Document(
                scholarship_id=application.id,
                document_type='Valid ID',
                original_filename=original_name,
                stored_filename=stored_name,
            ))

            for file_storage in request.files.getlist('supporting_documents'):
                original_name, stored_name = save_uploaded_file(file_storage)
                if stored_name:
                    db.session.add(Document(
                        scholarship_id=application.id,
                        document_type='Supporting Document',
                        original_filename=original_name,
                        stored_filename=stored_name,
                    ))

            db.session.commit()
            flash('Scholarship application submitted.', 'success')
            return redirect(url_for('dashboard'))

        return render_template('scholarship_form.html', form=form)

    @app.route('/uploads/<int:document_id>')
    @login_required
    def download_document(document_id):
        """
        Serve one uploaded document, restricted to the student who owns
        the parent scholarship application. This prevents insecure
        direct object access (one user reading another user's files by
        guessing/incrementing an ID).

        Parameters:
            document_id (int): Primary key of the requested Document row.

        Returns:
            Response: The file as an attachment download; aborts with
                404 if the document doesn't exist, or 403 if it belongs
                to a different user.
        """
        document = Document.query.get_or_404(document_id)
        owner_user_id = document.scholarship.student.user_id
        if owner_user_id != current_user.id:
            abort(403)
        return send_from_directory(
            app.config['UPLOAD_FOLDER'], document.stored_filename,
            as_attachment=True, download_name=document.original_filename
        )

    @app.route('/admin')
    @admin_required
    def admin_dashboard():
        """
        Admin overview: portal-wide stats plus every scholarship
        application (newest first) with quick approve/reject actions.

        Returns:
            Response: The rendered admin dashboard page.
        """
        applications = (
            ScholarshipApplication.query
            .join(Student)
            .order_by(ScholarshipApplication.submitted_at.desc())
            .all()
        )
        stats = {
            'students': Student.query.count(),
            'applications': len(applications),
            'pending': sum(1 for a in applications if a.status == 'Pending'),
            'approved': sum(1 for a in applications if a.status == 'Approved'),
            'rejected': sum(1 for a in applications if a.status == 'Rejected'),
        }
        return render_template(
            'admin_dashboard.html', applications=applications, stats=stats,
            form=AdminActionForm()
        )

    @app.route('/admin/application/<int:application_id>/status', methods=['POST'])
    @admin_required
    def admin_update_status(application_id):
        """
        Set a scholarship application's status to Approved or Rejected.

        Parameters:
            application_id (int): Primary key of the target application.

        Returns:
            Response: Redirect back to the admin dashboard.
        """
        form = AdminActionForm()
        if not form.validate_on_submit():
            abort(400)

        new_status = request.form.get('status')
        if new_status not in ('Approved', 'Rejected', 'Pending'):
            abort(400)

        application = ScholarshipApplication.query.get_or_404(application_id)
        application.status = new_status
        db.session.commit()
        flash(f'Application for "{application.scholarship_name}" marked {new_status}.', 'success')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/document/<int:document_id>')
    @admin_required
    def admin_download_document(document_id):
        """
        Let an admin download any student's uploaded document
        (unlike the student-facing download_document route, which is
        restricted to the owning student).

        Parameters:
            document_id (int): Primary key of the requested Document row.

        Returns:
            Response: The file as an attachment download.
        """
        document = Document.query.get_or_404(document_id)
        return send_from_directory(
            app.config['UPLOAD_FOLDER'], document.stored_filename,
            as_attachment=True, download_name=document.original_filename
        )

    @app.cli.command('create-admin')
    def create_admin():
        """
        CLI helper: `flask create-admin` promotes an existing username
        to admin (prompts for the username interactively).
        """
        username = input('Username to promote to admin: ').strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            print(f'No user named "{username}" found.')
            return
        user.is_admin = True
        db.session.commit()
        print(f'"{username}" is now an admin.')

    @app.errorhandler(413)
    def file_too_large(_error):
        """
        Handle uploads that exceed MAX_CONTENT_LENGTH.

        Parameters:
            _error: The RequestEntityTooLarge exception Flask raised
                (unused; message is generic by design).

        Returns:
            tuple(Response, int): A redirect back to the scholarship
                form plus HTTP 413 status.
        """
        flash('Upload too large. Maximum total upload size is 5 MB.', 'danger')
        return redirect(url_for('scholarship_apply')), 413

    @app.errorhandler(403)
    def forbidden(_error):
        """
        Render a plain 403 response for forbidden access attempts (e.g.
        trying to download another student's document).

        Parameters:
            _error: The Forbidden exception Flask raised (unused).

        Returns:
            tuple(str, int): A short message and HTTP 403 status.
        """
        return 'Forbidden: you do not have access to this resource.', 403

    with app.app_context():
        db.create_all()

    return app


app = create_app()

if __name__ == '__main__':
    # debug=True auto-reloads and shows tracebacks; turn OFF in production.
    app.run(debug=True)
