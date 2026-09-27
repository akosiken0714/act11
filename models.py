"""
Database models for the Student Account Portal.

Tables:
    User                  - login credentials (one per person who can log in).
    Student               - profile info, one-to-one with User.
    ScholarshipApplication - a single scholarship application, many-to-one with Student.
    Document              - metadata for an uploaded file, many-to-one with
                            ScholarshipApplication.

Passwords are never stored in plaintext: User.set_password() hashes them
with Werkzeug's PBKDF2-based generate_password_hash(), and
User.check_password() verifies with check_password_hash(). All foreign
keys are enforced by SQLAlchemy, and all queries built from these models
use parameterized ORM queries (no raw/string-built SQL anywhere).
"""

from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model, UserMixin):
    """
    Login credentials and account metadata for a portal user (student).

    Columns:
        id (int): Primary key.
        username (str): Unique login name.
        email (str): Unique email address.
        password_hash (str): Werkzeug password hash (never plaintext).
        created_at (datetime): Account creation timestamp (UTC).

    Relationships:
        student: One-to-one link to this user's Student profile row.
            Deleting a User cascades and deletes their Student profile.
    """

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    student = db.relationship(
        'Student', backref='user', uselist=False, cascade='all, delete-orphan'
    )

    def set_password(self, raw_password):
        """
        Hash a plaintext password and store the hash on this instance.

        Parameters:
            raw_password (str): The plaintext password submitted by the user.

        Returns:
            None. Sets self.password_hash in place.
        """
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        """
        Verify a plaintext password against the stored hash.

        Parameters:
            raw_password (str): The plaintext password submitted at login.

        Returns:
            bool: True if it matches the stored hash, False otherwise.
        """
        return check_password_hash(self.password_hash, raw_password)

    def __repr__(self):
        return f'<User {self.username}>'


class Student(db.Model):
    """
    Profile information for a student. One row per User.

    Columns:
        id (int): Primary key.
        user_id (int): Foreign key to users.id (one-to-one, unique).
        full_name (str): Student's full legal name.
        student_number (str): Unique school-issued student ID number.
        program (str): Degree program / course.
        year_level (str): Current year level.
        contact_number (str): Phone number.
        address (str): Mailing/home address.

    Relationships:
        scholarships: One-to-many list of this student's
            ScholarshipApplication rows. Deleting a Student cascades and
            deletes their applications (and, in turn, their documents).
    """

    __tablename__ = 'students'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    full_name = db.Column(db.String(120), nullable=False)
    student_number = db.Column(db.String(40), unique=True, nullable=False, index=True)
    program = db.Column(db.String(120), nullable=True)
    year_level = db.Column(db.String(20), nullable=True)
    contact_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(255), nullable=True)

    scholarships = db.relationship(
        'ScholarshipApplication', backref='student', cascade='all, delete-orphan',
        order_by='desc(ScholarshipApplication.submitted_at)'
    )

    def __repr__(self):
        return f'<Student {self.full_name} ({self.student_number})>'


class ScholarshipApplication(db.Model):
    """
    A single scholarship application submitted by a student.

    Columns:
        id (int): Primary key.
        student_id (int): Foreign key to students.id.
        scholarship_name (str): Name/type of scholarship applied for.
        gpa (float): Student's reported GPA at time of application.
        reason (str): Free-text justification / essay.
        status (str): Workflow state: 'Pending', 'Approved', or 'Rejected'.
        submitted_at (datetime): Submission timestamp (UTC).

    Relationships:
        documents: One-to-many list of Document rows attached to this
            application (the required valid ID plus any supporting
            files). Deleting an application cascades and deletes its
            document metadata rows.
    """

    __tablename__ = 'scholarship_applications'

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    scholarship_name = db.Column(db.String(150), nullable=False)
    gpa = db.Column(db.Float, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending', nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    documents = db.relationship(
        'Document', backref='scholarship', cascade='all, delete-orphan'
    )

    def __repr__(self):
        return f'<ScholarshipApplication {self.scholarship_name} - {self.status}>'


class Document(db.Model):
    """
    Metadata for a single uploaded file linked to a scholarship
    application. The file's bytes live on disk under the app's
    configured UPLOAD_FOLDER; only the path/metadata is stored here.

    Columns:
        id (int): Primary key.
        scholarship_id (int): Foreign key to scholarship_applications.id.
        document_type (str): Category label, e.g. 'Valid ID' or
            'Supporting Document'.
        original_filename (str): The sanitized name of the file as the
            user uploaded it (for display / download purposes only).
        stored_filename (str): The randomized, collision-proof filename
            actually saved on disk. Never derived from user input.
        uploaded_at (datetime): Upload timestamp (UTC).
    """

    __tablename__ = 'documents'

    id = db.Column(db.Integer, primary_key=True)
    scholarship_id = db.Column(
        db.Integer, db.ForeignKey('scholarship_applications.id'), nullable=False
    )
    document_type = db.Column(db.String(50), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Document {self.original_filename}>'
