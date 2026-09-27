"""
Flask-WTF form definitions for the Student Account Portal.

Every form here includes a hidden CSRF token automatically (via
FlaskForm) and server-side validators for every field, so submitted
data is never trusted without validation, regardless of what client-
side JavaScript may or may not enforce.
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired, MultipleFileField
from wtforms import (
    StringField, PasswordField, SubmitField, FloatField, TextAreaField, SelectField
)
from wtforms.validators import DataRequired, Email, EqualTo, Length, NumberRange, Regexp

# Single source of truth for allowed upload extensions, shared with app.py.
ALLOWED_DOC_EXTENSIONS = ['jpg', 'jpeg', 'png', 'pdf', 'docx']


class RegistrationForm(FlaskForm):
    """
    Validates data for creating a new user account.

    Fields:
        username (str): 4-25 chars; letters, digits, underscores only.
        email (str): Must be a syntactically valid email address.
        password (str): Minimum 8 characters.
        confirm_password (str): Must exactly match `password`.

    On successful validate_on_submit(), each field's cleaned value is
    available as form.<field>.data for the route to persist.
    """

    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Length(min=4, max=25),
            Regexp(r'^[A-Za-z0-9_]+$', message='Letters, numbers, and underscores only.')
        ]
    )
    email = StringField(
        'Email', validators=[DataRequired(), Email(), Length(max=120)]
    )
    password = PasswordField(
        'Password', validators=[DataRequired(), Length(min=8, message='Minimum 8 characters.')]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[DataRequired(), EqualTo('password', message='Passwords must match.')]
    )
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """
    Validates login credentials submitted on the login page.

    Fields:
        username (str): Required.
        password (str): Required.

    Returns (via validate_on_submit()): True/False; cleaned values are
    read from form.username.data / form.password.data by the route,
    which then verifies them against the stored password hash.
    """

    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class StudentProfileForm(FlaskForm):
    """
    Validates a student's editable profile fields.

    Fields:
        full_name (str): Required, max 120 chars.
        student_number (str): Required, unique, alphanumeric/dash only.
        program (str): Optional, max 120 chars.
        year_level (str): Required, one of a fixed set of choices.
        contact_number (str): Optional; digits, spaces, +, - only.
        address (str): Optional, max 255 chars.
    """

    full_name = StringField('Full Name', validators=[DataRequired(), Length(max=120)])
    student_number = StringField(
        'Student Number',
        validators=[
            DataRequired(), Length(max=40),
            Regexp(r'^[A-Za-z0-9\-]+$', message='Letters, numbers, and dashes only.')
        ]
    )
    program = StringField('Program', validators=[Length(max=120)])
    year_level = SelectField(
        'Year Level',
        choices=[('1', '1st Year'), ('2', '2nd Year'), ('3', '3rd Year'),
                 ('4', '4th Year'), ('5', '5th Year+')],
        validators=[DataRequired()]
    )
    contact_number = StringField(
        'Contact Number',
        validators=[Length(max=20), Regexp(r'^[0-9+\-\s]*$', message='Digits only.')]
    )
    address = StringField('Address', validators=[Length(max=255)])
    submit = SubmitField('Save Profile')


class ScholarshipForm(FlaskForm):
    """
    Validates a scholarship application, including the required valid-ID
    upload and any optional supporting documents.

    Fields:
        scholarship_name (str): Required, max 150 chars.
        gpa (float): Required, between 1.0 and 5.0 (adjust the range to
            match your institution's grading scale).
        reason (str): Required justification/essay text, max 2000 chars.
        valid_id (FileStorage): Required single file; extension must be
            one of ALLOWED_DOC_EXTENSIONS. Size is capped globally by
            MAX_CONTENT_LENGTH in app.py.
        supporting_documents (list[FileStorage]): Optional multiple
            files, same extension restriction.
    """

    scholarship_name = StringField(
        'Scholarship Name', validators=[DataRequired(), Length(max=150)]
    )
    gpa = FloatField(
        'GPA', validators=[DataRequired(), NumberRange(min=1.0, max=5.0)]
    )
    reason = TextAreaField(
        'Reason / Justification', validators=[DataRequired(), Length(max=2000)]
    )
    valid_id = FileField(
        'Valid ID',
        validators=[
            FileRequired(message='A valid ID file is required.'),
            FileAllowed(ALLOWED_DOC_EXTENSIONS, 'Only JPG, JPEG, PNG, PDF, or DOCX files allowed.')
        ]
    )
    supporting_documents = MultipleFileField(
        'Supporting Documents (optional)',
        validators=[
            FileAllowed(ALLOWED_DOC_EXTENSIONS, 'Only JPG, JPEG, PNG, PDF, or DOCX files allowed.')
        ]
    )
    submit = SubmitField('Submit Application')


class AdminActionForm(FlaskForm):
    """
    Minimal CSRF-protected form used for the admin dashboard's
    approve/reject buttons (no user-editable fields beyond the token).
    """
    pass
