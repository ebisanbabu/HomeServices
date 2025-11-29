from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, BooleanField, FileField
from wtforms.validators import DataRequired, Length, Optional, Email
try:
    from wtforms.fields.html5 import DateTimeLocalField
except Exception:
    DateTimeLocalField = None
from wtforms import ValidationError
import re

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3,80)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=200)])
    password = PasswordField("Password", validators=[DataRequired(), Length(6,128)])
    role = SelectField("Role", choices=[("client","Client"),("worker","Worker")])
    submit = SubmitField("Register")

    def validate_password(self, field):
        pw = field.data or ""
        if len(pw) < 10 or not re.search(r'[A-Z]', pw) or not re.search(r'\d', pw) or not re.search(r'[a-z]', pw):
            raise ValidationError("Password must be at least 10 characters and include uppercase, lowercase and a digit.")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    totp = StringField("TOTP (if enabled)", validators=[Optional(), Length(max=10)])
    submit = SubmitField("Login")

class BookingForm(FlaskForm):
    service_type = SelectField("Service Type", coerce=int)
    if DateTimeLocalField is not None:
        scheduled_time = DateTimeLocalField("Preferred time", format="%Y-%m-%dT%H:%M", validators=[DataRequired()])
    else:
        scheduled_time = StringField("Preferred time (e.g., 2025-12-01 10:00)", validators=[DataRequired()])
    description = TextAreaField("Notes", validators=[Length(max=500), Optional()])
    submit = SubmitField("Book Service")

class UploadCertificateForm(FlaskForm):
    certificate = FileField("Certificate (pdf/png/jpg)", validators=[DataRequired()])
    submit = SubmitField("Upload")


class ResetRequestForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    submit = SubmitField("Send reset OTP")


class ResetVerifyForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    otp = StringField("OTP", validators=[DataRequired(), Length(min=4, max=8)])
    password = PasswordField("New password", validators=[DataRequired(), Length(6,128)])
    submit = SubmitField("Reset password")
