from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError

from app import email
from ..models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField(
        'Username', 
        validators=[
            DataRequired(),
            Length(1, 64),
            Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, numbers, dots or '
    'underscores'),
    ])
    password = PasswordField(
        'Password', 
        validators=[
            DataRequired(), 
            EqualTo('password2', 
            message='Passwords must match.'),
            Regexp('^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&-+=()])(?=\\S+$).{8, 64}$',
            0, 
            'Passwords must have only letters, numbers, dots or '
            'spec symbols @#$%^&-+=()')])
    password2 = PasswordField(
        'Confirm password', 
        validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old password', validators=[DataRequired()])
    new_password = PasswordField('New password', validators=[DataRequired(), 
                    EqualTo('new_password_repeat', 'Passwords must match.'),
                    Regexp('^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&-+=()])(?=\\S+$).{8, 64}$',
                    0, 
                    'Passwords must have only letters, numbers, dots or '
                    'spec symbols @#$%^&-+=()')])
    new_password_repeat = PasswordField('Confirm new password', validators=[DataRequired()])
    submit = SubmitField('Update Password')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('Reset Password')

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New password', validators=[DataRequired(), 
                    EqualTo('new_password_repeat', 'Passwords must match.'),
                    Regexp('^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&-+=()])(?=\\S+$).{8, 64}$',
                    0, 
                    'Passwords must have only letters, numbers, dots or '
                    'spec symbols @#$%^&-+=()')])
    new_password_repeat = PasswordField('Confirm new password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

class ChangeEmailForm(FlaskForm):
    email = StringField('New email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Change email')
    
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')