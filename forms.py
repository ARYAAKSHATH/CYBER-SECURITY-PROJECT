from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from models import User
import re

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20, message="Username must be between 4 and 20 characters")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    master_password = PasswordField('Master Password', validators=[
        DataRequired(),
        Length(min=8, message="Master password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Master Password', validators=[
        DataRequired(),
        EqualTo('master_password', message='Passwords must match')
    ])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email.')
    
    def validate_master_password(self, master_password):
        password = master_password.data
        if len(password) < 8:
            raise ValidationError('Password must be at least 8 characters long.')
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', password):
            raise ValidationError('Password must contain at least one lowercase letter.')
        if not re.search(r'\d', password):
            raise ValidationError('Password must contain at least one digit.')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError('Password must contain at least one special character.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    master_password = PasswordField('Master Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AddCredentialForm(FlaskForm):
    website = StringField('Website/Service', validators=[
        DataRequired(),
        Length(max=200, message="Website name too long")
    ])
    username = StringField('Username/Email', validators=[
        DataRequired(),
        Length(max=100, message="Username too long")
    ])
    password = PasswordField('Password', validators=[DataRequired()])
    notes = TextAreaField('Notes (Optional)', validators=[Length(max=500)])
    submit = SubmitField('Save Credential')

class EditCredentialForm(FlaskForm):
    website = StringField('Website/Service', validators=[
        DataRequired(),
        Length(max=200, message="Website name too long")
    ])
    username = StringField('Username/Email', validators=[
        DataRequired(),
        Length(max=100, message="Username too long")
    ])
    password = PasswordField('Password', validators=[DataRequired()])
    notes = TextAreaField('Notes (Optional)', validators=[Length(max=500)])
    submit = SubmitField('Update Credential')

class PasswordGeneratorForm(FlaskForm):
    length = StringField('Password Length', validators=[DataRequired()], default='16')
    submit = SubmitField('Generate Password')