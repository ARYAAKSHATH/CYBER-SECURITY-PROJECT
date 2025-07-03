from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import bcrypt

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    master_password_hash = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.LargeBinary(32), nullable=False)  # For encryption key derivation
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationship with credentials
    credentials = db.relationship('Credential', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_master_password(self, password):
        """Hash and set the master password."""
        salt = bcrypt.gensalt()
        self.master_password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_master_password(self, password):
        """Check if provided password matches the stored hash."""
        return bcrypt.checkpw(password.encode('utf-8'), self.master_password_hash.encode('utf-8'))
    
    def __repr__(self):
        return f'<User {self.username}>'

class Credential(db.Model):
    __tablename__ = 'credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    website = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Credential {self.website} - {self.username}>'