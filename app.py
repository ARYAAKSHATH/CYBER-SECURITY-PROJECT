from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash
from datetime import datetime
import os

# Import our modules
from config import Config
from models import db, User, Credential
from forms import RegistrationForm, LoginForm, AddCredentialForm, EditCredentialForm, PasswordGeneratorForm
from encryption import PasswordEncryption
from passwords_utils import PasswordGenerator

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Initialize rate limiter
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Routes
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('index.html')
    
    @app.route('/register', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        form = RegistrationForm()
        if form.validate_on_submit():
            try:
                # Generate salt for encryption
                encryption_salt = PasswordEncryption.generate_salt()
                
                # Create new user
                user = User(
                    username=form.username.data.lower().strip(),
                    email=form.email.data.lower().strip(),
                    salt=encryption_salt
                )
                user.set_master_password(form.master_password.data)
                
                db.session.add(user)
                db.session.commit()
                
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Registration failed. Please try again.', 'error')
                app.logger.error(f"Registration error: {str(e)}")
        
        return render_template('register.html', form=form)
    
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("10 per minute")
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
            
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data.lower().strip()).first()
            
            if user and user.check_master_password(form.master_password.data):
                login_user(user)
                user.last_login = datetime.utcnow()
                
                # Store encryption key in session (derived from master password)
                encryption_key = PasswordEncryption.derive_key_from_password(
                    form.master_password.data, user.salt
                )
                session['encryption_key'] = encryption_key.decode('utf-8')
                
                db.session.commit()
                flash('Login successful!', 'success')
                
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')
        
        return render_template('login.html', form=form)
    
    @app.route('/logout')
    @login_required
    def logout():
        # Clear encryption key from session
        session.pop('encryption_key', None)
        logout_user()
        flash('You have been logged out.', 'info')
        return redirect(url_for('index'))
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        search_query = request.args.get('search', '')
        
        if search_query:
            credentials = Credential.query.filter(
                Credential.user_id == current_user.id,
                Credential.website.contains(search_query)
            ).order_by(Credential.website).all()
        else:
            credentials = Credential.query.filter_by(
                user_id=current_user.id
            ).order_by(Credential.website).all()
        
        return render_template('dashboard.html', credentials=credentials, search_query=search_query)
    
    @app.route('/add_credential', methods=['GET', 'POST'])
    @login_required
    def add_credential():
        form = AddCredentialForm()
        
        if form.validate_on_submit():
            try:
                # Get encryption key from session
                encryption_key = session.get('encryption_key')
                if not encryption_key:
                    flash('Session expired. Please log in again.', 'error')
                    return redirect(url_for('login'))
                
                # Encrypt the password
                encrypted_password = PasswordEncryption.encrypt_password(
                    form.password.data, 
                    encryption_key.encode('utf-8')
                )
                
                # Create new credential
                credential = Credential(
                    user_id=current_user.id,
                    website=form.website.data.strip(),
                    username=form.username.data.strip(),
                    encrypted_password=encrypted_password,
                    notes=form.notes.data.strip() if form.notes.data else None
                )
                
                db.session.add(credential)
                db.session.commit()
                
                flash('Credential saved successfully!', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                flash('Failed to save credential. Please try again.', 'error')
                app.logger.error(f"Add credential error: {str(e)}")
        
        return render_template('add_credential.html', form=form)
    
    @app.route('/edit_credential/<int:credential_id>', methods=['GET', 'POST'])
    @login_required
    def edit_credential(credential_id):
        credential = Credential.query.filter_by(
            id=credential_id, 
            user_id=current_user.id
        ).first_or_404()
        
        form = EditCredentialForm()
        
        if form.validate_on_submit():
            try:
                # Get encryption key from session
                encryption_key = session.get('encryption_key')
                if not encryption_key:
                    flash('Session expired. Please log in again.', 'error')
                    return redirect(url_for('login'))
                
                # Encrypt the new password
                encrypted_password = PasswordEncryption.encrypt_password(
                    form.password.data,
                    encryption_key.encode('utf-8')
                )
                
                # Update credential
                credential.website = form.website.data.strip()
                credential.username = form.username.data.strip()
                credential.encrypted_password = encrypted_password
                credential.notes = form.notes.data.strip() if form.notes.data else None
                credential.updated_at = datetime.utcnow()
                
                db.session.commit()
                
                flash('Credential updated successfully!', 'success')
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                flash('Failed to update credential. Please try again.', 'error')
                app.logger.error(f"Edit credential error: {str(e)}")
        
        # Pre-populate form with existing data (except password)
        if request.method == 'GET':
            form.website.data = credential.website
            form.username.data = credential.username
            form.notes.data = credential.notes
        
        return render_template('edit_credential.html', form=form, credential=credential)
    
    @app.route('/delete_credential/<int:credential_id>')
    @login_required
    def delete_credential(credential_id):
        credential = Credential.query.filter_by(
            id=credential_id,
            user_id=current_user.id
        ).first_or_404()
        
        try:
            db.session.delete(credential)
            db.session.commit()
            flash('Credential deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Failed to delete credential. Please try again.', 'error')
            app.logger.error(f"Delete credential error: {str(e)}")
        
        return redirect(url_for('dashboard'))
    
    @app.route('/get_password/<int:credential_id>')
    @login_required
    def get_password(credential_id):
        credential = Credential.query.filter_by(
            id=credential_id,
            user_id=current_user.id
        ).first_or_404()
        
        try:
            # Get encryption key from session
            encryption_key = session.get('encryption_key')
            if not encryption_key:
                return jsonify({'error': 'Session expired'}), 401
            
            # Decrypt password
            decrypted_password = PasswordEncryption.decrypt_password(
                credential.encrypted_password,
                encryption_key.encode('utf-8')
            )
            
            return jsonify({'password': decrypted_password})
        except Exception as e:
            app.logger.error(f"Get password error: {str(e)}")
            return jsonify({'error': 'Failed to decrypt password'}), 500
    
    @app.route('/generate_password')
    @login_required
    def generate_password():
        try:
            length = int(request.args.get('length', 16))
            password = PasswordGenerator.generate_password(length)
            strength = PasswordGenerator.check_password_strength(password)
            
            return jsonify({
                'password': password,
                'strength': strength
            })
        except Exception as e:
            app.logger.error(f"Generate password error: {str(e)}")
            return jsonify({'error': 'Failed to generate password'}), 500
    
    @app.route('/password_generator')
    @login_required
    def password_generator():
        return render_template('password_generator.html')
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('500.html'), 500
    
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return render_template('ratelimit.html'), 429
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)