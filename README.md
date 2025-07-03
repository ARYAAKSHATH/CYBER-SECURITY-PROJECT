Password Manager
A secure Flask-based web application for managing and encrypting user credentials with a password generator.
Setup Instructions
Clone the Repository

Clone the repository to your local machine:git clone <repository_url>


Navigate to the repository directory:cd <repository_directory>



Create and Activate Virtual Environment

Create a virtual environment:python -m venv venv


Activate the virtual environment:
On Windows:venv\Scripts\activate


On macOS/Linux:source venv/bin/activate




Install the required dependencies:pip install -r requirements.txt



File Descriptions and Execution
app.py

Description: The main Flask application file that defines routes, user authentication, and credential management.
Run Command:python app.py



check_database.py

Description: A utility script to inspect the SQLite database, listing tables and their contents.
Run Command:python check_database.py



config.py

Description: Contains configuration settings for the Flask app, including database and security settings.
Run Command: Not run directly; imported by app.py.

password_manager.db

Description: SQLite database file storing user and credential data (created automatically by app.py).
Run Command: Not run directly; managed by the application.

encryption.py

Description: Implements password encryption and decryption using Fernet symmetric encryption.
Run Command: Not run directly; imported by app.py.

models.py

Description: Defines database models for users and credentials using Flask-SQLAlchemy.
Run Command: Not run directly; imported by app.py.

forms.py

Description: Defines WTForms for user registration, login, and credential management.
Run Command: Not run directly; imported by app.py.

requirements.txt

Description: Lists Python dependencies required for the project.
Run Command: Not run directly; used with pip install -r requirements.txt.

passwords_utils.py

Description: Provides utilities for generating secure passwords and checking their strength.
Run Command: Not run directly; imported by app.py.

