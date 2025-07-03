
# Password Manager

A secure **Flask‑based** web application for managing and encrypting user credentials, complete with a built‑in password generator.

---

## 🛠️ Setup Instructions

### 1. Clone the Repository

```bash
git clone <repository_url>
cd <repository_directory>
````

### 2. Create and Activate a Virtual Environment

#### Create the environment:

```bash
python -m venv venv
```

#### Activate the environment:

* **On Windows**

  ```bash
  venv\Scripts\activate
  ```

* **On macOS/Linux**

  ```bash
  source venv/bin/activate
  ```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 📁 File Descriptions and Execution

| File                      | Description                                                                             | Run Command                                 |
| ------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------- |
| **`app.py`**              | Main Flask application defining routes, user authentication, and credential management. | `python app.py`                             |
| **`check_database.py`**   | Utility script to inspect the SQLite database (lists tables & contents).                | `python check_database.py`                  |
| **`config.py`**           | Configuration settings for the Flask app (database paths, security keys, etc.).         | *Imported by* `app.py`                      |
| **`password_manager.db`** | SQLite database storing users and credentials (auto‑created by the app).                | *Managed by the application*                |
| **`encryption.py`**       | Implements encryption/decryption using **Fernet** symmetric encryption.                 | *Imported by* `app.py`                      |
| **`models.py`**           | Database models for users and credentials using **Flask‑SQLAlchemy**.                   | *Imported by* `app.py`                      |
| **`forms.py`**            | **WTForms** definitions for registration, login, and credential forms.                  | *Imported by* `app.py`                      |
| **`passwords_utils.py`**  | Utilities for generating secure passwords and checking strength.                        | *Imported by* `app.py`                      |
| **`requirements.txt`**    | List of Python dependencies required for the project.                                   | Used with `pip install -r requirements.txt` |
