# Run instructions

1. Clone the project directory:
   git clone <repo> && cd home-services-app

2. Create a Python virtual environment:
   python -m venv venv
   source venv/bin/activate   # macOS / Linux
   venv\Scripts\activate      # Windows

   <!-- Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force (venv\Scripts\activate fix error)-->

3. Install dependencies:
   pip install -r requirements.txt

4. Create a `.env` file from `.env.example` and set required secrets:
   - SECRET_KEY: a random 32+ char string (used by Flask)
   - FERNET_KEYS: REQUIRED. Provide one or more comma-separated Fernet keys (base64)
     Generate a key using:

   python - <<PY
   from cryptography.fernet import Fernet
   print(Fernet.generate_key().decode())
   PY

   If you want email verification via SMTP, fill in the MAIL_* fields in `.env`. If not configured, verification links will be printed to console.

5. Initialize the database and bootstrap data:
   python init_db.py

   This creates instance/home_services.sqlite and a default admin:
     username: admin
     password: adminpass

6. Run the app:
   python app.py
   (The dev server will run at http://127.0.0.1:5000/)
