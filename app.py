from compatability_issues_fix import apply_werkzeug_shim
apply_werkzeug_shim()

import os
import hashlib
import base64
import json
import datetime
from datetime import timedelta
from flask import (
    Flask, render_template, redirect, url_for, flash, request, session, abort, current_app, send_from_directory
)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, joinedload
from models import (
    Base, User, ServiceType, Booking, VisitMapping, Notification, AuditLog
)
from forms import RegisterForm, LoginForm, BookingForm, UploadCertificateForm
from forms import ResetRequestForm, ResetVerifyForm
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from cryptography.fernet import Fernet, MultiFernet
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler
import pyotp
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import bleach
from werkzeug.utils import secure_filename

# load env
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or "dev-secret"

# Set MAIL_BYPASS=True, auto-verify accounts and skip email checks.
app.config['MAIL_BYPASS'] = os.getenv('MAIL_BYPASS', 'False') == 'True'

# --- App config (cookies, sessions) ---
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

# CORS restriction
CORS(app, resources={r"/api/*": {"origins": os.getenv("CORS_ORIGINS", "http://localhost:5000")}})

# Database
DB_URI = f"sqlite:///{os.path.join('instance','home_services.sqlite')}"
engine = create_engine(DB_URI, echo=False, future=True)
Base.metadata.bind = engine
SessionLocal = scoped_session(sessionmaker(bind=engine, future=True))

# Ensure DB tables exist
try:
    # create any missing tables
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        rows = conn.execute("PRAGMA table_info('bookings')").fetchall()
        existing_cols = [r[1] for r in rows]
        if 'worker_id' not in existing_cols:
            conn.exec_driver_sql('ALTER TABLE bookings ADD COLUMN worker_id INTEGER')
            print('DB migration: added bookings.worker_id column')
        rows_u = conn.execute("PRAGMA table_info('users')").fetchall()
        existing_u_cols = [r[1] for r in rows_u]
        if 'is_blocked' not in existing_u_cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN is_blocked BOOLEAN DEFAULT 0")
            print('DB migration: added users.is_blocked column')
            if 'is_verified' not in existing_u_cols:
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0")
                print('DB migration: added users.is_verified column')
except Exception:
    pass


def ensure_schema_before_requests():
    try:
        Base.metadata.create_all(engine)
        with engine.connect() as conn:
            rows = conn.execute("PRAGMA table_info('bookings')").fetchall()
            existing_cols = [r[1] for r in rows]
            if 'worker_id' not in existing_cols:
                conn.exec_driver_sql('ALTER TABLE bookings ADD COLUMN worker_id INTEGER')
                print('DB migration (startup): added bookings.worker_id column')
            rows_u = conn.execute("PRAGMA table_info('users')").fetchall()
            existing_u_cols = [r[1] for r in rows_u]
            if 'is_blocked' not in existing_u_cols:
                conn.exec_driver_sql("ALTER TABLE users ADD COLUMN is_blocked BOOLEAN DEFAULT 0")
                print('DB migration (startup): added users.is_blocked column')
                if 'is_verified' not in existing_u_cols:
                    conn.exec_driver_sql("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0")
                    print('DB migration (startup): added users.is_verified column')
    except Exception as e:
        print('Schema check failed at startup:', e)

try:
    if hasattr(app, 'before_first_request'):
        app.before_first_request(ensure_schema_before_requests)
    else:
        ensure_schema_before_requests()
except Exception:
    try:
        ensure_schema_before_requests()
    except Exception:
        pass

# --- FERNET KEYS ---
FERNET_KEYS = os.getenv("FERNET_KEYS")
if not FERNET_KEYS:
    raise RuntimeError(
        "FERNET_KEYS not set. Provide one or more comma-separated Fernet keys (base64).\n"
        "Generate with:\n"
        "  python - <<PY\n"
        "  from cryptography.fernet import Fernet\n"
        "  print(Fernet.generate_key().decode())\n"
        "  PY\n"
    )
fernet_keys_list = [Fernet(k.encode()) if isinstance(k, str) and not k.startswith("b'") else Fernet(k) for k in FERNET_KEYS.split(",")]
try:
    multi_fernet = MultiFernet(fernet_keys_list)
except Exception:
    f_objs = [Fernet(k) for k in FERNET_KEYS.split(",")]
    multi_fernet = MultiFernet(f_objs)

# --- Talisman: CSP and secure headers ---
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", "data:"],
}
Talisman(app, content_security_policy=csp, force_https=False)

# --- Mail ---
mail = Mail(app)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', '')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', '0') or 0)
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'False') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', '')

# --- Rate limiting ---
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# --- Login manager ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# --- Scheduler for automated retention purge ---
scheduler = BackgroundScheduler()
scheduler.start()

# --- Serializer for email tokens ---
ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Allowed upload types
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
UPLOAD_FOLDER = os.path.join('instance', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# Simple User class
class LoginUser(UserMixin):
    def __init__(self, user):
        self.id = user.id
        self.username = user.username
        self.role = user.role
        self.is_verified = getattr(user, 'is_verified', False)
        self.is_blocked = getattr(user, 'is_blocked', False)

@login_manager.user_loader
def load_user(user_id):
    s = SessionLocal()
    try:
        u = s.query(User).get(int(user_id))
    finally:
        s.close()
    if u:
        return LoginUser(u)
    return None

# Utility: hash email for privacy
def hash_email(email):
    if not email:
        return None
    h = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    return h

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def antivirus_scan_stub(filepath):
    # For demo we always return True (clean)
    # In production we are using clamscan
    return True

def audit_log(actor_user_id, action, details=""):
    s = SessionLocal()
    try:
        al = AuditLog(user_id=actor_user_id, action=action, details=details)
        s.add(al)
        s.commit()
    finally:
        s.close()

# automated retention purge
def purge_old_mappings():
    retention_days = int(os.getenv("RETENTION_DAYS", "14"))
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
    s = SessionLocal()
    try:
        old = s.query(VisitMapping).filter(VisitMapping.created_at < cutoff).all()
        count = len(old)
        for r in old:
            s.delete(r)
        s.commit()
        if count:
            audit_log(None, "purge_old_mappings", f"Purged {count} visit mappings older than {retention_days} days.")
    finally:
        s.close()

# schedule job daily
scheduler.add_job(func=purge_old_mappings, trigger="interval", days=1)

# Session management
@app.before_request
def session_management():
    session.permanent = True
    session.modified = True

@app.after_request
def set_additional_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


@app.context_processor
def inject_current_year():
    try:
        return {'current_year': datetime.datetime.utcnow().year}
    except Exception:
        return {'current_year': ''}


@app.context_processor
def inject_notification_helpers():
    def get_unread_count():
        try:
            if not (current_user and getattr(current_user, 'is_authenticated', False)):
                return 0
            s = SessionLocal()
            try:
                return s.query(Notification).filter_by(user_id=current_user.id, read=False).count()
            finally:
                s.close()
        except Exception:
            return 0
    return {'get_unread_count': get_unread_count}

@app.route("/")
def index():
    return render_template("index.html")

# --- Register route with email verification & password policy ---
@app.route("/register", methods=["GET","POST"])
@limiter.limit("5 per minute")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        s = SessionLocal()
        try:
            if s.query(User).filter_by(username=form.username.data).first():
                flash("Username already exists", "danger")
                return redirect(url_for("register"))
            u = User(
                username=form.username.data,
                email_hash=hash_email(form.email.data),
                password_hash=generate_password_hash(form.password.data),
                role=form.role.data,
                email_verified=False
            )
            s.add(u)
            s.commit()

            token = ts.dumps(u.username, salt='email-confirm-key')
            verify_url = url_for('confirm_email', token=token, _external=True)

            if app.config.get('MAIL_BYPASS'):
                u.email_verified = True
                s.commit()
                audit_log(u.id, "register", f"User {u.username} registered (mail bypass: auto-verified).")
                flash("Registered (dev bypass active) - account auto-verified.", "success")
                return redirect(url_for("login"))

            if app.config.get('MAIL_SERVER'):
                try:
                    msg = Message("Verify your HomeServices account", sender=app.config.get('MAIL_USERNAME'), recipients=[form.email.data])
                    msg.body = f"Click to verify: {verify_url}"
                    mail.send(msg)
                except Exception as e:
                    print("Mail send failed:", e)
                    print("Verification URL:", verify_url)
            else:
                print("EMAIL VERIFICATION (dev):", verify_url)

            audit_log(u.id, "register", f"User {u.username} registered.")
            flash("Registered. Check your email for verification link.", "success")
            return redirect(url_for("login"))
        finally:
            s.close()
    return render_template("register.html", form=form)

# email confirmation route
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        username = ts.loads(token, salt='email-confirm-key', max_age=3600*24)
    except Exception:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for("index"))
    s = SessionLocal()
    try:
        u = s.query(User).filter_by(username=username).first()
        if not u:
            flash("User not found.", "danger")
            return redirect(url_for("index"))
        u.email_verified = True
        s.commit()
        audit_log(u.id, "email_confirm", f"User {u.username} verified email.")
        flash("Email verified. You can now use your account.", "success")
        return redirect(url_for("login"))
    finally:
        s.close()

# --- Login with rate limiting, account lockout, TOTP check ---
MAX_FAIL = int(os.getenv("MAX_FAIL", "5"))
LOCK_MINUTES = int(os.getenv("LOCK_MINUTES", "30"))

@app.route("/login", methods=["GET","POST"])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        s = SessionLocal()
        try:
            u = s.query(User).filter_by(username=form.username.data).first()
            if not u:
                flash("Invalid credentials", "danger")
                return redirect(url_for("login"))

            if getattr(u, 'is_blocked', False):
                flash("Account blocked by administrator.", "danger")
                audit_log(u.id, "login_attempt_blocked", "Attempted login while admin-blocked.")
                return redirect(url_for("login"))

            if u.locked_until and u.locked_until > datetime.datetime.utcnow():
                flash("Account locked due to repeated failures. Try later.", "danger")
                audit_log(u.id, "login_attempt_locked", "Attempted login while account locked.")
                return redirect(url_for("login"))

            if not check_password_hash(u.password_hash, form.password.data):
                u.failed_attempts = (u.failed_attempts or 0) + 1
                if u.failed_attempts >= MAX_FAIL:
                    u.locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=LOCK_MINUTES)
                    u.failed_attempts = 0
                    s.commit()
                    audit_log(u.id, "account_locked", f"Account locked for {LOCK_MINUTES} minutes due to failed logins.")
                    flash("Too many failed attempts. Account locked.", "danger")
                    return redirect(url_for("login"))
                s.commit()
                audit_log(u.id, "failed_login", "Incorrect password.")
                flash("Invalid credentials", "danger")
                return redirect(url_for("login"))

            if not u.email_verified and not app.config.get('MAIL_BYPASS'):
                flash("Please verify your email before logging in.", "warning")
                return redirect(url_for("login"))

            if u.totp_enabled:
                totp_code = form.totp.data or ""
                if not totp_code:
                    flash("TOTP code required for this account.", "danger")
                    return redirect(url_for("login"))
                try:
                    totp = pyotp.TOTP(u.totp_secret)
                    if not totp.verify(totp_code, valid_window=1):
                        flash("Invalid TOTP code", "danger")
                        audit_log(u.id, "failed_totp", "Invalid TOTP during login.")
                        return redirect(url_for("login"))
                except Exception:
                    flash("TOTP verification failed", "danger")
                    return redirect(url_for("login"))

            u.failed_attempts = 0
            u.locked_until = None
            s.commit()
            login_user(LoginUser(u))
            audit_log(u.id, "login", "User logged in.")
            flash("Logged in", "success")
            return redirect(url_for("dashboard"))
        finally:
            s.close()
    return render_template("login.html", form=form)


# --- Password reset request: send OTP via email ---
@app.route('/reset/request', methods=['GET','POST'])
@limiter.limit('5 per minute')
def reset_request():
    form = ResetRequestForm()
    if form.validate_on_submit():
        s = SessionLocal()
        try:
            u = s.query(User).filter_by(username=form.username.data).first()
            if not u:
                flash('If the account exists, a reset code will be sent.', 'info')
                return redirect(url_for('login'))

            # generate 6-digit OTP
            import random
            otp = f"{random.randint(0,999999):06d}"
            token = ts.dumps({'username': u.username, 'otp': otp}, salt='pw-reset')

            session['pw_reset_token'] = token

            user_email = getattr(u, 'email', None)
            if app.config.get('MAIL_SERVER') and user_email:
                try:
                    msg = Message('Your password reset code', sender=app.config.get('MAIL_USERNAME'), recipients=[user_email])
                    msg.body = f"Your reset code is: {otp}\nIf you did not request this, ignore this email."
                    mail.send(msg)
                    flash('Reset code sent to your email.', 'info')
                except Exception as e:
                    print('Mail send failed:', e)
                    print('Reset token:', token)
                    flash('Unable to send email.', 'warning')
                    print(f"PASSWORD RESET (dev fallback): username={u.username} otp={otp} token={token}")
            else:
                print(f"PASSWORD RESET: username={u.username} otp={otp} token={token}")
                if app.config.get('MAIL_SERVER') and not user_email:
                    flash('No email address is available for this account; contact support.', 'warning')
                else:
                    flash('Reset code sent.', 'info')
        finally:
            s.close()
        return redirect(url_for('reset_verify'))
    return render_template('reset_request.html', form=form)


# --- Verify OTP and set new password ---
@app.route('/reset/verify', methods=['GET','POST'])
@limiter.limit('10 per hour')
def reset_verify():
    form = ResetVerifyForm()
    if form.validate_on_submit():
        token = session.get('pw_reset_token')
        if not token:
            flash('No reset request found. Start again.', 'danger')
            return redirect(url_for('reset_request'))
        try:
            data = ts.loads(token, salt='pw-reset', max_age=60*15)
        except Exception:
            flash('Reset token expired or invalid. Start again.', 'danger')
            session.pop('pw_reset_token', None)
            return redirect(url_for('reset_request'))

        if data.get('username') != form.username.data or data.get('otp') != form.otp.data:
            flash('Invalid code or username.', 'danger')
            return redirect(url_for('reset_verify'))

        s = SessionLocal()
        try:
            u = s.query(User).filter_by(username=form.username.data).first()
            if not u:
                flash('User not found.', 'danger')
                return redirect(url_for('reset_request'))
            u.password_hash = generate_password_hash(form.password.data)
            s.commit()
            audit_log(u.id, 'password_reset', 'User reset password via OTP')
            flash('Password updated. You can now login.', 'success')
            session.pop('pw_reset_token', None)
            return redirect(url_for('login'))
        finally:
            s.close()
    return render_template('reset_verify.html', form=form)

@app.route("/logout")
@login_required
def logout():
    audit_log(current_user.id, "logout", "User logged out.")
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    s = SessionLocal()
    try:
        services = s.query(ServiceType).all()
        bookings = s.query(Booking).filter_by(client_id=current_user.id).all() if current_user else []
        notifications = s.query(Notification).filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    finally:
        s.close()
    return render_template("dashboard.html", services=services, bookings=bookings, notifications=notifications)

# booking
@app.route("/book", methods=["GET","POST"])
@login_required
@limiter.limit("10 per minute")
def book_service():
    s = SessionLocal()
    form = BookingForm()
    try:
        form.service_type.choices = [(st.id, st.name) for st in s.query(ServiceType).all()]
        if form.validate_on_submit():
            clean_desc = bleach.clean(form.description.data or "", tags=[], strip=True)
            sched = form.scheduled_time.data
            try:
                if hasattr(sched, 'strftime'):
                    sched_str = sched.strftime("%Y-%m-%d %H:%M")
                else:
                    sched_str = str(sched)
            except Exception:
                sched_str = str(sched)

            booking = Booking(
                client_id=current_user.id,
                service_type_id=form.service_type.data,
                description=clean_desc,
                scheduled_time=sched_str
            )
            s.add(booking)
            s.commit()
            encrypted = multi_fernet.encrypt(str(current_user.id).encode()).decode()
            mapping = VisitMapping(
                ephemeral_visit_id=booking.ephemeral_visit_id,
                encrypted_user_id=encrypted
            )
            s.add(mapping)
            s.commit()
            audit_log(current_user.id, "create_booking", f"Booking {booking.id} created.")
            flash("Service requested. Worker will contact you.", "success")
            return redirect(url_for("dashboard"))
    finally:
        s.close()
    return render_template("book_service.html", form=form)

@app.route("/my_bookings")
@login_required
def my_bookings():
    s = SessionLocal()
    try:
        myb = s.query(Booking).options(joinedload(Booking.service_type)).filter_by(client_id=current_user.id).order_by(Booking.created_at.desc()).all()
    finally:
        s.close()
    return render_template("my_bookings.html", bookings=myb)


@app.route('/notifications', methods=['GET','POST'])
@login_required
def notifications():
    s = SessionLocal()
    try:
        if request.method == 'POST':
            nid = request.form.get('id')
            if nid:
                n = s.query(Notification).get(int(nid))
                if n and n.user_id == current_user.id:
                    n.read = True
                    s.commit()
                    audit_log(current_user.id, 'notification_read', f'Notification {n.id} marked read')
                    return redirect(url_for('notifications'))
            if request.form.get('mark_all'):
                s.query(Notification).filter_by(user_id=current_user.id, read=False).update({Notification.read: True})
                s.commit()
                audit_log(current_user.id, 'notifications_mark_all', 'Marked all notifications read')
                return redirect(url_for('notifications'))

        nots = s.query(Notification).filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    finally:
        s.close()
    return render_template('notifications.html', notifications=nots)

# Worker dashboard
@app.route("/worker")
@login_required
def worker_dashboard():
    if current_user.role not in ("worker", "admin"):
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))
    s = SessionLocal()
    try:
        open_bookings = s.query(Booking).options(joinedload(Booking.service_type), joinedload(Booking.client)).filter_by(status="requested").all()
        my_claims = []
        accepted = []
        completed_orders = []
        if current_user.role == "worker":
            my_claims = s.query(Booking).options(joinedload(Booking.service_type), joinedload(Booking.client)).filter_by(status="accepted", worker_id=current_user.id).all()
        else:
            accepted = s.query(Booking).options(joinedload(Booking.service_type), joinedload(Booking.client)).filter_by(status="accepted").all()
            completed_orders = s.query(Booking).options(joinedload(Booking.service_type), joinedload(Booking.client)).filter_by(status="completed").order_by(Booking.created_at.desc()).all()
    finally:
        s.close()
    return render_template("worker_dashboard.html", open_bookings=open_bookings, my_claims=my_claims, accepted=accepted, completed_orders=completed_orders)

@app.route("/claim/<int:booking_id>")
@login_required
def claim(booking_id):
    if current_user.role != "worker":
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))
    if not getattr(current_user, 'is_verified', False):
        flash("You must be verified by an administrator before claiming jobs. Upload your certificate and wait for verification.", "warning")
        return redirect(url_for('upload_certificate'))
    s = SessionLocal()
    try:
        b = s.query(Booking).get(booking_id)
        if not b:
            flash("Booking not found", "danger")
            return redirect(url_for("worker_dashboard"))
        b.status = "accepted"
        b.worker_id = current_user.id
        s.commit()
        note = Notification(user_id=b.client_id, message=f"Your booking {b.id} was accepted by a worker.")
        s.add(note)
        s.commit()
        audit_log(current_user.id, "claim_booking", f"Booking {b.id} claimed by user {current_user.username}.")
    finally:
        s.close()
    flash("Booking claimed", "success")
    return redirect(url_for("worker_dashboard"))

@app.route("/complete/<int:booking_id>", methods=["POST"])
@login_required
def complete(booking_id):
    if current_user.role != "worker":
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))
    s = SessionLocal()
    try:
        b = s.query(Booking).get(booking_id)
        if not b:
            flash("Booking not found", "danger")
            return redirect(url_for("worker_dashboard"))
        b.status = "completed"
        ephemeral_id = b.ephemeral_visit_id
        s.commit()
        audit_log(current_user.id, "complete_booking", f"Booking {b.id} completed.")
        if request.form.get("report_positive") == "1":
            mappings = s.query(VisitMapping).filter_by(ephemeral_visit_id=ephemeral_id).all()
            for m in mappings:
                try:
                    uid = int(multi_fernet.decrypt(m.encrypted_user_id.encode()).decode())
                    note = Notification(user_id=uid, message=f"Possible exposure detected for booking id {b.id}. Please follow guidelines.")
                    s.add(note)
                except Exception:
                    pass
            s.commit()
            audit_log(current_user.id, "report_positive", f"Reported positive for booking {b.id}.")
    finally:
        s.close()
    flash("Booking marked completed.", "success")
    return redirect(url_for("worker_dashboard"))

# Admin minimal page
@app.route("/admin")
@login_required
def admin():
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))
    s = SessionLocal()
    try:
        users = s.query(User).all()
        uploads_dir = app.config.get('UPLOAD_FOLDER') or os.path.join('instance', 'uploads')
        try:
            all_files = os.listdir(uploads_dir)
        except Exception:
            all_files = []
        for u in users:
            prefix = f"user_{u.id}_"
            u.uploads = [f for f in all_files if f.startswith(prefix)]
    finally:
        s.close()
    return render_template("admin.html", users=users)


@app.route('/admin/audit')
@login_required
def admin_audit():
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    actor = request.args.get('actor')
    action = request.args.get('action')
    try:
        limit = int(request.args.get('limit', 200))
    except Exception:
        limit = 200

    s = SessionLocal()
    try:
        q = s.query(AuditLog, User.username).outerjoin(User, AuditLog.user_id == User.id)
        if actor:
            q = q.filter(User.username == actor)
        if action:
            q = q.filter(AuditLog.action == action)
        rows = q.order_by(AuditLog.created_at.desc()).limit(limit).all()
        logs = []
        for a, uname in rows:
            logs.append({'id': a.id, 'user_id': a.user_id, 'username': uname, 'action': a.action, 'details': a.details, 'created_at': a.created_at})
    finally:
        s.close()
    return render_template('admin_audit.html', logs=logs)

@app.route("/admin/cleanup", methods=["POST"])
@login_required
def cleanup():
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))
    purge_old_mappings()
    flash("Old visit mappings purged for privacy", "success")
    return redirect(url_for("admin"))

# Admin actions
@app.route("/admin/block/<int:user_id>", methods=["POST"])
@login_required
def admin_block_user(user_id):
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("admin"))
    s = SessionLocal()
    try:
        u = s.query(User).get(user_id)
        if not u:
            flash("User not found", "danger")
            return redirect(url_for("admin"))
        uname = u.username
        u.is_blocked = True
        s.commit()
        audit_log(current_user.id, "admin_block_user", f"Blocked user {uname} ({u.id})")
        flash(f"User {uname} blocked.", "success")
    finally:
        s.close()
    return redirect(url_for("admin"))

@app.route("/admin/unblock/<int:user_id>", methods=["POST"])
@login_required
def admin_unblock_user(user_id):
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("admin"))
    s = SessionLocal()
    try:
        u = s.query(User).get(user_id)
        if not u:
            flash("User not found", "danger")
            return redirect(url_for("admin"))
        uname = u.username
        u.is_blocked = False
        s.commit()
        audit_log(current_user.id, "admin_unblock_user", f"Unblocked user {uname} ({u.id})")
        flash(f"User {uname} unblocked.", "success")
    finally:
        s.close()
    return redirect(url_for("admin"))


@app.route("/admin/verify/<int:user_id>", methods=["POST"])
@login_required
def admin_verify_user(user_id):
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("admin"))
    s = SessionLocal()
    try:
        u = s.query(User).get(user_id)
        if not u:
            flash("User not found", "danger")
            return redirect(url_for("admin"))
        uname = u.username
        u.is_verified = True
        s.commit()
        audit_log(current_user.id, "admin_verify_user", f"Verified user {uname} ({u.id})")
        flash(f"User {uname} marked as verified.", "success")
    finally:
        s.close()
    return redirect(url_for("admin"))


@app.route("/admin/unverify/<int:user_id>", methods=["POST"])
@login_required
def admin_unverify_user(user_id):
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("admin"))
    s = SessionLocal()
    try:
        u = s.query(User).get(user_id)
        if not u:
            flash("User not found", "danger")
            return redirect(url_for("admin"))
        uname = u.username
        u.is_verified = False
        s.commit()
        audit_log(current_user.id, "admin_unverify_user", f"Unverified user {uname} ({u.id})")
        flash(f"User {uname} marked as unverified.", "success")
    finally:
        s.close()
    return redirect(url_for("admin"))

@app.route("/admin/booking/<int:booking_id>/force_complete", methods=["POST"])
@login_required
def admin_force_complete(booking_id):
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("admin"))
    s = SessionLocal()
    try:
        b = s.query(Booking).get(booking_id)
        if not b:
            flash("Booking not found", "danger")
            return redirect(url_for("admin"))
        b.status = "completed"
        s.commit()
        note = Notification(user_id=b.client_id, message=f"Your booking {b.id} was marked completed by an administrator.")
        s.add(note)
        s.commit()
        audit_log(current_user.id, "admin_force_complete", f"Booking {b.id} force-completed by admin {current_user.username}.")
        flash("Booking marked completed.", "success")
    finally:
        s.close()
    return redirect(url_for("admin"))

@app.route("/admin/booking/<int:booking_id>/force_cancel", methods=["POST"])
@login_required
def admin_force_cancel(booking_id):
    if current_user.role != "admin":
        flash("Access denied", "danger")
        return redirect(url_for("admin"))
    s = SessionLocal()
    try:
        b = s.query(Booking).get(booking_id)
        if not b:
            flash("Booking not found", "danger")
            return redirect(url_for("admin"))
        b.status = "cancelled"
        s.commit()
        note = Notification(user_id=b.client_id, message=f"Your booking {b.id} was cancelled by an administrator.")
        s.add(note)
        s.commit()
        audit_log(current_user.id, "admin_force_cancel", f"Booking {b.id} force-cancelled by admin {current_user.username}.")
        flash("Booking cancelled.", "success")
    finally:
        s.close()
    return redirect(url_for("admin"))


@app.route('/admin/download_certificate/<path:filename>')
@login_required
def download_certificate(filename):
    # only admins can download
    if current_user.role != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('admin'))
    uploads_dir = app.config.get('UPLOAD_FOLDER') or os.path.join('instance', 'uploads')
    safe_files = []
    try:
        safe_files = os.listdir(uploads_dir)
    except Exception:
        pass
    if filename not in safe_files:
        flash('File not found', 'danger')
        return redirect(url_for('admin'))
    try:
        return send_from_directory(uploads_dir, filename, as_attachment=True)
    except Exception:
        flash('Failed to send file', 'danger')
        return redirect(url_for('admin'))

# Upload certificate route
@app.route("/upload_certificate", methods=["GET", "POST"])
@login_required
def upload_certificate():
    if current_user.role != "worker":
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))
    if getattr(current_user, 'is_verified', False):
        flash("Your account is already verified. No upload required.", "info")
        return redirect(url_for('worker_dashboard'))
    form = UploadCertificateForm()
    if form.validate_on_submit():
        file = request.files.get('certificate')
        if not file or file.filename == '':
            flash("No file selected", "danger")
            return redirect(url_for("upload_certificate"))
        if not allowed_file(file.filename):
            flash("File type not allowed", "danger")
            return redirect(url_for("upload_certificate"))
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{current_user.id}_{filename}")
        file.save(save_path)
        clean = antivirus_scan_stub(save_path)
        if not clean:
            try:
                os.remove(save_path)
            except Exception:
                pass
            audit_log(current_user.id, "upload_infected", f"Upload {filename} failed antivirus.")
            flash("Uploaded file failed antivirus scan and was rejected.", "danger")
            return redirect(url_for("upload_certificate"))
        audit_log(current_user.id, "upload_certificate", f"Uploaded certificate {filename}.")
        flash("Certificate uploaded successfully.", "success")
        return redirect(url_for("dashboard"))
    return render_template("upload_certificate.html", form=form)

# TOTP management endpoints
@app.route("/setup_totp")
@login_required
def setup_totp():
    s = SessionLocal()
    try:
        u = s.query(User).get(current_user.id)
        if not u:
            flash("User not found", "danger")
            return redirect(url_for("dashboard"))
        if not u.totp_secret:
            secret = pyotp.random_base32()
            u.totp_secret = secret
            s.commit()
        else:
            secret = u.totp_secret
        provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=u.username, issuer_name="HomeServices")
    finally:
        s.close()
    audit_log(current_user.id, "setup_totp", "User retrieved TOTP setup.")
    return render_template("setup_totp.html", provisioning_uri=provisioning_uri, secret=secret)

@app.route("/enable_totp", methods=["POST"])
@login_required
def enable_totp():
    code = request.form.get("code")
    s = SessionLocal()
    try:
        u = s.query(User).get(current_user.id)
        if not u or not u.totp_secret:
            flash("TOTP not configured", "danger")
            return redirect(url_for("dashboard"))
        if pyotp.TOTP(u.totp_secret).verify(code):
            u.totp_enabled = True
            s.commit()
            audit_log(current_user.id, "enable_totp", "User enabled TOTP.")
            flash("TOTP enabled for your account.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid TOTP code.", "danger")
            return redirect(url_for("setup_totp"))
    finally:
        s.close()

@app.route("/disable_totp", methods=["POST"])
@login_required
def disable_totp():
    s = SessionLocal()
    try:
        u = s.query(User).get(current_user.id)
        if not u:
            flash("User not found", "danger")
            return redirect(url_for("dashboard"))
        u.totp_enabled = False
        u.totp_secret = None
        s.commit()
        audit_log(current_user.id, "disable_totp", "User disabled TOTP.")
        flash("TOTP disabled.", "success")
        return redirect(url_for("dashboard"))
    finally:
        s.close()

if __name__ == "__main__":
    app.run(debug=True)
