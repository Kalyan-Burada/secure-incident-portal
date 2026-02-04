import os
import base64
import pyotp
import qrcode
import io
import datetime
from dotenv import load_dotenv

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from functools import wraps

# ------------------ CONFIG ------------------
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

ADMIN_SIGNUP_KEY = os.getenv('ADMIN_SIGNUP_KEY', 'ADMIN123')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ------------------ CRYPTO SETUP ------------------
if not os.path.exists("aes_key.key"):
    aes_key = Fernet.generate_key()
    with open("aes_key.key", "wb") as f:
        f.write(aes_key)
else:
    with open("aes_key.key", "rb") as f:
        aes_key = f.read()

cipher_suite = Fernet(aes_key)

if not os.path.exists("private_rsa.pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("private_rsa.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_rsa.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    with open("private_rsa.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("public_rsa.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

# ------------------ MODELS ------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(20))
    mfa_secret = db.Column(db.String(32))

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    encrypted_content = db.Column(db.LargeBinary)
    digital_signature = db.Column(db.Text)
    image_b64 = db.Column(db.Text)
    status = db.Column(db.String(20), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(100))
    action = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)

def log_action(user, action):
    db.session.add(AuditLog(user=user, action=action))
    db.session.commit()

# ------------------ ACCESS CONTROL ------------------
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                log_action(current_user.username, "UNAUTHORIZED ACCESS")
                return render_template("403.html"), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------ ROUTES ------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

# ---------- REGISTER ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        admin_key = request.form.get('admin_key', '')

        if role == 'Admin' and admin_key != ADMIN_SIGNUP_KEY:
            flash("Invalid Admin Key", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for('register'))

        mfa_secret = pyotp.random_base32()
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')

        session['reg'] = {
            'username': username,
            'password': hashed_pw,
            'role': role,
            'mfa': mfa_secret
        }
        return redirect(url_for('setup_mfa'))

    return render_template('register.html')

@app.route('/setup_mfa')
def setup_mfa():
    if 'reg' not in session:
        return redirect(url_for('register'))

    data = session['reg']
    uri = pyotp.TOTP(data['mfa']).provisioning_uri(
        name=data['username'], issuer_name="SecurePortal"
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render_template('mfa_setup.html', qr_code=qr_b64)

@app.route('/verify_mfa_creation', methods=['POST'])
def verify_mfa_creation():
    otp = request.form['otp']
    data = session.get('reg')

    if pyotp.TOTP(data['mfa']).verify(otp):
        user = User(
            username=data['username'],
            password_hash=data['password'],
            role=data['role'],
            mfa_secret=data['mfa']
        )
        db.session.add(user)
        db.session.commit()
        log_action("SYSTEM", f"User created: {user.username}")
        session.clear()
        flash("Account created successfully", "success")
        return redirect(url_for('login'))

    flash("Invalid OTP", "danger")
    return redirect(url_for('setup_mfa'))

# ---------- LOGIN STEP 1 ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            session['pre_2fa'] = user.id
            return redirect(url_for('login_2fa'))
        flash("Invalid credentials", "danger")
    return render_template('login.html')

# ---------- LOGIN STEP 2 ----------
@app.route('/login_2fa', methods=['GET', 'POST'])
def login_2fa():
    if 'pre_2fa' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        user = User.query.get(session['pre_2fa'])
        if pyotp.TOTP(user.mfa_secret).verify(request.form['otp']):
            login_user(user)
            session.pop('pre_2fa')
            log_action(user.username, "Login successful")
            return redirect(url_for('dashboard'))
        flash("Invalid OTP", "danger")

    return render_template('login_2fa.html')

# ---------- FORGOT PASSWORD ----------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if not user:
            flash("Invalid user", "danger")
            return redirect(url_for('forgot_password'))

        if not pyotp.TOTP(user.mfa_secret).verify(request.form['otp']):
            flash("Invalid OTP", "danger")
            return redirect(url_for('forgot_password'))

        user.password_hash = generate_password_hash(
            request.form['new_password'], method='pbkdf2:sha256'
        )
        db.session.commit()
        log_action(user.username, "Password reset via MFA")
        flash("Password reset successful", "success")
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

# ---------- DASHBOARD ----------
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'Employee':
        reports = Report.query.filter_by(user_id=current_user.id).all()
    else:
        reports = Report.query.all()
    return render_template('dashboard.html', reports=reports, role=current_user.role)

# ---------- SUBMIT REPORT ----------
@app.route('/submit', methods=['POST'])
@login_required
@role_required(['Employee'])
def submit_report():
    text = request.form['description']
    file = request.files['image']

    signature = private_key.sign(
        text.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    encrypted = cipher_suite.encrypt(text.encode())
    img_b64 = base64.b64encode(file.read()).decode() if file else ""

    report = Report(
        user_id=current_user.id,
        encrypted_content=encrypted,
        digital_signature=base64.b64encode(signature).decode(),
        image_b64=img_b64
    )

    db.session.add(report)
    db.session.commit()
    log_action(current_user.username, "Submitted report")
    flash("✅ Incident submitted securely. Your report has been encrypted.", "success")
    return redirect(url_for('dashboard'))

# ---------- VIEW REPORT ----------
@app.route('/view/<int:id>')
@login_required
@role_required(['Admin', 'Analyst'])
def view_report(id):
    report = Report.query.get(id)
    text = cipher_suite.decrypt(report.encrypted_content).decode()

    valid = True
    try:
        public_key.verify(
            base64.b64decode(report.digital_signature),
            text.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except:
        valid = False

    return render_template('view_report.html',
                           text=text, valid=valid, image=report.image_b64)

# ---------- ADMIN PANEL ROUTES (ADDED ONLY THESE) ----------
@app.route('/manage_users')
@login_required
@role_required(['Admin'])
def manage_users():
    users = User.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
    return render_template('manage_users.html', users=users, logs=logs)

@app.route('/delete_user/<int:id>')
@login_required
@role_required(['Admin'])
def delete_user(id):
    user = User.query.get(id)
    if user and user.id != current_user.id:
        db.session.delete(user)
        db.session.commit()
        log_action(current_user.username, f"Deleted User: {user.username}")
        flash("User deleted successfully.", "success")
    return redirect(url_for('manage_users'))

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

# ------------------ MAIN ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
