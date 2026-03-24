import re
import logging
import os
from datetime import datetime

from flask import Flask, render_template, request, redirect, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, Email, Regexp, ValidationError
from flask_bcrypt import Bcrypt
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from sqlalchemy import text
from flask_wtf.file import FileField
from dotenv import load_dotenv
from functools import wraps

# -------------------- BASIC SETUP --------------------
app = Flask(__name__)

# Logging
logging.basicConfig(filename='error.log', level=logging.ERROR)

# -------------------- SECURITY HEADERS (TASK 1) --------------------
csp = {
    'default-src': ["'self'"],
    'style-src': ["'self'", "https://cdn.jsdelivr.net"],
    'script-src': ["'self'", "https://cdn.jsdelivr.net"]
}
Talisman(app, content_security_policy=csp, force_https=False)

# -------------------- RATE LIMITING (TASK 2) --------------------
app.config["RATELIMIT_STORAGE_URI"] = "memory://"
limiter = Limiter( 
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# -------------------- CONFIG --------------------
load_dotenv()

app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')

# Session Security
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

# File Upload Config (TASK 3)
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# -------------------- EXTENSIONS --------------------
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# -------------------- FORM --------------------
class PersonForm(FlaskForm):
    fname = StringField('First Name', validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp('^[A-Za-z]+$', message="Only letters allowed")
    ])
    lname = StringField('Last Name', validators=[
        DataRequired(),
        Length(min=2, max=50),
        Regexp('^[A-Za-z]+$', message="Only letters allowed")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email()
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6)
    ])
    submit = SubmitField('Submit')

    # 🚨 Attack detection
    def validate_fname(self, field):
        if re.search(r"(SELECT|INSERT|DELETE|DROP|--|'|<|>)", field.data, re.IGNORECASE):
            raise ValidationError("Invalid characters detected! Possible attack.")

    def validate_lname(self, field):
        if re.search(r"(SELECT|INSERT|DELETE|DROP|--|'|<|>)", field.data, re.IGNORECASE):
            raise ValidationError("Invalid characters detected! Possible attack.")

# -------------------- MODEL --------------------
class FirstApp(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)

class UploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Upload')

# -------------------- SIMULATE ADMIN task 5 ------------------
@app.route('/make_admin/<int:sno>')
def make_admin(sno):
    user = FirstApp.query.get(sno)
    user.is_admin = True
    db.session.commit()
    return "User is now admin!"

@app.route('/login/<int:sno>')
def login(sno):
    session['user_id'] = sno
    return f"Logged in as user {sno}"

def get_current_user():
    user_id = session.get('user_id')
    if user_id:
        return FirstApp.query.get(user_id)
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()

        if not user or not user.is_admin:
            abort(403)   # Forbidden

        return f(*args, **kwargs)
    return decorated_function

# -------------------- ROUTES --------------------

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def hello_world():
    session.permanent = True
    form = PersonForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')

        user = FirstApp(
            fname=form.fname.data,
            lname=form.lname.data,
            email=form.email.data,
            password=hashed_password
        )

        db.session.add(user)
        db.session.commit()

        flash("Record added successfully!", "success")
        return redirect('/')

    elif request.method == 'POST':
        flash("Invalid input. Possible attack detected.", "danger")

    allpeople = FirstApp.query.all()
    return render_template('index.html', allpeople=allpeople, form=form)

# -------------------- DELETE --------------------
@app.route('/delete/<int:sno>')
@admin_required
def delete(sno):
    person = FirstApp.query.get_or_404(sno)
    db.session.delete(person)
    db.session.commit()
    return redirect('/')

# -------------------- UPDATE --------------------
@app.route('/update/<int:sno>', methods=['GET', 'POST'])
@admin_required
def update(sno):
    person = FirstApp.query.get_or_404(sno)
    form = PersonForm(obj=person)

    if form.validate_on_submit():
        person.fname = form.fname.data
        person.lname = form.lname.data
        person.email = form.email.data

        # Update password ONLY if entered
        if form.password.data:
            person.password = bcrypt.generate_password_hash(
                form.password.data).decode('utf-8')

        db.session.commit()   # ✅ YOU FORGOT THIS BEFORE

        flash("Updated successfully!", "success")
        return redirect('/')

    elif request.method == 'POST':
        flash("Invalid input.", "danger")

    return render_template('update.html', form=form, person=person)

# -------------------- SAFE QUERY (TASK 2) --------------------
@app.route('/safe')
def safe():
    name = request.args.get('name')
    query = text("SELECT * FROM first_app WHERE fname = :name")
    result = db.session.execute(query, {"name": name})
    return str(list(result))

# -------------------- FILE UPLOAD (TASK 3) --------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    form = UploadForm()

    if form.validate_on_submit():
        file = form.file.data

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            flash("File uploaded securely!", "success")
            return redirect('/upload')
        else:
            flash("Invalid file type!", "danger")

    return render_template('upload.html', form=form)

# -------------------- ERROR HANDLING --------------------
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    logging.error(str(e))
    return render_template('500.html'), 500

# -------------------- MAIN --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)