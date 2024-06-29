from flask import Flask, render_template, redirect, request, url_for
from models import db, User, Password
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from sqlalchemy.exc import SQLAlchemyError
from cryptography.fernet import Fernet, InvalidToken
from flask_migrate import Migrate
from dotenv import load_dotenv
import os

load_dotenv()
secret_key = os.getenv("SECRET_KEY")
database_url = os.getenv("DATABASE_URL")

# Ensure critical environment variables are set
if not secret_key:
    raise ValueError("No SECRET_KEY set for Flask application. Did you forget to set the environment variable?")
if not database_url:
    raise ValueError("No DATABASE_URL set for Flask application. Did you forget to set the environment variable?")

app = Flask(__name__)
app.config["SECRET_KEY"] = secret_key
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

key_path = os.path.join(os.path.dirname(__file__), 'secret.key')

def generate_key():
    return Fernet.generate_key()

def load_key():
    if os.path.exists(key_path):
        with open(key_path, 'rb') as key_file:
            return key_file.read()
    else:
        key = generate_key()
        with open(key_path, 'wb') as key_file:
            key_file.write(key)
        return key
    
key = load_key()
fernet = Fernet(key)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except User.DoesNotExist:
        return None


@app.route('/')
@login_required
def index():
    return redirect(url_for("home"))

@app.route('/home')
@login_required
def home():
    pwd_data = {}
    objects = Password.query.filter_by(username=current_user.username).all()

    for data in objects:
        try:
            decrypted_pwd = fernet.decrypt(data.encrypted_password)
            pwd_data[data.password_id] = {data.service_name: decrypted_pwd.decode()}
            
        except InvalidToken as e:
            pwd_data[data.password_id] = {data.service_name: "Error decrypting"}

    return render_template("home.html", username=current_user.username, pwd_datas=pwd_data, objects=objects)


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.hashed_password, password):
            login_user(user)
            return redirect(url_for("home"))
        else:
            return "Invalid username or password", 401

    return render_template("login.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_pass = request.form.get("confirm_pass")

        if not (username and email and password and confirm_pass):
            return "All fields are required", 400

        if password != confirm_pass:
            return "Passwords do not match", 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists", 400

        pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        try:
            new_user = User(username=username, email=email, hashed_password=pw_hash)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("login"))
        except SQLAlchemyError as e:
            db.session.rollback()
            return "Unexpected error", 500

    return render_template("register.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/create", methods=["POST", "GET"])
@login_required
def create():
    if request.method == "POST":
        service_name = request.form.get("service_name")
        password = request.form.get("password")
        username = current_user.username
        user_id =  current_user.user_id
        enc_pass = fernet.encrypt(password.encode())

        try:
            new_pw = Password(user_id=user_id, service_name=service_name, encrypted_password=enc_pass, username=username)
            db.session.add(new_pw)
            db.session.commit()
            return redirect(url_for("home"))
        except SQLAlchemyError as e:
            db.session.rollback()
            return "Unexpected error", 500
    return render_template("create.html")

        
@app.route('/update', methods=["POST", "GET"])
@login_required
def update():
    if request.method == "POST":
        pwd_id = request.form.get("password_id")
        service_name = request.form.get("service_name")
        password = request.form.get("password")

        pwd_record = Password.query.filter_by(password_id=pwd_id).first()
        
        if pwd_record:
            pwd_record.service_name = service_name
            enc_pwd = fernet.encrypt(password.encode())
            pwd_record.encrypted_password = enc_pwd
            db.session.commit()
            return redirect(url_for("home"))
        else:
            return render_template("error.html")
    
    pwd_id = request.args.get("password_id")
    pwd_record = Password.query.filter_by(password_id=pwd_id).first()
    if pwd_record:
        try:
            dec_pwd = fernet.decrypt(pwd_record.encrypted_password).decode()
        except Exception as e:
            dec_pwd = ''
            return render_template("error.html")

        return render_template("update.html", password_id = pwd_id, password=dec_pwd, service_name=pwd_record.service_name)
    else:
        return render_template("error.html")

@app.route('/delete', methods=["POST"])
@login_required
def delete():
    pwd_id = request.form.get("password_id")
    pwd_object = Password.query.filter_by(password_id=pwd_id).first()

    if pwd_object:
        db.session.delete(pwd_object)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("error.html")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
