from flask import Flask, render_template, redirect, request
from models import db, User, Password
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)
app.config["SECRET_KEY"] = "admin@123"
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "postgresql://mazin:123@localhost:5432/pswd_mngr"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except User.DoesNotExist:
        return None

@app.route("/")
def index():
    return redirect("/login")

@app.route("/home")
@login_required
def home():
    user_id = current_user.user_id
    user = User.query.filter_by(user_id=user_id).first()
    return render_template("home.html", username = user.username)

@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.hashed_password, password):
            login_user(user)
            return redirect("/home")
        else:
            return "Invalid username or password", 401

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
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
            return redirect("/login")
        except SQLAlchemyError as e:
            db.session.rollback()
            return "Unexpected error", 500

    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
