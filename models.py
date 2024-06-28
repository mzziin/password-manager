from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    hashed_password = db.Column(db.String(120), nullable=False)

    passwords = db.relationship('Password', backref='user', lazy=True, cascade="all, delete-orphan")
    def get_id(self):
        return str(self.user_id)

class Password(db.Model):
    __tablename__ = 'passwords'

    password_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    service_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100))
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
