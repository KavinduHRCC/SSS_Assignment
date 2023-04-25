from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
from app import app, db
"""The sqlalchemy module is an Object-Relational Mapping (ORM) library for Python that allows you to interact with databases using Python code rather than SQL.
werkzeug.security provides utilities for working with password hashing and verification. datetime is a module for working with dates and times, and 
jwt is a package for working with JSON Web Tokens."""

# db is instance of a SQLAlchemy database

class User(db.Model): # The User model contains columns for user id, name, email, password_hash, and a relationship to the Token model. It has methods to generate and verify JSON web tokens (JWTs) for user authentication.
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(128), nullable=False)
    email = Column(String(128), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    tokens = relationship('Token', backref='user', lazy='dynamic') #allowing each user to have multiple authentication tokens associated with their account

    def __init__(self, name, email, password): # Initializes a new user object with the provided name, email, and password. 
        self.name = name
        self.email = email
        self.password_hash = generate_password_hash(password) #The password is hashed using the generate_password_hash function from the werkzeug.security module.

    def verify_password(self, password): # Checks if the provided password matches the hashed password for the user.
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=3600):
    """Generates a JSON web token (JWT) for the user's authentication. 
    The token contains a subject claim (sub) with the user's id, an issued at claim (iat) with the current time, 
    and an expiration claim (exp) with a default expiration time of 3600 seconds (1 hour). 
    The token is encoded using the jwt.encode function from the jwt module, with a secret key specified in the Flask application's configuration."""
        now = datetime.utcnow()
        payload = {
            'sub': self.id,
            'iat': now,
            'exp': now + timedelta(seconds=expires_in)
        }
        return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token): # Verifies the provided JWT and returns the corresponding User object if the token is valid, or None if the token is invalid or has expired.
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            return User.query.get(payload['sub'])
        except:
            return None

class Token(db.Model):
    __tablename__ = 'tokens'
    id = Column(Integer, primary_key=True)
    token = Column(String(1024), nullable=False, unique=True) #  A string column for the authentication token, which cannot be null and must be unique
    user_id = Column(Integer, ForeignKey('users.id')) # An integer foreign key referencing the id column of the User model

    def __init__(self, token, user_id): 
        self.token = token # sets the token attribute of the instance to the value of the token argument
        self.user_id = user_id # sets the user_id attribute of the instance to the value of the user_id argument.
