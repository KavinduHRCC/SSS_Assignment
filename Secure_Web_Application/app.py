from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, escape
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, login_user, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
import os
import hashlib

#Secure Communication - All communication between clients and servers should be encrypted to prevent eavesdropping and man-in-the-middle attacks.
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) #SECRET_KEY is a random string used to sign cookies and other secure data
app.config['SESSION_TYPE'] = 'filesystem' #specifies that session data should be stored in the filesystem
app.config['SESSION_COOKIE_SECURE'] = True #SESSION_COOKIE_SECURE sets the secure flag on session cookies, meaning they will only be sent over HTTPS.
app.config['SESSION_COOKIE_HTTPONLY'] = True #sets the HttpOnly flag on session cookies, preventing them from being accessed by JavaScript.
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict' #sets the SameSite attribute on session cookies to Strict, meaning they will only be sent with requests originating from the same site.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' #specifies the database to be used for storing application data
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False #set to False to disable modification tracking, which can improve performance
db = SQLAlchemy(app) # managing the database
login_manager = LoginManager(app)
login_manager.login_view = 'login' #managing user authentication
login_manager.login_message_category = 'info' #specifies the type of flash message to display when the user is redirected

class User(db.Model, UserMixin): #This class represents a user in our web application and contains fields for their username, password (stored as a hashed string), and email address.
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self): #To provide a string representation of a user object
        return f"User('{self.username}', '{self.email}')"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/') #which displays a simple greeting
def home():
    return render_template('home.html')
    
#where users can create a new account
@app.route('/register', methods=['GET', 'POST']) 
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.')
            return redirect('/register')
        user = User(username=username, email=email, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created. Please log in.')
        return redirect('/login')
    else:
        return render_template('register.html')
        
#where users can log in to their account
@app.route('/login', methods=['GET', 'POST']) 
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/dashboard')
        else:
            flash('Invalid username or password.')
            return redirect('/login')
    else:
        return render_template('login.html')

@app.route('/dashboard') #that can only be accessed by logged-in users
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout') #route for logging out
@login_required
def logout():
    logout_user()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
