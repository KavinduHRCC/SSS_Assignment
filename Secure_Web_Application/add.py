from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask application
app = Flask(__name__)

# Set up configuration options for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret'

# Initialize database object
db = SQLAlchemy(app)

# Define user model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.name}>'

# Define insert function to add new user to database
@app.route('/insert', methods=['POST'])
def insert():
    name = request.form['name']
    email = request.form['email']
    password = generate_password_hash(request.form['password'])

    # Check if user already exists
    user = User.query.filter_by(email=email).first()
    if user:
        flash('Email address already exists')
        return redirect(url_for('index'))

    # Create new user
    new_user = User(name=name, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()
    flash('User successfully created')
    return redirect(url_for('index'))

# Define index function to display existing users
@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)
