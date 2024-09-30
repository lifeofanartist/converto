from flask import Flask, render_template, redirect, request, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import pytesseract
import os
from werkzeug.utils import secure_filename

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Wrap create_all in an application context
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html')
        
        # Validate password strength
        if len(password) < 8 or not any(char.isdigit() for char in password) or \
           not any(char.isupper() for char in password) or \
           not any(char.islower() for char in password) or \
           not any(char in '!@#$%^&*' for char in password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, digit, and special character.', 'error')
            return render_template('register.html')
        
        # If all validations pass, create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect('/convert')
        else:
            flash('Login failed. Check your password.')
    return render_template('login.html')

@app.route('/convert', methods=['GET', 'POST'])
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['image']
        language = request.form['language']
        
        if file and allowed_file(file.filename):
            # Create the 'temp' directory if it doesn't exist
            temp_dir = os.path.join(os.path.dirname(__file__), 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            
            # Save the file temporarily
            filename = secure_filename(file.filename)
            file_path = os.path.join(temp_dir, filename)
            file.save(file_path)
            
            try:
                # Open the image using PIL
                image = Image.open(file_path)
                
                # Perform OCR based on the selected language
                if language == 'eng':
                    text = pytesseract.image_to_string(image, lang='eng')
                elif language == 'nep':
                    text = pytesseract.image_to_string(image, lang='nep')
                else:
                    text = "Unsupported language selected"
                
                # Remove the temporary file
                os.remove(file_path)
                
                return render_template('convert.html', text=text, username=user.username)
            except Exception as e:
                # If any error occurs during processing, remove the file and show an error message
                if os.path.exists(file_path):
                    os.remove(file_path)
                return render_template('convert.html', error=f"An error occurred: {str(e)}", username=user.username)
    
    return render_template('convert.html', text=None, username=user.username)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()

