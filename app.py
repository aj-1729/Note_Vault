import os
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from cryptography.fernet import Fernet
# --- App Initialization ---
app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing

# --- Configuration ---
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', "a_strong_default_secret_key_for_dev")
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY', "a_different_strong_secret_key")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME') # Your Gmail address
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD') # Your Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')


# Database Configuration: Use environment variable for production, otherwise use local SQLite
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace("postgres://", "postgresql://", 1)
else:
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Database Configuration ---

# Check if we are on PythonAnywhere
if 'PYTHONANYWHERE_DOMAIN' in os.environ:
    # Configuration for PythonAnywhere's MySQL database
    DB_USER = os.environ.get('DB_USER')
    DB_PASSWORD = os.environ.get('DB_PASSWORD')
    DB_HOST = os.environ.get('DB_HOST')
    DB_NAME = os.environ.get('DB_NAME')
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    )
else:
    # Fallback to local SQLite database for development
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# --- Extensions Initialization ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY']) 


# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    encryption_key = db.Column(db.LargeBinary, nullable=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    #owner = db.relationship('User' , backref=db.backref('notes' , lazy=True))

    def to_dict(self):
        """Serializes the Note object to a dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'created_at': self.created_at.isoformat() + 'Z'
        }


from flask import Flask, jsonify, request, url_for

def encrypt_data(data, key):
   
    f = Fernet(key)
    return f.encrypt(data.encode('utf-8')).decode('utf-8')

def decrypt_data(encrypt_data, key):
   
    f = Fernet(key)
    return f.decrypt(encrypt_data.encode('utf-8')).decode('utf-8')

@app.route('/')
def health_check():
    """Health check endpoint to confirm the API is running."""
    return jsonify({"status": "API is running!"}), 200
# --- User Authentication Routes ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not password or not email:
        return jsonify({"message": "Username, email, and password are required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already exists"}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    encryption_key = Fernet.generate_key()
    new_user = User(username=username, email=email, password=hashed_password ,encryption_key=encryption_key)
    db.session.add(new_user)
    db.session.commit()

    # --- Send verification email ---
    token = s.dumps(email, salt='email-confirm')
    link = url_for('verify_email', token=token, _external=True)
    msg = Message('Please Confirm Your Email For NoteVault', recipients=[email])
    msg.body = f'Click on the verification link is {link}'
    mail.send(msg)
    # --- End of email sending ---

    return jsonify({"message": "User created. Please check your email to verify your account."}), 201


@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        # Token is valid for 1 hour (3600 seconds)
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        return '<h1>The confirmation link is invalid or has expired.</h1>'

    user = User.query.filter_by(email=email).first_or_404()
    user.is_verified = True
    db.session.commit()
    return '<h1>Your email has been verified! You can now log in.</h1>' # You can redirect to a frontend page




@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data.get('username') # Can be username or email
    password = data.get('password')

    user = User.query.filter(or_(User.username == identifier, User.email == identifier)).first()

    if not user:
        return jsonify({"message": "Incorrect username, email, or password"}), 401

    if not user.is_verified:
        return jsonify({"message": "Account not verified. Please check your email."}), 403 # 403 Forbidden

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token)

    return jsonify({"message": "Incorrect username, email, or password"}), 401



# --- Notes CRUD Routes ---
@app.route('/notes', methods=['GET'])
@jwt_required()
def get_notes():
    """Get all notes for the current user, with optional title search."""
    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)
    title_keyword = request.args.get('title')
    query = Note.query.filter_by(user_id=current_user_id).order_by(Note.created_at.desc())

    if title_keyword:
        all_notes = query.all()
        decrypted_notes = []
        for note in all_notes:
            try:
                decrypted_title = decrypt_data(note.title, user.encryption_key)
                if title_keyword.lower() in decrypted_title.lower():
                    decrypted_notes.append({
                        'id': note.id,
                        'title': decrypted_title,
                        'content': decrypt_data(note.content, user.encryption_key),
                        'created_at': note.created_at.isoformat() + 'Z'
                    })
            except Exception:
                continue 
        return jsonify(decrypted_notes)
    else:
        notes = query.all()
        decrypted_notes = [
            {
                'id': note.id,
                'title': decrypt_data(note.title, user.encryption_key),
                'content': decrypt_data(note.content, user.encryption_key),
                'created_at': note.created_at.isoformat() + 'Z'
            } for note in notes
        ]
        return jsonify(decrypted_notes)

@app.route('/notes/<int:note_id>', methods=['GET'])
@jwt_required()
def get_note(note_id):
    """Get a single note by its ID."""
    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)
    note = Note.query.filter_by(id=note_id, user_id=current_user_id).first()
    if not note:
        return jsonify({"msg": "Note not found"}), 404
    
    decrypted_note = {
        'id': note.id,
        'title': decrypt_data(note.title, user.encryption_key),
        'content': decrypt_data(note.content, user.encryption_key),
        'created_at': note.created_at.isoformat() + 'Z'
    }
    return jsonify(decrypted_note)

@app.route('/notes', methods=['POST'])
@jwt_required()
def create_note():
    """Create a new note."""
    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)
    data = request.get_json()
    if not data or 'title' not in data or 'content' not in data:
        return jsonify({'error': 'Bad Request: Missing title or content'}), 400
    

    encrypted_title = encrypt_data(data['title'], user.encryption_key)
    encrypted_content = encrypt_data(data['content'], user.encryption_key)

    new_note = Note(title=encrypted_title, content=encrypted_content, user_id=current_user_id)
    
    db.session.add(new_note)
    db.session.commit()

    response_data = {
        'id': new_note.id,
        'title': data['title'],
        'content': data['content'],
        'created_at': new_note.created_at.isoformat() + 'Z'
    }
    return jsonify(response_data), 201

@app.route('/notes/<int:note_id>', methods=['PUT'])
@jwt_required()
def update_note(note_id):
    """Update an existing note."""
    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)
    note = Note.query.filter_by(id=note_id, user_id=current_user_id).first()
    if not note:
        return jsonify({"msg": "Note not found"}), 404
    

    data = request.get_json()
    if 'title' in data:
        note.title = encrypt_data(data['title'], user.encryption_key)
    if 'content' in data:
        note.content = encrypt_data(data['content'], user.encryption_key)
    db.session.commit()

    decrypted_note = {
        'id': note.id,
        'title': decrypt_data(note.title, user.encryption_key),
        'content': decrypt_data(note.content, user.encryption_key),
        'created_at': note.created_at.isoformat() + 'Z'
    }

    return jsonify(decrypted_note)

@app.route('/notes/<int:note_id>', methods=['DELETE'])
@jwt_required()
def delete_note(note_id):
    """Delete a note."""
    current_user_id = int(get_jwt_identity())
    note = Note.query.filter_by(id=note_id, user_id=current_user_id).first()
    if not note:
        return jsonify({"msg": "Note not found"}), 404
    db.session.delete(note)
    db.session.commit()
    return jsonify({'message': 'Note deleted successfully'})

if __name__ == '__main__':
    # This block will create the database file if it doesn't exist
    # when you run `flask db upgrade`
    with app.app_context():
        # The db.create_all() is now handled by Flask-Migrate
        pass
    app.run(debug=True, port=5000)
