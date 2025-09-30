import os
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from flask_migrate import Migrate

# --- App Initialization ---
app = Flask(__name__)
CORS(app) # Enable Cross-Origin Resource Sharing

# --- Configuration ---
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', "a_strong_default_secret_key_for_dev")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

# Database Configuration: Use environment variable for production, otherwise use local SQLite
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace("postgres://", "postgresql://", 1)
else:
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Extensions Initialization ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def to_dict(self):
        """Serializes the Note object to a dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'created_at': self.created_at.isoformat() + 'Z'
        }

# --- API Routes ---

@app.route('/')
def health_check():
    """Health check endpoint to confirm the API is running."""
    return jsonify({"status": "API is running!"}), 200

# --- User Authentication Routes ---
@app.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Please try another username"}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created Successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    """Log in a user and return a JWT access token."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token)
    return jsonify({"msg": "Incorrect username or password"}), 401

# --- Notes CRUD Routes ---
@app.route('/notes', methods=['GET'])
@jwt_required()
def get_notes():
    """Get all notes for the current user, with optional title search."""
    current_user_id = int(get_jwt_identity())
    title_keyword = request.args.get('title')
    query = Note.query.filter_by(user_id=current_user_id).order_by(Note.created_at.desc())
    if title_keyword:
        query = query.filter(Note.title.ilike(f'%{title_keyword}%'))
    notes = query.all()
    return jsonify([note.to_dict() for note in notes])

@app.route('/notes/<int:note_id>', methods=['GET'])
@jwt_required()
def get_note(note_id):
    """Get a single note by its ID."""
    current_user_id = int(get_jwt_identity())
    note = Note.query.filter_by(id=note_id, user_id=current_user_id).first()
    if not note:
        return jsonify({"msg": "Note not found"}), 404
    return jsonify(note.to_dict())

@app.route('/notes', methods=['POST'])
@jwt_required()
def create_note():
    """Create a new note."""
    current_user_id = int(get_jwt_identity())
    data = request.get_json()
    if not data or 'title' not in data or 'content' not in data:
        return jsonify({'error': 'Bad Request: Missing title or content'}), 400
    new_note = Note(title=data['title'], content=data['content'], user_id=current_user_id)
    db.session.add(new_note)
    db.session.commit()
    return jsonify(new_note.to_dict()), 201

@app.route('/notes/<int:note_id>', methods=['PUT'])
@jwt_required()
def update_note(note_id):
    """Update an existing note."""
    current_user_id = int(get_jwt_identity())
    note = Note.query.filter_by(id=note_id, user_id=current_user_id).first()
    if not note:
        return jsonify({"msg": "Note not found"}), 404
    data = request.get_json()
    note.title = data.get('title', note.title)
    note.content = data.get('content', note.content)
    db.session.commit()
    return jsonify(note.to_dict())

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
