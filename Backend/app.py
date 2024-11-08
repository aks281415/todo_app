from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_cors import CORS

app = Flask(__name__)

CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'  # SQLite database ka path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
app.config['JWT_SECRET_KEY'] = 'f9e8bcfad67947af9a3ebf8495e38f4a5f9d8ba1d964a3f4f58dfe1ac3912d3f'

db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "User already exists!"}), 409

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], password=hashed_password)

    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully!"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({"message": "Login failed! Check username and password."}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({"message": f"Welcome {user.username}!", "access_token": access_token}), 200

@app.route('/api/tasks', methods=['POST'])
@jwt_required()
def add_task():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    new_task = Task(title=data['title'], user_id=current_user_id)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({"message": "Task added successfully!", "task": {"id": new_task.id, "title": new_task.title}}), 201

@app.route('/api/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user_id = get_jwt_identity()
    tasks = Task.query.filter_by(user_id=current_user_id).all()
    task_list = [{"id": task.id, "title": task.title, "date_created": task.date_created} for task in tasks]
    return jsonify(task_list), 200

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_tasks(task_id):
    current_user_id = get_jwt_identity()
    task = Task.query.filter_by(id=task_id, user_id=current_user_id).first_or_404()

    data = request.get_json()
    task.title = data['title']
    db.session.commit()

    return jsonify({"message": "Task updated successfully!", "task": {"id": task.id, "title": task.title}})

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    current_user_id = get_jwt_identity()  # Get the current logged-in user ID
    task = Task.query.filter_by(id=task_id, user_id=current_user_id).first_or_404()

    db.session.delete(task)
    db.session.commit()

    return jsonify({"message": "Task deleted successfully!"}), 200

@app.route('/')
def home():
    return jsonify({"message": "Welcome to the To-Do App!"})

if __name__ == '__main__':
    app.run(debug=True)
