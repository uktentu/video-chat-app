from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
from datetime import datetime
import uuid
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))

# Database configuration
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', logger=True, engineio_logger=True)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Create tables before first request
@app.before_first_request
def create_tables():
    db.create_all()

# Store active users in each room
active_users = {}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='author', lazy=True)
    meetings = db.relationship('Meeting', backref='creator', lazy=True)

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    meeting_id = db.Column(db.String(8), unique=True, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='meeting', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    meeting_id = db.Column(db.Integer, db.ForeignKey('meeting.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    if current_user.is_authenticated:
        meetings = Meeting.query.filter_by(creator_id=current_user.id).all()
        return render_template('home.html', meetings=meetings)
    return render_template('home.html')

def generate_meeting_id(length=8):
    """Generate a shorter meeting ID using a combination of timestamp and random characters"""
    timestamp = hex(int(datetime.utcnow().timestamp()))[2:6]  # 4 chars from timestamp
    random_chars = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length-4))
    return timestamp + random_chars

@app.route('/create_meeting', methods=['POST'])
@login_required
def create_meeting():
    title = request.form.get('title', 'New Meeting')
    meeting_id = generate_meeting_id()
    
    meeting = Meeting(
        meeting_id=meeting_id,
        title=title,
        creator_id=current_user.id
    )
    
    db.session.add(meeting)
    db.session.commit()
    
    return redirect(url_for('chat', meeting_id=meeting_id))

@app.route('/join_meeting', methods=['POST'])
@login_required
def join_meeting():
    meeting_id = request.form.get('meeting_id')
    meeting = Meeting.query.filter_by(meeting_id=meeting_id).first()
    
    if not meeting:
        flash('Invalid meeting ID!', 'error')
        return redirect(url_for('home'))
        
    return redirect(url_for('chat', meeting_id=meeting_id))

@app.route('/chat/<meeting_id>')
@login_required
def chat(meeting_id):
    meeting = Meeting.query.filter_by(meeting_id=meeting_id).first()
    if not meeting:
        flash('Invalid meeting ID!', 'error')
        return redirect(url_for('home'))
        
    messages = Message.query.filter_by(meeting_id=meeting.id).order_by(Message.timestamp.desc()).limit(50).all()
    return render_template('chat.html', messages=messages, meeting=meeting)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if user already exists
        user_exists = User.query.filter_by(username=username).first()
        email_exists = User.query.filter_by(email=email).first()
        
        if user_exists:
            flash('Username already exists!', 'error')
            return redirect(url_for('signup'))
        
        if email_exists:
            flash('Email already registered!', 'error')
            return redirect(url_for('signup'))
        
        # Hash password and create user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!', 'error')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@socketio.on('send_message')
def handle_message(data):
    if not current_user.is_authenticated:
        return
    
    meeting = Meeting.query.filter_by(meeting_id=data['meeting_id']).first()
    if not meeting:
        return
    
    message = Message(
        content=data['message'],
        user_id=current_user.id,
        meeting_id=meeting.id
    )
    db.session.add(message)
    db.session.commit()
    
    emit('receive_message', {
        'message': message.content,
        'username': current_user.username,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    }, room=data['meeting_id'])

@socketio.on('join')
def on_join(data):
    if not current_user.is_authenticated:
        return
        
    meeting_id = data['room']
    join_room(meeting_id)
    
    if meeting_id not in active_users:
        active_users[meeting_id] = {}
    
    active_users[meeting_id][current_user.id] = current_user.username
    
    emit('user_joined', {
        'userId': current_user.id,
        'username': current_user.username
    }, room=meeting_id, include_self=False)
    
    for user_id, username in active_users[meeting_id].items():
        if user_id != current_user.id:
            emit('user_joined', {
                'userId': user_id,
                'username': username
            }, room=request.sid)

@socketio.on('leave')
def on_leave(data):
    if not current_user.is_authenticated:
        return
        
    room = data['room']
    leave_room(room)
    
    if room in active_users and current_user.id in active_users[room]:
        del active_users[room][current_user.id]
        if not active_users[room]:
            del active_users[room]
    
    emit('user_left', {
        'userId': current_user.id,
        'username': current_user.username
    }, room=room)

@socketio.on('offer')
def handle_offer(data):
    if not current_user.is_authenticated:
        return
        
    target_id = data.get('targetUserId')
    if not target_id:
        return
        
    emit('offer', {
        'sdp': data['sdp'],
        'userId': current_user.id,
        'username': current_user.username
    }, room=target_id)

@socketio.on('answer')
def handle_answer(data):
    if not current_user.is_authenticated:
        return
        
    target_id = data.get('targetUserId')
    if not target_id:
        return
        
    emit('answer', {
        'sdp': data['sdp'],
        'userId': current_user.id,
        'username': current_user.username
    }, room=target_id)

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    if not current_user.is_authenticated:
        return
        
    target_id = data.get('targetUserId')
    if not target_id:
        return
        
    emit('ice_candidate', {
        'candidate': data['candidate'],
        'userId': current_user.id,
        'username': current_user.username
    }, room=target_id)

@socketio.on('disconnect')
def on_disconnect():
    if not current_user.is_authenticated:
        return
        
    # Remove user from all active rooms
    for room in active_users:
        if current_user.id in active_users[room]:
            del active_users[room][current_user.id]
            if not active_users[room]:
                del active_users[room]
            emit('user_left', {
                'userId': current_user.id,
                'username': current_user.username
            }, room=room)

@app.route('/dashboard')
@login_required
def dashboard():
    meetings = Meeting.query.filter_by(creator_id=current_user.id).order_by(Meeting.created_at.desc()).all()
    return render_template('dashboard.html', meetings=meetings)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    socketio.run(app, host='0.0.0.0', port=port, debug=False) 