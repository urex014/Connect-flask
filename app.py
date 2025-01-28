from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, send, join_room, leave_room
import os
import os



# Initialize Flask app and extensions
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


# Initialize extensions to start the sqlite and websocket when app.py is initiated
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, cors_allowed_origins="*")

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    profile_photo = db.Column(db.String(150), default='default.jpg')
    
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('splash.html')


@app.route('/splash2.html')
def splash2():
    return render_template('splash2.html')

@app.route('/auth')
def auth():
    return render_template('auth.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('signup.html', error="Passwords do not match")

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('signup.html', error="This username is already taken")

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('chat_list'))

        return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')

@app.route('/chat_list', methods=['GET', 'POST'])
@login_required
def chat_list():
    
    user_data = []
    query = request.form.get('search', '')

    if query:
        users = User.query.filter(User.username.ilike(f"%{query}%"), User.id != current_user.id).all()
    else:
        # Fetch users who have exchanged messages with current user
        subquery = db.session.query(
            db.func.max(Message.timestamp).label('latest_timestamp'),
            db.case(
                (Message.sender_id == current_user.id, Message.recipient_id),
                else_=Message.sender_id
            ).label('user_id')
        ).filter(
            (Message.sender_id == current_user.id) | (Message.recipient_id == current_user.id)
        ).group_by(db.case(
            (Message.sender_id == current_user.id, Message.recipient_id),
            else_=Message.sender_id
        )).subquery()

        users = db.session.query(User, subquery.c.latest_timestamp).join(
            subquery, User.id == subquery.c.user_id
        ).order_by(subquery.c.latest_timestamp.desc()).all()

    for user_entry in users:
        user = user_entry if isinstance(user_entry, User) else user_entry[0]
        last_message = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.recipient_id == user.id)) |
            ((Message.sender_id == user.id) & (Message.recipient_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()

        user_data.append({
            'id': user.id,
            'username': user.username,
            'profile_photo': user.profile_photo,
            'last_message': last_message.content if last_message else "No messages yet",
        })
    
    # Render the chat_list.html template with the user data
    return render_template('chat_list.html', users=user_data)
from flask import jsonify, request
from flask_login import login_required, current_user
# ... other imports

@app.route('/search_users')
@login_required
def search_users():
    query = request.args.get('q', '').strip().lower()
    if query:
        users = User.query.filter(
            User.username.ilike(f"%{query}%"), User.id != current_user.id
        ).all()
    else:
        users = []

    user_data = [
        {
            "id": user.id,
            "username": user.username,
            "profile_photo": user.profile_photo,
        }
        for user in users
    ]

    return jsonify(user_data) 

    



@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    other_user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        content = request.form.get('message', '').strip()
        if content:
            # Save the message to the database
            new_message = Message(sender_id=current_user.id, recipient_id=user_id, content=content)
            db.session.add(new_message)
            db.session.commit()

            # Redirect to refresh the page
            return redirect(url_for('chat', user_id=user_id)) 

    # Fetch all messages between the two users
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp).all()

    return render_template('chat.html', recipient=other_user, messages=messages)


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/update_profile_photo', methods=['POST'])
@login_required
def update_profile_photo():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('settings'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('settings'))
    
    if file and allowed_file(file.filename):
        # Secure the filename and save it to the upload folder
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the file
        file.save(filepath)

        # Update the current user's profile_photo field in the database
        current_user.profile_photo = filename
        db.session.commit()
        updated_user = User.query.get(current_user.id)
        print(updated_user.profile_photo)

        flash('Profile photo updated successfully!')
        return redirect(url_for('settings'))
    
    flash('Invalid file type. Please upload an image.')
    return redirect(url_for('settings'))


@socketio.on('join_room')
def on_join(data):
    room = str(data['room'])
    join_room(room)
    print(f" {current_user.username} has joined room: {room}")

@socketio.on('leave_room')
def on_leave(data):
    room = str(data['room'])
    leave_room(room)
    print(f"{current_user.username} has left room: {room}")

@socketio.on('new_message')
def handle_new_message(data):
    room = str(data['recipient_id'])
    send(data, room=room)
    socketio.emit('new_message', data, room=room)
    print(f"New message from {data['username']} to room {room}")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
    with app.app_context():
        db.create_all()
    socketio.run(app, debug=True)