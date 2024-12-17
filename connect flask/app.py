from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename
import os

# Initialize Flask app and extensions
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    profile_photo = db.Column(db.String(150), default = 'default.jpg')

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

    # Search logic
    if query:
        users = User.query.filter(User.username.contains(query), User.id != current_user.id).all()
    else:
        # Default: Fetch users who have exchanged messages with current user
        subquery = db.session.query(
            db.func.max(Message.timestamp).label('latest_timestamp'),
            db.case(
                (Message.sender_id == current_user.id, Message.recipient_id),
                else_=Message.sender_id
            ).label('user_id')
        ).filter(
            (Message.sender_id == current_user.id) | (Message.recipient_id == current_user.id)
        ).group_by('user_id').subquery()

        users = db.session.query(User, subquery.c.latest_timestamp).join(
            subquery, User.id == subquery.c.user_id
        ).order_by(subquery.c.latest_timestamp.desc()).all()

    # Map user data
    for user in users:
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

    return render_template('chat_list.html', users=user_data)




@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    other_user = User.query.get_or_404(user_id)  # Ensure other_user is loaded

    if request.method == 'POST':
        content = request.form.get('message', ' ')
        if content.strip():
            # Create a new message
            new_message = Message(sender_id=current_user.id, recipient_id=user_id, content=content)
            db.session.add(new_message)

            # Update the recipient's last message preview
            other_user.last_message = content
            db.session.commit()

        return redirect(url_for('chat', user_id=user_id))

    # Fetch messages between the current user and the other user
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp).all()

    return render_template('chat.html', recipient=other_user, messages=messages)

@app.route('/search_users', methods=['GET'])
@login_required
def search_users():
    query = request.args.get('q', '')
    users = User.query.filter(User.username.contains(query), User.id != current_user.id).all()
    return jsonify([{'id': user.id, 'username': user.username} for user in users])


@app.route('/update_profile_photo', methods=['POST'])
@login_required
def update_profile_photo():
    if 'profile_photo' in request.files:
        profile_photo = request.files['profile_photo']
        if profile_photo:
            filename = secure_filename(profile_photo.filename)
            filepath = os.path.join('static/uploads', filename)
            profile_photo.save(filepath)

            # Update the user's profile photo in the database
            current_user.profile_photo = filename
            db.session.commit()

    return redirect(url_for('settings'))



@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        if 'profile_photo' in request.files:
            profile_photo = request.files['profile_photo']
            if profile_photo:
                filename = secure_filename(profile_photo.filename)
                filepath = os.path.join('static/uploads', filename)
                profile_photo.save(filepath)

                # Update the user's profile photo URL in the database
                current_user.profile_photo = filename
                db.session.commit()

        return redirect(url_for('settings'))

    return render_template('settings.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
