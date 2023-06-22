from flask import Flask, render_template, Response, request, jsonify, session, flash, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_socketio import SocketIO, emit, send
import requests
from dotenv import load_dotenv
import re
import os
from datetime import timedelta
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VideoGrant

app = Flask(__name__)
socketio = SocketIO(app)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=1)
app.config['SECRET_KEY'] = 'Sankalp@893'

login_manager = LoginManager(app)
login_manager.login_view = 'login'

load_dotenv()


join_requests = []
def send_join_request(username):
    join_requests.append(username)  
    # Notify the admin or perform any other desired action

def get_join_requests():
    return join_requests if session['username'] == 'admin' else []

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


# Twilio API credentials
account_sid = os.getenv('TWILIO_ACCOUNT_SID')
api_key = os.getenv('TWILIO_API_KEY')
api_secret = os.getenv('TWILIO_API_SECRET')
room_name = "sankalp's room"


@app.route('/dashboard')
@login_required
def dashboard():
    join_requests = get_join_requests()
    return render_template('dashboard.html', join_requests=join_requests)


@app.route('/token', methods=['POST'])
@login_required
def generate_token():
    # Get user identity from the request data
    user_identity = request.form.get('user_identity')

    # Create a Twilio access token
    token = AccessToken(account_sid, api_key, api_secret, identity=user_identity)

    # Create a video grant and add it to the token
    video_grant = VideoGrant(room=room_name)
    token.add_grant(video_grant)

    # Return the token as a JSON response
    return jsonify(token=token.to_jwt().decode())

# Azure Blob Storage link for the movie
movie_url = "https://streamxonline.blob.core.windows.net/streamx/The.Hobbit.An.Unexpected.Journey.mp4"

@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Validate the credentials
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'Sankalp' and password == 'Sankalp@893':
            user = User(username)
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@socketio.on('sdp')
def handle_sdp(sdp):
    emit('sdp', sdp, broadcast=True, include_self=False)


@socketio.on('ice_candidate')
def handle_ice_candidate(candidate):
    emit('ice_candidate', candidate, broadcast=True, include_self=False)


@socketio.on('join_request')
def handle_join_request(data):
    username = data['username']
    send_join_request(username)
    emit('join_request_notification', username, broadcast=True, include_self=False)

@app.route('/video')
@login_required
def video():
    range_header = request.headers.get('Range', 'bytes=0-')
    size = None

    # Make a HEAD request to get the file size
    head_response = requests.head(movie_url)
    if 'Content-Length' in head_response.headers:
        size = int(head_response.headers['Content-Length'])

    # Parse range header
    byte1, byte2 = 0, None
    match = re.search('(\d+)-(\d*)', range_header)
    groups = match.groups()

    byte1 = int(groups[0])
    if groups[1]:
        byte2 = int(groups[1])

    if byte2 is None:
        byte2 = size - 1

    length = byte2 - byte1 + 1

    # Make a GET request to get the content
    headers = {'Range': f'bytes={byte1}-{byte2}'}
    response = requests.get(movie_url, headers=headers, stream=True)

    # Serve video stream
    def generate():
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                yield chunk

    rv = Response(generate(), 206, mimetype='video/mp4')
    rv.headers.add('Content-Range', f'bytes {byte1}-{byte2}/{size}')
    rv.headers.add('Accept-Ranges', 'bytes')
    rv.headers.add('Content-Length', str(length))

    return rv


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)


