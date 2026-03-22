# crypto_engine.py
# Kishan Ratnasingam 100754728
# SOFE 4840U - Computer Security
import os
import sys
import base64
from flask import Flask, json, request, session, redirect, url_for, render_template, jsonify
from flask_session import Session
from backend.vault_manager import save_vault, load_vault, vault_exists, VAULT_PATH

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__,
            template_folder=os.path.join(BASE_DIR, 'frontend', 'templates'),
            static_folder=os.path.join(BASE_DIR, 'frontend', 'static'))
app.config["SECRET_KEY"] = "sofe4840-password-manager-secret-key"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = "./flask_session"
app.config["PERMANENT_SESSION_LIFETIME"] = 300
app.config["SESSION_PERMANENT"] = True

Session(app)
from functools import wraps
#add login_required decorator to protect routes that require authentication
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'key' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Set up server-side sessions
@app.route('/')
def index():
    if 'key' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# This route checks if the vault file exists and returns the salt if it does. The frontend can use this to determine if the user is new or returning, and to get the salt for key derivation.
@app.route('/get-salt')
def get_salt():
    if not vault_exists():
        return jsonify({"exists": False})
    
    with open(VAULT_PATH, 'r') as f:
        vault_data = json.load(f)
    
    return jsonify({
        "exists": True,
        "salt": vault_data['salt']
    })

#add route for login that accepts POST requests with the master key, tries to load the vault, and returns success or failure
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # just show the login page
        return render_template('login.html')
    
    if request.method == 'POST':
        data = request.get_json()
        key = base64.b64decode(data['key'])
        salt = base64.b64decode(data['salt'])
    
    if not vault_exists():
        save_vault([], key, salt)
        session['key'] = data['key']
        session['credentials'] = []
        session.permanent = True
        return jsonify({"success": True})
    
    credentials = load_vault(key)
    
    if credentials is None:
        return jsonify({"success": False, "error": "Invalid master password"}), 401
    
    session['key'] = data['key']
    session['credentials'] = credentials
    session.permanent = True
    return jsonify({"success": True})

#add route for dashboard that shows credentials, requires login
@app.route('/dashboard')
@login_required
def dashboard():
    credentials = session.get('credentials', [])
    return render_template('dashboard.html', credentials=credentials)

#add route for adding a credential
@app.route('/add', methods=['POST'])
@login_required
def add():
    data = request.get_json()
    
    # get current credentials from session
    credentials = session.get('credentials', [])
    
    # build new credential
    new_credential = {
        "service": data['service'],
        "username": data['username'],
        "password": data['password']
    }
    
    # add to list
    credentials.append(new_credential)
    
    # get key and save vault
    key = base64.b64decode(session['key'])
    save_vault(credentials, key)
    
    # update session
    session['credentials'] = credentials
    
    return jsonify({"success": True})

#add route for deleting a credential by index
@app.route('/delete', methods=['POST'])
@login_required
def delete():
    data = request.get_json()
    index = data['index']
    
    credentials = session.get('credentials', [])
    
    #handle invalid index
    if index < 0 or index >= len(credentials):
        return jsonify({"success": False, "error": "Invalid index"}), 400
    
    credentials.pop(index)
    
    key = base64.b64decode(session['key'])
    save_vault(credentials, key)
    session['credentials'] = credentials
    
    return jsonify({"success": True})

# The `logout` route clears the user's session and redirects them to the login page,
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))