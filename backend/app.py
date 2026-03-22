# crypto_engine.py
# Kishan Ratnasingam 100754728
# SOFE 4840U - Computer Security
import os
import sys
import base64
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from flask_session import Session
from backend.vault_manager import save_vault, load_vault, vault_exists

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')

from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'key' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    if 'key' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # just show the login page
        return render_template('login.html')
    
    if request.method == 'POST':
        data = request.get_json()
        key = base64.b64decode(data['key'])
    
    # brand new user — no vault exists yet
    if not vault_exists():
        save_vault([], key)  # create empty vault
        session['key'] = data['key']
        session['credentials'] = []
        session.permanent = True
        return jsonify({"success": True})
    
    # existing user — try to load vault
    credentials = load_vault(key)
    
    if credentials is None:
        return jsonify({"success": False, "error": "Invalid master password"}), 401
    
    session['key'] = data['key']
    session['credentials'] = credentials
    session.permanent = True
    return jsonify({"success": True})