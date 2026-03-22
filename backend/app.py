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