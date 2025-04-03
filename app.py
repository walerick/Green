from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import pandas as pd
import requests
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Configure Upload Folder
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Dummy user database (in production, use a real database)
users = {
    "admin": generate_password_hash("password123")
}

# Allowed file extensions
ALLOWED_EXTENSIONS = {'xls', 'xlsx'}

load_dotenv()
# API_KEY = os.getenv("OPENAI_API_KEY")
API_KEY = os.getenv("API_KEY")
# OpenRouter API Configuration

API_URL = 'https://openrouter.ai/api/v1/chat/completions'


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])


@app.route('/chat-interface')
def chat_interface():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html')


@app.route('/chat', methods=['POST'])
def chat():
    user_input = request.json.get('message')

    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }

    data = {
        "model": "deepseek/deepseek-chat:free",
        "messages": [
            {"role": "system", "content": "You can only talk about climate change. If I ask you anything asides that, tell me 'I'm not programmed for that'."},
            {"role": "user", "content": user_input}
        ]
    }

    response = requests.post(API_URL, json=data, headers=headers)

    if response.status_code == 200:
        chatbot_reply = response.json()['choices'][0]['message']['content']
        return jsonify({'response': chatbot_reply})
    else:
        return jsonify({'error': 'Failed to fetch data from API'}), 500


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only Excel files are allowed.'}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        df = pd.read_excel(file_path)
        excel_data = df.to_json(orient='records')

        headers = {
            'Authorization': f'Bearer {API_KEY}',
            'Content-Type': 'application/json'
        }

        data = {
            "model": "deepseek/deepseek-chat:free",
            "messages": [
                {"role": "system", "content": "Analyze this Excel data and provide a concise summary."},
                {"role": "user", "content": excel_data}
            ]
        }

        response = requests.post(API_URL, json=data, headers=headers)

        if response.status_code == 200:
            ai_response = response.json()['choices'][0]['message']['content']
            return jsonify({'response': ai_response})
        else:
            return jsonify({'error': 'Failed to analyze Excel file'}), 500

    except Exception as e:
        return jsonify({'error': f'Error processing Excel file: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True)



