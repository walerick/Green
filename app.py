from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import pandas as pd
import requests
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
# Add this at the top of your app.py
from collections import defaultdict

# Dictionary to store conversation history for each user
conversation_history = defaultdict(list)
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


# @app.route('/chat', methods=['POST'])
# def chat():
#     user_input = request.json.get('message')
#
#     headers = {
#         'Authorization': f'Bearer {API_KEY}',
#         'Content-Type': 'application/json'
#     }
#
#     data = {
#         "model": "deepseek/deepseek-chat:free",
#         "messages": [
#             {"role": "system", "content": "chat with me."},
#             {"role": "user", "content": user_input}
#         ]
#     }
#
#     response = requests.post(API_URL, json=data, headers=headers)
#
#     if response.status_code == 200:
#         chatbot_reply = response.json()['choices'][0]['message']['content']
#         return jsonify({'response': chatbot_reply})
#     else:
#         return jsonify({'error': 'Failed to fetch data from API'}), 500


# Then modify your chat route:
@app.route('/chat', methods=['POST'])
def chat():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user_input = request.json.get('message')
    username = session['username']

    # Get the user's conversation history
    messages = conversation_history.get(username, [])

    # Add system message if this is a new conversation
    if not messages:
        messages.append({"role": "system", "content": "You are a helpful assistant."})

    # Add user's new message
    messages.append({"role": "user", "content": user_input})

    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }

    data = {
        "model": "deepseek/deepseek-chat:free",
        "messages": messages
    }

    response = requests.post(API_URL, json=data, headers=headers)

    if response.status_code == 200:
        chatbot_reply = response.json()['choices'][0]['message']['content']

        # Add assistant's reply to the conversation history
        messages.append({"role": "assistant", "content": chatbot_reply})
        conversation_history[username] = messages

        return jsonify({'response': chatbot_reply})
    else:
        return jsonify({'error': 'Failed to fetch data from API'}), 500


# @app.route('/upload', methods=['POST'])
# def upload():
#     if 'file' not in request.files:
#         return jsonify({'error': 'No file uploaded'}), 400
#
#     file = request.files['file']
#
#     if file.filename == '':
#         return jsonify({'error': 'No selected file'}), 400
#
#     if not allowed_file(file.filename):
#         return jsonify({'error': 'Invalid file type. Only Excel files are allowed.'}), 400
#
#     filename = secure_filename(file.filename)
#     file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#     file.save(file_path)
#
#     try:
#         df = pd.read_excel(file_path)
#         excel_data = df.to_json(orient='records')
#
#         headers = {
#             'Authorization': f'Bearer {API_KEY}',
#             'Content-Type': 'application/json'
#         }
#
#         data = {
#             "model": "deepseek/deepseek-chat:free",
#             "messages": [
#                 {"role": "system", "content": "Analyze this Excel data and provide a concise summary."},
#                 {"role": "user", "content": excel_data}
#             ]
#         }
#
#         response = requests.post(API_URL, json=data, headers=headers)
#
#         if response.status_code == 200:
#             ai_response = response.json()['choices'][0]['message']['content']
#             return jsonify({'response': ai_response})
#         else:
#             return jsonify({'error': 'Failed to analyze Excel file'}), 500
#
#     except Exception as e:
#         return jsonify({'error': f'Error processing Excel file: {str(e)}'}), 500


@app.route('/upload', methods=['POST'])
def upload():
    # Check if user is logged in
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    # Check if file was uploaded
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']

    # Validate file
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only Excel files are allowed.'}), 400

    # Save file securely
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        # Read Excel file
        df = pd.read_excel(file_path)
        excel_data = df.to_json(orient='records')

        # Get or initialize conversation history
        username = session['username']
        messages = conversation_history.get(username, [])

        # Add system message if new conversation
        if not messages:
            messages.append({
                "role": "system",
                "content": "You are a helpful data analyst assistant. Analyze Excel data and provide insights."
            })

        # Add user's data with context about the file
        messages.append({
            "role": "user",
            "content": f"I've uploaded an Excel file named '{filename}' with the following data: {excel_data}. Please analyze it."
        })

        # Prepare API request
        headers = {
            'Authorization': f'Bearer {API_KEY}',
            'Content-Type': 'application/json'
        }

        data = {
            "model": "deepseek/deepseek-chat:free",
            "messages": messages
        }

        # Call API
        response = requests.post(API_URL, json=data, headers=headers)

        if response.status_code == 200:
            ai_response = response.json()['choices'][0]['message']['content']

            # Update conversation history
            messages.append({"role": "assistant", "content": ai_response})
            conversation_history[username] = messages

            # Clean up - remove the uploaded file
            if os.path.exists(file_path):
                os.remove(file_path)

            return jsonify({
                'response': ai_response,
                'filename': filename
            })
        else:
            # Clean up even if API call fails
            if os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({
                'error': 'Failed to analyze Excel file',
                'details': response.json()
            }), 500

    except Exception as e:
        # Clean up if any error occurs
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'error': f'Error processing Excel file',
            'details': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True)



