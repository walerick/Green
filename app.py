from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
import pandas as pd
import requests
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from collections import defaultdict
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import Forbidden
from cryptography.fernet import Fernet
import base64


# Dictionary to store conversation history for each user
conversation_history = defaultdict(list)
app = Flask(__name__)
# app.secret_key = 'your_secret_key_here'
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
# Initialize CSRF protection
csrf = CSRFProtect(app)
app.config.update(
    WTF_CSRF_TIME_LIMIT=3600,  # 1 hour token expiration
    WTF_CSRF_SSL_STRICT=False  # Only send CSRF cookie over HTTPS
)

# Configure Upload Folder
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Dummy user database (in production, use a real database)
users = {
    "User": generate_password_hash("password123")
}

# Allowed file extensions
ALLOWED_EXTENSIONS = {'xls', 'xlsx'}

load_dotenv()
# API_KEY = os.getenv("OPENAI_API_KEY")
API_KEY = os.getenv("API_KEY")
# OpenRouter API Configuration


# Initialize encryption
def initialize_encryption():
    # Generate or load encryption key
    encryption_key = os.environ.get('ENCRYPTION_KEY')
    return Fernet(encryption_key.encode())


cipher_suite = initialize_encryption()


# Encryption functions
def encrypt_data(data: str) -> str:
    """Encrypt sensitive data before storage/transmission"""
    if not data:
        return data
    encrypted = cipher_suite.encrypt(data.encode())
    return base64.b64encode(encrypted).decode()  # For safe storage


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data when needed"""
    if not encrypted_data:
        return encrypted_data
    decoded = base64.b64decode(encrypted_data.encode())
    return cipher_suite.decrypt(decoded).decode()

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

@app.route('/file-analysis')
def file_analysis():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('file_analysis.html')


@app.route('/analyze-file', methods=['POST'])
def analyze_file():
    if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
        csrf.protect()
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

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

        # Create fresh messages for each analysis (no history)
        messages = [{
            "role": "user",
            "content": f"Analyze this Excel data: {excel_data}. Format results as a markdown table with columns: ID, Industry, Purpose, Green."
        }, {
            "role": "system",
            "content": """Your task is to classify financial records into green finance categories. You will be provided with an Excel file that includes the following columns: ID, Industry, Purpose, and Green category.  

                Your job is to analyze each row and determine if it matches one of the categories listed below.  

                OUTPUT REQUIREMENTS:
                1. Format the results as a markdown table with exactly these columns: "ID", "Industry", "Purpose", "Green"
                2. For each record, classify it as either:
                   - 'Green - [Category Name]' (e.g., 'Green - Renewable Energy')
                   - 'Not Green Finance'
                3. Only use the categories provided. Do not create new ones or infer beyond what is listed.

                Here's an example of how the output should look:
                | ID | Industry | Purpose | Green |
                |----|----------|---------|-------|
                | 1 | Manufacturing | Solar panel production | Green - Solar Energy Utilization Equipment |
                | 2 | Construction | Office building construction | Not Green Finance |

                Guidance Catalogue for Green and Low-Carbon Transformation Industries:
                [Your task is to classify financial records into green finance categories. You will be provided with an Excel file that includes the following columns: ID, Industry, Purpose, and Green category.  Your job is to analyze each row and determine if it matches one of the categories listed below.  If a record matches one of the green finance categories, classify it as:  ‘Green – [Category Name]’  (e.g., ‘Green – Renewable Energy’)  If a record does not match any category, classify it as:  ‘Not Green Finance’  Only use the categories provided. Do not create new ones or infer beyond what is listed.  Guidance Catalogue for Green and Low-Carbon Transformation Industries    1. Energy Conservation and Carbon Reduction Industry  1.1 High-Efficiency Energy-Saving Equipment Manufacturing  1.1.1 Manufacturing of energy-saving boilers  1.1.2 Manufacturing of energy-saving kilns  1.1.3 Manufacturing of energy-saving internal combustion engines  1.1.4 Manufacturing of high-efficiency generators and generator sets  1.1.5 Manufacturing of energy-saving pumps and vacuum equipment  1.1.6 Manufacturing of energy-saving gas compression equipment  1.1.7 Manufacturing of energy-saving electric motors and micro-special motors  1.1.8 Manufacturing of energy-saving fans and blowers  1.1.9 Manufacturing of energy-saving transformers, rectifiers, inductors, and welding machines  1.1.10 Manufacturing of high-efficiency energy-saving magnetic levitation power equipment  1.1.11 Manufacturing of energy-saving agricultural supplies  1.1.12 Manufacturing of energy-saving mining and construction materials production equipment  1.1.13 Manufacturing of high-efficiency energy-saving low-carbon commercial equipment  1.1.14 Manufacturing of high-efficiency energy-saving low-carbon household appliances  1.1.15 Manufacturing of high-efficiency lighting products and systems  1.1.16 Manufacturing of high-efficiency energy-saving stoves and cooking equipment  1.1.17 Manufacturing of waste heat, waste pressure, and waste gas utilization equipment  1.1.18 Manufacturing of green building materials  1.1.19 Manufacturing of energy measurement, testing, monitoring, and control equipment    1.2 Advanced Transportation Equipment Manufacturing  1.2.1 Manufacturing of key components for new energy vehicles  1.2.2 Manufacturing of green ships (excluding shipyard construction)  1.2.3 Manufacturing of advanced rail transit equipment  1.2.4 Manufacturing of advanced high-efficiency aviation equipment  1.2.5 Manufacturing of advanced port loading and unloading equipment    1.3 Energy Conservation and Carbon Reduction Retrofit  1.3.1 Energy-saving retrofit and efficiency improvement of boilers (kilns)  1.3.2 Efficiency improvement of steam turbine generator systems  1.3.3 Efficiency improvement of motor systems  1.3.4 Energy-saving retrofit of power grids  1.3.5 Utilization of waste heat and waste pressure  1.3.6 Optimization of energy systems  1.3.7 Green lighting retrofit  1.3.8 Green and low-carbon upgrading of ships    1.4 Green and Low-Carbon Transformation of Key Industrial Sectors  1.4.1 Energy conservation, carbon reduction retrofit, and efficiency improvement  1.4.2 Process improvement and workflow optimization  1.4.3 Digitalization and intelligent upgrading  1.5 Greenhouse Gas Control  1.5.1 Carbon Capture, Utilization, and Storage  1.5.2 Development and Utilization of Ozone-Depleting Substance Substitutes  1.5.3 Greenhouse Gas Emission Reduction in Industrial Production Processes    2 Environmental Protection Industry  2.1 Manufacturing of Advanced Environmental Protection Equipment and Raw Materials  2.1.1 Manufacturing of Air Pollution Control Equipment  2.1.2 Manufacturing of Water Pollution Control Equipment  2.1.3 Manufacturing of Soil Pollution Treatment and Remediation Equipment  2.1.4 Manufacturing of Equipment for Collection, Storage, Transportation, and Disposal of Solid Waste  2.1.5 Manufacturing of Noise and Vibration Control Equipment  2.1.6 Manufacturing of Radioactive Pollution Prevention and Treatment Equipment  2.1.7 Manufacturing of Environmental Pollution Treatment Agents and Materials  2.1.8 Production and Substitution of Non-toxic and Harmless Raw Materials and Products  2.1.9 Production of High-Efficiency, Low-Toxicity, and Low-Residue Pesticides  2.1.10 Manufacturing of Environmental Monitoring Instruments and Emergency Response Equipment  2.1.11 Manufacturing of Pollution Control Equipment for Convention-Regulated Chemical Substances  2.1.12 Manufacturing of Low (or Zero) Pollution Emission Equipment    2.2 Air Pollution Control  2.2.1 Industrial Desulfurization, Denitrification, and Dust Removal Retrofit  2.2.2 Ultra-Low Emission Retrofit in Key Industries  2.2.3 Comprehensive Treatment of Volatile Organic Compounds (VOCs)  2.2.4 Control of Fugitive Air Pollutant Emissions from Industrial Plants and Mines  2.2.5 Comprehensive Treatment of Urban Dust Pollution  2.2.6 Control of Cooking Fume Pollution from the Catering Industry  2.2.7 Control of Atmospheric Ammonia Emissions    2.3 Water Pollution Control  2.3.1 Protection of Water Bodies and Groundwater Pollution Prevention  2.3.2 Water Environment Treatment in Key River Basins and Marine Areas  2.3.3 Treatment of Black and Odorous Water Bodies in Cities (Including County-Level Cities)  2.3.4 Water Pollution Control in Key Industries  2.3.5 Centralized Water Pollution Control in Industrial Parks    2.4 Soil Pollution Control  2.4.1 Treatment of Agricultural Land Pollution  2.4.2 Treatment of Pollution on Construction Land  2.4.3 Prevention and Control of Non-Point Source Pollution in Agriculture, Forestry, and Grasslands  2.4.4 Desert Pollution Control    2.5 Other Pollution Control and Comprehensive Environmental Remediation  2.5.1 Harmless Treatment and Disposal of Industrial Solid Waste  2.5.2 Treatment and Disposal of Hazardous Waste  2.5.3 Noise and Vibration Pollution Control  2.5.4 Control of Odor Pollution  2.5.5 Treatment of Emerging Pollutants  2.5.6 Clean Production Retrofit in Key Industries  2.5.7 Centralized Transformation of Pollution Control in Industrial Parks  2.5.8 Pollution Control for Transportation Vehicles and Vessels  2.5.9 Pollution Prevention and Control for Ships and Ports  2.5.10 Pollution Control of Livestock and Aquaculture Waste  2.5.11 Improvement of Rural Living Environment  3 Resource Recycling Industry  3.1 Resource Recycling Equipment Manufacturing  3.1.1 Manufacturing of Comprehensive Utilization Equipment for Mineral Resources    3.1.2 Manufacturing of High-Efficiency and Recycling Water Resource Utilization Equipment    3.1.3 Manufacturing of Comprehensive Utilization Equipment for Industrial Solid Waste    3.1.4 Manufacturing of Comprehensive Utilization Equipment for Agricultural and Forestry Waste    3.1.5 Manufacturing of Recycling Equipment for Used Materials    3.1.6 Manufacturing of Waste Resource Utilization Equipment    3.1.7 Manufacturing of Waste Gas Recovery and Utilization Equipment    3.2 Resource Recycling  3.2.1 Comprehensive Utilization of Mineral Resources    3.2.2 High-Efficiency and Recycling Utilization of Water Resources    3.2.3 Comprehensive Utilization of Industrial Solid Waste    3.2.4 Comprehensive Utilization of Agricultural and Forestry Waste    3.2.5 Recycling and Utilization of Used Materials    3.2.6 Waste Resource Utilization    3.2.7 Waste Gas Recovery and Utilization    3.2.8 Circular Transformation of Industrial Parks    3.2.9 Efficient Processing and Recycling of Wood    4 Green and Low-Carbon Energy Transition  4.1 New and Clean Energy Equipment Manufacturing  4.1.1 Manufacturing of Wind Power Equipment    4.1.2 Manufacturing of Solar Energy Utilization Equipment    4.1.3 Manufacturing of Biomass Energy Utilization Equipment    4.1.4 Manufacturing of Hydropower and Pumped Storage Equipment    4.1.5 Manufacturing of Nuclear Power Equipment    4.1.6 Manufacturing of Gas Turbine Equipment    4.1.7 Manufacturing of Geothermal Energy Development and Utilization Equipment    4.1.8 Manufacturing of Ocean Energy Development and Utilization Equipment    4.1.9 Manufacturing of Unconventional Oil and Gas Equipment    4.1.10 Manufacturing of Offshore Oil and Gas Equipment    4.1.11 Manufacturing of New Energy Storage Products    4.1.12 Full-Chain Equipment Manufacturing for Hydrogen Energy Production, Storage, Transportation, and Utilization    4.1.13 Manufacturing of Smart Grid Products and Equipment    4.2 Clean Energy Infrastructure Construction and Operation  4.2.1 Wind Power Facility Construction and Operation    4.2.2 Solar Energy Utilization Facility Construction and Operation    4.2.3 Biomass Energy Utilization Facility Construction and Operation    4.2.4 Large-Scale Hydropower Facility Construction and Operation    4.2.5 Nuclear Power Plant and Nuclear Energy Comprehensive Utilization Facility Construction and Operation    4.2.6 Geothermal Energy Utilization Facility Construction and Operation    4.2.7 Ocean Energy Utilization Facility Construction and Operation    4.2.8 Hydrogen Energy Infrastructure Construction and Operation    4.2.9 Heat Pump Facility Construction and Operation    4.3 Safe and Efficient Operation of Energy Systems  4.3.1 Construction and Operation of Integrated Power Generation, Grid, Load, and Storage Systems and Multi-Energy Complementary Projects    4.3.2 Construction and Operation of New Energy Storage Facilities    4.3.3 Construction and Operation of Pumped Storage Power Stations    4.3.4 Renovation and Upgrading of Small Hydropower Stations    4.3.5 Construction and Operation of Smart Grids    4.3.6 Construction and Operation of New Power Load Management Systems    4.3.7 Construction and Operation of Natural Gas Transmission, Storage, and Peak Shaving Facilities    4.3.8 Construction and Operation of Distributed Energy Projects    4.3.9 Digital and Intelligent Upgrading of the Energy Industry    4.4 Clean and Low-Carbon Transition of Traditional Energy  4.4.1 Clean Coal Production    4.4.2 Clean and Efficient Utilization of Coal    4.4.3 Energy-Saving and Carbon-Reduction Transformation, Heating Transformation, Flexibility Transformation, and Clean and Efficient Supporting Power Construction for Coal Power Units    4.4.4 Clean Fuel Production    4.4.5 Clean Production of Crude Oil and Natural Gas    4.4.6 Development of Unconventional Oil and Gas Resources    4.4.7 Extraction and Utilization of Coalbed Methane (Coal Mine Gas)    4.4.8 Methane Recovery and Utilization in Oil and Gas Fields    5 Ecological Protection, Restoration, and Utilization  5.1 Ecological Agriculture, Forestry, Animal Husbandry, and Fishery  5.1.1 Modern Breeding and Seedling Cultivation    5.1.2 Conservation of Germplasm Resources    5.1.3 Green Agricultural Production    5.1.4 Organic and Green-Certified Agriculture    5.1.5 Construction and Operation of Protected Areas and Protected Farmlands    5.1.6 Green Prevention and Control of Crop Diseases and Pests    5.1.7 Recreational Agriculture and Rural Tourism    5.1.8 Protection and Restoration of Agricultural Ecosystems    5.1.9 Cultivation and Management of Forest Resources    5.1.10 Conservation of Forestry Genetic Resources    5.1.11 Understory Planting, Breeding, and Collection    5.1.12 Forest Recreation and Health Tourism    5.1.13 Bamboo Industry    5.1.14 Green Animal Husbandry    5.1.15 Green Fishery    5.1.16 Construction and Operation of Marine Ranches    5.2 Ecological Protection and Restoration  5.2.1 Biodiversity Conservation  5.2.2 Establishment and Protective Operation of Nature Reserves  5.2.3 Protection and Restoration of Natural Forests  5.2.4 Grassland Protection and Restoration  5.2.5 Construction and Operation of Forest and Grassland Fire Prevention and Extinguishing Systems  5.2.6 Comprehensive Control of Desertification and Rocky Desertification  5.2.7 Comprehensive Control of Soil Erosion  5.2.8 Ecological Protection and Restoration in Key Areas  5.2.9 Integrated Protection and Restoration of Mountains, Rivers, Forests, Farmlands, Lakes, Grasslands, and Deserts  5.2.10 Prevention and Control of Harmful Biological Disasters  5.2.11 Prevention, Control, and Response to Drought and Flood Disasters in Aquatic Ecosystems  5.2.12 Wetland Protection and Restoration  5.2.13 Marine Ecology, Coastal Zones, and Island Ecological Restoration  5.2.14 Stock Enhancement and Release  5.3 Comprehensive Land Management  5.3.1 Comprehensive Management of Coal Mining Subsidence Areas  5.3.2 Management and Restoration of Over-Extracted Groundwater Areas  5.3.3 Comprehensive Land Management  5.3.4 Restoration and Ecological Rehabilitation of Mining Geological Environments  6 Green Infrastructure Upgrades  6.1 Building Energy Efficiency and Green Buildings  6.1.1 Construction and Operation of Green Buildings    6.1.2 Construction and Operation of Ultra-Low Energy and Low-Carbon Buildings    6.1.3 Green Renovation and Operation of Existing Buildings    6.1.4 Construction, Renovation, and Operation of Green Rural Housing    6.1.5 Application of Renewable Energy in Buildings    6.1.6 Design and Construction of Prefabricated Buildings    6.1.7 Intelligent Construction of Building Projects    6.2 Green Transportation  6.2.1 Construction of Green Highways and Low-Carbon Upgrades to Highway Infrastructure    6.2.2 Green Renovation of Transportation Hubs and Stations    6.2.3 Construction and Operation of Charging, Battery Swapping, and Gas Refueling Facilities    6.2.4 Construction and Operation of Intelligent Transportation Systems    6.2.5 Construction and Operation of Shared Transportation Facilities    6.2.6 Construction and Operation of Urban-Rural Passenger Transport Systems    6.2.7 Construction and Operation of Urban Slow-Traffic Systems    6.2.8 Construction and Operation of Environmentally Friendly Railways and Railway Green Upgrades    6.2.9 Construction and Operation of Multimodal Transport Systems and Road-to-Rail/Road-to-Water Transport    6.2.10 Construction and Operation of Highway Drop-and-Hook Transport Systems    6.2.11 Green Civil Aviation    6.2.12 Green Ports and Waterways    6.3 Green Logistics  6.3.1 Construction and Operation of Green Logistics Hubs and Green Logistics Parks    6.3.2 Construction of Green Warehousing Facilities (Including Cold Storage)    6.3.3 Construction and Operation of Green Grain Storage and Logistics Facilities    6.3.4 Application of Green Logistics Technology and Equipment    6.4 Environmental Infrastructure  6.4.1 Construction, Maintenance, and Operation of Landscaping and Greening    6.4.2 Construction and Operation of Sponge Cities    6.4.3 Construction and Operation of District Metered Leak Control in Urban Water Supply Networks    6.4.4 Intelligent Construction of Water Conservancy Facilities    6.4.5 Inspection, Renovation, Construction, and Restoration of Urban Sewage Collection Systems    6.4.6 Investigation, Rectification, and Standardized Construction of Outfalls into Rivers and Seas    6.4.7 Construction and Operation of Wastewater and Sludge Treatment and Disposal Facilities    6.4.8 Construction and Operation of Municipal Solid Waste Collection, Transport, and Treatment Facilities    6.4.9 Construction and Operation of Ecological and Environmental Monitoring Systems    6.4.10 Construction and Operation of Ecological Security Early Warning Systems and Ecological Protection and Restoration Information Platforms    6.5 Urban-Rural Energy Infrastructure  6.5.1 Intelligent Construction, Operation, and Upgrading of Urban Power Facilities    6.5.2 Construction and Operation of Integrated Urban Energy Supply Facilities    6.5.3 Clean and Low-Carbon Construction, Operation, and Upgrading of Urban Centralized Heating Systems    6.5.4 Construction and Operation of Rural Clean Energy Infrastructure    6.6 Information Infrastructure  6.6.1 Energy-Saving Upgrades for Communication Network Facilities    6.6.2 Construction of Green Data Centers    6.6.3 Energy-Saving Upgrades for Data Centers    7 Green Services  7.1 Consulting and Supervision  7.1.1 Survey Services for Green and Low-Carbon Transition Industry Projects    7.1.2 Consulting and Design Services for Green and Low-Carbon Transition Industry Projects    7.1.3 Construction Supervision Services for Green and Low-Carbon Transition Industry Projects    7.1.4 Other Consulting Services Related to Green and Low-Carbon Transition Industries    7.2 Operation Management  7.2.1 Development of Energy Management Systems    7.2.2 Contract Energy Management    7.2.3 Contract Water Conservation Management    7.2.4 Demand-Side Power Management    7.2.5 Third-Party Services for Resource Recycling and Utilization    7.2.6 Third-Party Governance of Environmental Pollution    7.2.7 Digital Empowerment for Green and Low-Carbon Management    7.3 Monitoring and Testing  7.3.1 Construction of Online Energy Consumption Monitoring Systems    7.3.2 Monitoring of Greenhouse Gas Emission Sources    7.3.3 Environmental Damage Monitoring and Assessment    7.3.4 Pollution Source Monitoring    7.3.5 Corporate Environmental Monitoring  7.3.6 Ecological Environment Monitoring and Ecological Security Early Warning  7.3.7 Ecosystem Carbon Sink Monitoring and Assessment  7.3.8 Carbon Monitoring and Assessment    7.4 Evaluation, Review, and Verification  7.4.1 Energy-Saving Assessment and Energy Auditing  7.4.2 Energy-Saving and Energy Efficiency Diagnosis  7.4.3 Carbon Emission-Related Accounting, Verification, and Other Services  7.4.4 Building Energy Efficiency and Carbon Emission Assessment  7.4.5 Cleaner Production Audit  7.4.6 Environmental Impact Assessment  7.4.7 Ecological Environment Quality Monitoring and Assessment  7.4.8 Identification and Assessment of Natural Resource Ecological Protection Compensation and Asset Damage Compensation  7.4.9 Ecological Protection and Restoration Product and Ecosystem Assessment  7.4.10 Geological Disaster Risk Assessment  7.4.11 Soil and Water Conservation Assessment  7.4.12 Green Manufacturing Evaluation    7.5 Green Technology Product R&D, Certification, and Promotion  7.5.1 Green Technology Product Research and Development  7.5.2 Green Technology Product Certification and Promotion  7.5.3 Green Technology Transactions    7.6 Resource and Environmental Rights Trading  7.6.1 Carbon Trading  7.6.2 Energy Use Rights Trading  7.6.3 Water Use Rights Trading  7.6.4 Emission Rights Trading  7.6.5 Forest Rights Trading  7.6.6 Renewable Energy Green Certificates and Green Power Trading ]
                """
            # (Keep the same long system message as before)
        }]

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
            ai_response = response.json()['choices'][0]['message']['content']

            # Clean up file immediately
            if os.path.exists(file_path):
                os.remove(file_path)

            return jsonify({
                'response': ai_response,
                'filename': filename,
                'raw_data': excel_data  # Include raw data for fallback
            })
        else:
            if os.path.exists(file_path):
                os.remove(file_path)
            return jsonify({
                'error': 'Failed to analyze Excel file',
                'details': response.text
            }), 500

    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        return jsonify({
            'error': 'Error processing Excel file',
            'details': str(e)
        }), 500

def classify_as_green(record):
    """Implement your actual green classification logic here"""
    # This is a placeholder - replace with your actual classification logic
    purpose = str(record.get('Purpose', '')).lower()
    industry = str(record.get('Industry', '')).lower()

    green_keywords = ['renewable', 'solar', 'wind', 'green', 'sustainable',
                      'energy efficiency', 'eco-friendly', 'conservation']

    for keyword in green_keywords:
        if keyword in purpose or keyword in industry:
            return "Green"

    return "Not Green"




@app.route('/chat', methods=['POST'])
def chat():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    user_input = request.json.get('message')
    if not user_input:
        return jsonify({'error': 'No message provided'}), 400

    # Encrypt the user input before storing
    encrypted_input = encrypt_data(user_input)
    username = session['username']

    # Get conversation history (with encrypted messages)
    messages = conversation_history.get(username, [])

    # Add system message if new conversation
    if not messages:
        system_msg = encrypt_data("Your name is Greenelle, so you should introduce yourself properly. I might later want to discuss with you about different things so you should limit the conversation to these topics without explicitly telling me youre doing so [Green Finance, Sustainable finance, Climate change].")  # Encrypt system message too
        messages.append({"role": "system", "content": system_msg})

    # Add encrypted user message
    messages.append({"role": "user", "content": encrypted_input})

    # Prepare messages for API (decrypting only what's needed)
    api_messages = []
    for msg in messages:
        decrypted_content = decrypt_data(msg['content'])
        api_messages.append({
            "role": msg['role'],
            "content": decrypted_content
        })

    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }

    data = {
        "model": "deepseek/deepseek-chat:free",
        "messages": api_messages
    }

    try:
        response = requests.post(API_URL, json=data, headers=headers)
        if response.status_code == 200:
            ai_response = response.json()['choices'][0]['message']['content']

            # Encrypt AI response before storing
            encrypted_response = encrypt_data(ai_response)
            messages.append({"role": "assistant", "content": encrypted_response})
            conversation_history[username] = messages

            return jsonify({'response': ai_response})
        else:
            return jsonify({
                'error': 'Failed to fetch data from API',
                'details': response.text
            }), 500
    except Exception as e:
        return jsonify({
            'error': 'Error processing chat request',
            'details': str(e)
        }), 500


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


@app.errorhandler(Forbidden)
def handle_csrf_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'CSRF token missing or invalid'}), 403
    flash('Session expired. Please try again.', 'error')
    return redirect(url_for('login'))
