import sys
import subprocess
import pkg_resources

required_packages = {
    'scapy': 'scapy',
    'requests': 'requests',
    'pyyaml': 'PyYAML',
    'captcha': 'captcha',
    'flask': 'Flask',
}

def install_packages(packages):
    for package in packages:
        try:
            dist = pkg_resources.get_distribution(package)
            print(f"{dist.key} ({dist.version}) is installed")
        except pkg_resources.DistributionNotFound:
            print(f"{package} is NOT installed. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", packages[package]])

print("Checking and installing required packages...")
install_packages(required_packages)

import scapy.all as scapy
import time
import threading
import logging
from logging.handlers import TimedRotatingFileHandler
from collections import defaultdict
import statistics
import requests
import json
import os
import sqlite3
from datetime import datetime, timedelta
import yaml
from captcha.image import ImageCaptcha
import random
import string
from flask import Flask, request, send_file, jsonify, abort
import io

# Load configuration
try:
    with open('config.yaml', 'r') as config_file:
        config = yaml.safe_load(config_file)
except FileNotFoundError:
    print("Error: config.yaml file not found. Please ensure it exists in the same directory as the script.")
    sys.exit(1)
except yaml.YAMLError as e:
    print(f"Error reading config.yaml: {e}")
    sys.exit(1)

# Configuration
BLOCK_TIME = config.get('BLOCK_TIME', 300)
TIME_WINDOW = config.get('TIME_WINDOW', 60)
MAX_CONNECTIONS_PER_IP = config.get('MAX_CONNECTIONS_PER_IP', 100)
SYN_FLOOD_THRESHOLD = config.get('SYN_FLOOD_THRESHOLD', 100)
UDP_FLOOD_THRESHOLD = config.get('UDP_FLOOD_THRESHOLD', 1000)
ICMP_FLOOD_THRESHOLD = config.get('ICMP_FLOOD_THRESHOLD', 50)
HTTP_FLOOD_THRESHOLD = config.get('HTTP_FLOOD_THRESHOLD', 200)
PACKET_RATE_THRESHOLD = config.get('PACKET_RATE_THRESHOLD', 1000)
BANDWIDTH_THRESHOLD = config.get('BANDWIDTH_THRESHOLD', 10485760)

# ChatGPT API configuration
OPENAI_API_KEY = config.get('OPENAI_API_KEY')
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

# CAPTCHA configuration
CAPTCHA_LENGTH = config.get('CAPTCHA_LENGTH', 6)
CAPTCHA_EXPIRY = config.get('CAPTCHA_EXPIRY', 300)  # 5 minutes
CAPTCHA_MAX_ATTEMPTS = config.get('CAPTCHA_MAX_ATTEMPTS', 3)

# Database and Log configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(SCRIPT_DIR, 'network_monitor.db')
MAIN_LOG_FILE = os.path.join(SCRIPT_DIR, 'Log.txt')
BLOCKED_IP_LOG_FILE = os.path.join(SCRIPT_DIR, 'blockedip.txt')
AI_LOG_FILE = os.path.join(SCRIPT_DIR, 'ailog.txt')

# Set up logging with rotation
def setup_logger(name, log_file, level=logging.INFO):
    handler = TimedRotatingFileHandler(log_file, when="D", interval=1, backupCount=60)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

main_logger = setup_logger('main_logger', MAIN_LOG_FILE)
blocked_ip_logger = setup_logger('blocked_ip_logger', BLOCKED_IP_LOG_FILE)
ai_logger = setup_logger('ai_logger', AI_LOG_FILE)

# Tracking dictionaries
connection_count = defaultdict(list)
syn_flood_count = defaultdict(int)
udp_flood_count = defaultdict(int)
icmp_flood_count = defaultdict(int)
http_flood_count = defaultdict(int)
packet_count = defaultdict(list)
bandwidth_usage = defaultdict(list)

# CAPTCHA storage
captcha_storage = {}
captcha_attempts = defaultdict(int)

# Whitelist
WHITELIST = set(config.get('WHITELIST', []))

# Flask app setup
app = Flask(__name__)

def generate_captcha():
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=CAPTCHA_LENGTH))
    image = ImageCaptcha(width=280, height=90)
    captcha_image = image.generate(captcha_text)
    captcha_storage[captcha_text] = time.time() + CAPTCHA_EXPIRY
    return captcha_text, captcha_image

@app.route('/captcha/<ip>', methods=['GET'])
def serve_captcha(ip):
    if ip in WHITELIST:
        return jsonify({"error": "IP is whitelisted"}), 400
    
    captcha_text, captcha_image = generate_captcha()
    ai_logger.info(f"Generated CAPTCHA for IP: {ip}")
    return send_file(io.BytesIO(captcha_image.getvalue()), mimetype='image/png')

@app.route('/verify/<ip>', methods=['POST'])
def verify_captcha(ip):
    if ip in WHITELIST:
        return jsonify({"error": "IP is whitelisted"}), 400
    
    user_input = request.form.get('captcha', '').upper()  # Convert to uppercase for case-insensitive comparison
    if not user_input:
        return jsonify({"success": False, "message": "No CAPTCHA input provided"}), 400
    
    captcha_attempts[ip] += 1
    if captcha_attempts[ip] > CAPTCHA_MAX_ATTEMPTS:
        ai_logger.warning(f"CAPTCHA attempts exceeded for IP: {ip}")
        return jsonify({"success": False, "message": "Maximum CAPTCHA attempts exceeded"}), 403
    
    if user_input in captcha_storage:
        if time.time() < captcha_storage[user_input]:
            del captcha_storage[user_input]
            captcha_attempts[ip] = 0  # Reset attempts on success
            ai_logger.info(f"CAPTCHA verified successfully for IP: {ip}")
            return jsonify({"success": True, "message": "CAPTCHA verified successfully"})
        else:
            ai_logger.info(f"CAPTCHA expired for IP: {ip}")
            return jsonify({"success": False, "message": "CAPTCHA expired"})
    else:
        ai_logger.info(f"CAPTCHA verification failed for IP: {ip}")
        return jsonify({"success": False, "message": "CAPTCHA verification failed"})

def captcha_challenge_ip(ip, reason):
    if ip in WHITELIST:
        ai_logger.info(f"Skipping CAPTCHA challenge for whitelisted IP: {ip}")
        return
    
    ai_logger.info(f"CAPTCHA challenge triggered for IP: {ip}. Reason: {reason}")
    # In a real-world scenario, you would redirect the user to the CAPTCHA page
    # For this script, we'll just log it and provide instructions
    ai_logger.info(f"To complete CAPTCHA, visit: http://[your_server_ip]:5000/captcha/{ip}")
    ai_logger.info(f"To verify CAPTCHA, send a POST request to: http://[your_server_ip]:5000/verify/{ip}")

# [Other functions like init_db, update_ip_data, get_ip_data, clean_old_data remain the same]

def chatgpt_analyze(data):
    if not OPENAI_API_KEY:
        ai_logger.error("OpenAI API key is not set. Skipping AI analysis.")
        return None
    
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "system", "content": "You are a cybersecurity expert. Analyze the following network traffic data and suggest appropriate actions to mitigate potential threats."},
                     {"role": "user", "content": json.dumps(data)}]
    }
    try:
        response = requests.post(OPENAI_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        analysis = response.json()['choices'][0]['message']['content']
        ai_logger.info(f"AI Analysis for IP {data['ip']}: {analysis}")
        return analysis
    except requests.exceptions.RequestException as e:
        ai_logger.error(f"Failed to get ChatGPT response: {str(e)}")
        return None

def take_action(ip, analysis):
    if ip in WHITELIST:
        ai_logger.info(f"Skipping action for whitelisted IP: {ip}")
        return
    
    if not analysis:
        ai_logger.warning(f"No analysis available for IP: {ip}. Skipping action.")
        return
    
    action, explanation = analysis.lower().split(',', 1)
    action = action.strip()

    if action == "block":
        block_ip(ip, f"AI recommendation: {explanation}")
    elif action == "temp_block":
        temp_block_ip(ip, f"AI recommendation: {explanation}")
    elif action == "rate_limit":
        rate_limit_ip(ip, f"AI recommendation: {explanation}")
    elif action == "captcha":
        captcha_challenge_ip(ip, f"AI recommendation: {explanation}")
    elif action == "watchlist":
        add_to_watchlist(ip, f"AI recommendation: {explanation}")
    elif action == "alert":
        send_alert(ip, f"AI recommendation: {explanation}")
    elif action == "none":
        ai_logger.info(f"No action taken for {ip}. AI analysis: {explanation}")
    else:
        ai_logger.warning(f"Unknown action '{action}' for {ip}. Full analysis: {analysis}")

# [Other functions like block_ip, unblock_ip, temp_block_ip, rate_limit_ip, add_to_watchlist, send_alert remain largely the same]

def packet_callback(packet):
    try:
        if scapy.IP in packet:
            src_ip = packet[scapy.IP].src
            
            if src_ip in WHITELIST:
                return

            update_packet_stats(src_ip, len(packet))
            
            if scapy.TCP in packet:
                handle_tcp_packet(src_ip, packet)
            elif scapy.UDP in packet:
                handle_udp_packet(src_ip)
            elif scapy.ICMP in packet:
                handle_icmp_packet(src_ip)
    except Exception as e:
        main_logger.error(f"Error in packet_callback: {str(e)}")

# [Other packet handling functions remain largely the same]

def main():
    main_logger.info("Starting AI-enhanced DoS and DDoS protection script with CAPTCHA support...")
    try:
        init_db()
        reset_counters()
        threading.Thread(target=clean_old_data, daemon=True).start()
        
        # Start Flask server in a separate thread
        threading.Thread(target=lambda: app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False), daemon=True).start()
        
        scapy.sniff(prn=packet_callback, store=0)
    except Exception as e:
        main_logger.error(f"Error in main function: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
