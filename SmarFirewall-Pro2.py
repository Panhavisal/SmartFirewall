import subprocess
import sys
import os
import requests
import json
import logging
import time
import threading
import sqlite3
import yaml
from scapy.all import sniff, IP
from datetime import datetime, timedelta

# Function to install required libraries
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Auto-install required libraries if not present
try:
    import scapy.all
except ImportError:
    install('scapy')

try:
    import requests
except ImportError:
    install('requests')

try:
    import yaml
except ImportError:
    install('pyyaml')

# Load configuration from YAML file
with open('config.yaml', 'r') as file:
    config = yaml.safe_load(file)

OPENAI_API_KEY = config.get("OPENAI_API_KEY")
OPENAI_API_URL = config.get("OPENAI_API_URL", "https://api.openai.com/v1/chat/completions")
AI_PROMPT_TEMPLATE = config.get("AI_PROMPT_TEMPLATE")
CPU_THRESHOLD = config.get("CPU_THRESHOLD", 80)
MEMORY_THRESHOLD = config.get("MEMORY_THRESHOLD", 80)
PACKET_RATE_THRESHOLD = config.get("PACKET_RATE_THRESHOLD", 1000)
SYN_FLOOD_THRESHOLD = config.get("SYN_FLOOD_THRESHOLD", 200)
HTTP_FLOOD_THRESHOLD = config.get("HTTP_FLOOD_THRESHOLD", 300)
WHITELIST = config.get("WHITELIST", [])
MAX_AI_RESPONSE_TIME = config.get("MAX_AI_RESPONSE_TIME", 5)
TEMP_BLOCK_DURATION = config.get("TEMP_BLOCK_DURATION", 300)
PERMANENT_BLOCK_THRESHOLD = config.get("PERMANENT_BLOCK_THRESHOLD", 3)
WATCHLIST_DURATION = config.get("WATCHLIST_DURATION", 3600)  # 1 hour default duration

# Set up logging
logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
ai_logger = logging.getLogger("AI_Analysis")
action_logger = logging.getLogger("Action_Logger")
action_handler = logging.FileHandler('aiaction.txt')
action_logger.addHandler(action_handler)
action_logger.setLevel(logging.INFO)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('traffic_data.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic (
            ip TEXT PRIMARY KEY,
            packet_count INTEGER,
            bandwidth_usage INTEGER,
            syn_count INTEGER,
            udp_count INTEGER,
            icmp_count INTEGER,
            http_count INTEGER,
            connection_count INTEGER,
            last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            block_type TEXT,
            block_count INTEGER DEFAULT 0,
            block_until TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS watchlist (
            ip TEXT PRIMARY KEY,
            watch_until TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def update_traffic_data(ip, packet_len, syn, udp, icmp, http):
    conn = sqlite3.connect('traffic_data.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO traffic (ip, packet_count, bandwidth_usage, syn_count, udp_count, icmp_count, http_count, connection_count)
        VALUES (?, 1, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(ip) DO UPDATE SET
        packet_count = packet_count + 1,
        bandwidth_usage = bandwidth_usage + ?,
        syn_count = syn_count + ?,
        udp_count = udp_count + ?,
        icmp_count = icmp_count + ?,
        http_count = http_count + ?,
        connection_count = connection_count + 1,
        last_update = CURRENT_TIMESTAMP
    ''', (ip, packet_len, syn, udp, icmp, http, packet_len, syn, udp, icmp, http))
    
    conn.commit()
    conn.close()

def get_traffic_data():
    conn = sqlite3.connect('traffic_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM traffic')
    data = cursor.fetchall()
    conn.close()
    return data

def get_blocked_ips():
    conn = sqlite3.connect('traffic_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip, block_type, block_until FROM blocked_ips WHERE block_until > CURRENT_TIMESTAMP')
    data = cursor.fetchall()
    conn.close()
    return {ip: (block_type, block_until) for ip, block_type, block_until in data}

def block_ip(ip, block_type, duration=None):
    conn = sqlite3.connect('traffic_data.db')
    cursor = conn.cursor()
    if duration:
        block_until = datetime.now() + timedelta(seconds=duration)
        cursor.execute('''
            INSERT INTO blocked_ips (ip, block_type, block_count, block_until)
            VALUES (?, ?, 1, ?)
            ON CONFLICT(ip) DO UPDATE SET
            block_type = ?,
            block_count = block_count + 1,
            block_until = ?
        ''', (ip, block_type, block_until, block_type, block_until))
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])  # Add iptables rule
    else:
        cursor.execute('''
            INSERT INTO blocked_ips (ip, block_type, block_count, block_until)
            VALUES (?, ?, 1, DATETIME('now', '+100 years'))
            ON CONFLICT(ip) DO UPDATE SET
            block_type = ?,
            block_count = block_count + 1,
            block_until = DATETIME('now', '+100 years')
        ''', (ip, block_type, block_type))
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])  # Add iptables rule
    conn.commit()
    conn.close()

def unblock_ips():
    conn = sqlite3.connect('traffic_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip FROM blocked_ips WHERE block_until < CURRENT_TIMESTAMP')
    data = cursor.fetchall()
    for ip, in data:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])  # Remove iptables rule
    cursor.execute('DELETE FROM blocked_ips WHERE block_until < CURRENT_TIMESTAMP')
    conn.commit()
    conn.close()

def get_watchlist():
    conn = sqlite3.connect('traffic_data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip, watch_until FROM watchlist WHERE watch_until > CURRENT_TIMESTAMP')
    data = cursor.fetchall()
    conn.close()
    return {ip: watch_until for ip, watch_until in data}

def add_to_watchlist(ip):
    watch_until = datetime.now() + timedelta(seconds=WATCHLIST_DURATION)
    conn = sqlite3.connect('traffic_data.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO watchlist (ip, watch_until)
        VALUES (?, ?)
        ON CONFLICT(ip) DO UPDATE SET
        watch_until = ?
    ''', (ip, watch_until, watch_until))
    conn.commit()
    conn.close()

def get_server_health():
    # Placeholder function to simulate getting server health metrics
    return {
        "cpu_usage": 75,
        "memory_usage": 65,
        "disk_io": 120
    }

def chatgpt_analyze(traffic_data):
    if not OPENAI_API_KEY:
        ai_logger.error("OpenAI API key is not set. Using fallback mechanism.")
        return None
    
    server_health = get_server_health()
    
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    
    prompt = AI_PROMPT_TEMPLATE.format(
        cpu_usage=server_health['cpu_usage'],
        memory_usage=server_health['memory_usage'],
        disk_io=server_health['disk_io'],
        traffic_data=json.dumps(traffic_data)
    )
    
    payload = {
        "model": "gpt-4-turbo",
        "messages": [
            {"role": "system", "content": "You are a network security expert."},
            {"role": "user", "content": prompt}
        ]
    }
    
    try:
        response = requests.post(OPENAI_API_URL, headers=headers, json=payload, timeout=MAX_AI_RESPONSE_TIME)
        response.raise_for_status()
        analysis = response.json()['choices'][0]['message']['content']
        ai_logger.info(f"AI Analysis for IP {traffic_data['ip']}: {analysis}")
        return analysis
    except requests.exceptions.RequestException as e:
        ai_logger.error(f"Failed to get ChatGPT response: {str(e)}")
        return None
    except Exception as e:
        ai_logger
