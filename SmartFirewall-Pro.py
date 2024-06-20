import subprocess
import sys
import os
import requests
import json
import logging
import time
import threading
import sqlite3
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

# Configuration Loading
config = {
    "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
    "OPENAI_API_URL": "https://api.openai.com/v1/engines/gpt-3.5-turbo/completions",
    "AI_PROMPT_TEMPLATE": """
    The current server status is as follows:
    - CPU Usage: {cpu_usage}%
    - Memory Usage: {memory_usage}%
    - Disk I/O: {disk_io} operations/sec
    The following traffic data has been recorded:
    {traffic_data}
    Based on this information, please advise on the appropriate actions to take.
    """,
    "CPU_THRESHOLD": 80,
    "MEMORY_THRESHOLD": 80,
    "PACKET_RATE_THRESHOLD": 1000,
    "SYN_FLOOD_THRESHOLD": 200,
    "HTTP_FLOOD_THRESHOLD": 300,
    "WHITELIST": ["192.168.1.1", "10.0.0.1"],  # Add server IP to whitelist
    "MAX_AI_RESPONSE_TIME": 10,
    "TEMP_BLOCK_DURATION": 300,  # Temporary block duration in seconds
    "PERMANENT_BLOCK_THRESHOLD": 3  # Number of times an IP can be temporarily blocked before permanent block
}

OPENAI_API_KEY = config.get("OPENAI_API_KEY")
OPENAI_API_URL = config.get("OPENAI_API_URL")
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
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "What action should be taken based on this data?"}
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
        ai_logger.error(f"Unexpected error in AI analysis: {str(e)}")
        return None

def fallback_analysis(traffic_data, server_health):
    # Simple rule-based analysis
    if server_health['cpu_usage'] > CPU_THRESHOLD or server_health['memory_usage'] > MEMORY_THRESHOLD:
        if traffic_data['packet_count'] > PACKET_RATE_THRESHOLD:
            return "temp_block, High server load and high packet rate detected"
        else:
            return "rate_limit, High server load detected"
    elif traffic_data['syn_count'] > SYN_FLOOD_THRESHOLD:
        return "temp_block, Potential SYN flood detected"
    elif traffic_data['http_count'] > HTTP_FLOOD_THRESHOLD:
        return "captcha, Potential HTTP flood detected"
    elif traffic_data['packet_count'] > PACKET_RATE_THRESHOLD:
        return "rate_limit, High packet rate detected"
    else:
        return "watchlist, Suspicious activity detected"

def analyze_traffic():
    traffic_data = get_traffic_data()
    blocked_ips = get_blocked_ips()
    
    for data in traffic_data:
        ip, packet_count, bandwidth_usage, syn_count, udp_count, icmp_count, http_count, connection_count, last_update = data
        if ip in blocked_ips:
            continue
        
        data_dict = {
            "ip": ip,
            "packet_count": packet_count,
            "bandwidth_usage": bandwidth_usage,
            "syn_count": syn_count,
            "udp_count": udp_count,
            "icmp_count": icmp_count,
            "http_count": http_count,
            "connection_count": connection_count
        }
        ai_logger.info(f"Analyzing traffic data for IP {ip}: {data_dict}")
        print(f"Analyzing traffic data for IP {ip}: {data_dict}")  # Real-time console notification
        server_health = get_server_health()
        analysis = chatgpt_analyze(data_dict)
        if analysis is None:
            ai_logger.warning("AI analysis failed. Using fallback mechanism.")
            analysis = fallback_analysis(data_dict, server_health)
        take_action(ip, analysis)

def take_action(ip, analysis):
    if ip in WHITELIST:
        ai_logger.info(f"Skipping action for whitelisted IP: {ip}")
        print(f"Skipping action for whitelisted IP: {ip}")  # Real-time console notification
        return
    
    if not analysis:
        ai_logger.warning(f"No analysis available for IP: {ip}. Using default action.")
        analysis = "watchlist, No analysis available"
    
    action, explanation = analysis.lower().split(',', 1)
    action = action.strip()

    ai_logger.info(f"Taking action '{action}' for IP {ip} with explanation: {explanation}")
    action_logger.info(f"IP: {ip} - Action: {action} - Explanation: {explanation}")
    print(f"Taking action '{action}' for IP {ip} with explanation: {explanation}")  # Real-time console notification
    
    if action == "block":
        block_ip(ip, "permanent")
        ai_logger.info(f"Permanently blocked IP {ip} for reason: {explanation}")
    elif action == "temp_block":
        block_ip(ip, "temporary", TEMP_BLOCK_DURATION)
        ai_logger.info(f"Temporarily blocked IP {ip} for {TEMP_BLOCK_DURATION} seconds. Reason: {explanation}")
    elif action == "rate_limit":
        ai_logger.info(f"Rate limited IP {ip} for reason: {explanation}")
    elif action == "captcha":
        ai_logger.info(f"Captcha challenge for IP {ip} for reason: {explanation}")
    elif action == "watchlist":
        ai_logger.info(f"Added IP {ip} to watchlist for reason: {explanation}")
    elif action == "adjust_resources":
        ai_logger.info(f"Adjusted server resources for reason: {explanation}")
    elif action == "none":
        ai_logger.info(f"No action taken for {ip}. Analysis: {explanation}")
        print(f"No action taken for {ip}. Analysis: {explanation}")  # Real-time console notification
    else:
        ai_logger.warning(f"Unknown action '{action}' for {ip}. Using default action.")
        print(f"Unknown action '{action}' for {ip}. Using default action.")  # Real-time console notification
        ai_logger.info(f"Added IP {ip} to watchlist for unknown action. Reason: {explanation}")

def capture_traffic(packet):
    if IP in packet:
        ip = packet[IP].src
        if ip == "0.0.0.0" or ip in config["WHITELIST"]:
            return  # Skip the server IP itself and whitelisted IPs
        
        packet_len = len(packet)
        syn = 1 if packet.haslayer('TCP') and packet['TCP'].flags == 'S' else 0
        udp = 1 if packet.haslayer('UDP') else 0
        icmp = 1 if packet.haslayer('ICMP') else 0
        http = 1 if packet.haslayer('HTTP') else 0
        
        update_traffic_data(ip, packet_len, syn, udp, icmp, http)
        
def start_sniffing():
    sniff(prn=capture_traffic, filter="ip", store=0)

def main():
    # Print and log startup message
    startup_message = "Port Protection Script is starting and running..."
    print(startup_message)
    logging.info(startup_message)
    
    # Start traffic capture in a separate thread
    traffic_thread = threading.Thread(target=start_sniffing)
    traffic_thread.daemon = True
    traffic_thread.start()
    
    # Main monitoring loop
    while True:
        unblock_ips()  # Unblock IPs that are temporarily blocked and have passed the duration
        analyze_traffic()
        time.sleep(60)  # Wait for 60 seconds before the next iteration

if __name__ == "__main__":
    main()