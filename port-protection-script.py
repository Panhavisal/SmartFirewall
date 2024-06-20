import sys
import subprocess
import pkg_resources

required_packages = {
    'scapy': 'scapy',
    'requests': 'requests',
    'pyyaml': 'PyYAML',
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
BLOCK_TIME = config['BLOCK_TIME']
TIME_WINDOW = config['TIME_WINDOW']
MAX_CONNECTIONS_PER_IP = config['MAX_CONNECTIONS_PER_IP']
SYN_FLOOD_THRESHOLD = config['SYN_FLOOD_THRESHOLD']
UDP_FLOOD_THRESHOLD = config['UDP_FLOOD_THRESHOLD']
ICMP_FLOOD_THRESHOLD = config['ICMP_FLOOD_THRESHOLD']
HTTP_FLOOD_THRESHOLD = config['HTTP_FLOOD_THRESHOLD']
PACKET_RATE_THRESHOLD = config['PACKET_RATE_THRESHOLD']
BANDWIDTH_THRESHOLD = config['BANDWIDTH_THRESHOLD']

# ChatGPT API configuration
OPENAI_API_KEY = config['OPENAI_API_KEY']
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

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

# Whitelist
WHITELIST = set(config['WHITELIST'])

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS monitored_ips
                 (ip TEXT PRIMARY KEY, 
                  first_seen TIMESTAMP,
                  last_updated TIMESTAMP,
                  packet_count INTEGER,
                  bandwidth_usage INTEGER,
                  syn_count INTEGER,
                  udp_count INTEGER,
                  icmp_count INTEGER,
                  http_count INTEGER,
                  connection_count INTEGER,
                  is_blocked INTEGER)''')
    conn.commit()
    conn.close()
    main_logger.info("Database initialized")

def update_ip_data(ip, data, is_blocked):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    now = datetime.now()
    c.execute('''INSERT OR REPLACE INTO monitored_ips
                 (ip, first_seen, last_updated, packet_count, bandwidth_usage, 
                  syn_count, udp_count, icmp_count, http_count, connection_count, is_blocked)
                 VALUES (?, COALESCE((SELECT first_seen FROM monitored_ips WHERE ip = ?), ?),
                         ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (ip, ip, now, now, data['packet_count'], data['bandwidth_usage'],
               data['syn_count'], data['udp_count'], data['icmp_count'],
               data['http_count'], data['connection_count'], int(is_blocked)))
    conn.commit()
    conn.close()
    main_logger.info(f"Updated data for IP {ip} (Blocked: {is_blocked})")

def get_ip_data(ip):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT * FROM monitored_ips WHERE ip = ?', (ip,))
    data = c.fetchone()
    conn.close()
    return data

def clean_old_data():
    while True:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        week_ago = datetime.now() - timedelta(days=7)
        c.execute('DELETE FROM monitored_ips WHERE last_updated < ? AND is_blocked = 0', (week_ago,))
        conn.commit()
        conn.close()
        main_logger.info("Cleaned old data from database")
        time.sleep(86400)  # Sleep for a day

def chatgpt_analyze(data):
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
    except Exception as e:
        ai_logger.error(f"Failed to get ChatGPT response: {str(e)}")
        return None

def take_action(ip, analysis):
    if "block" in analysis.lower():
        block_ip(ip, f"AI recommendation: {analysis}")
    elif "rate limit" in analysis.lower():
        rate_limit_ip(ip)
    elif "monitor" in analysis.lower():
        add_to_watchlist(ip)
    else:
        ai_logger.info(f"No action taken for {ip}. AI analysis: {analysis}")

def packet_callback(packet):
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

def update_packet_stats(ip, packet_size):
    current_time = time.time()
    packet_count[ip].append(current_time)
    bandwidth_usage[ip].append((current_time, packet_size))
    
    packet_count[ip] = [t for t in packet_count[ip] if t > current_time - TIME_WINDOW]
    bandwidth_usage[ip] = [(t, s) for t, s in bandwidth_usage[ip] if t > current_time - TIME_WINDOW]
    
    if len(packet_count[ip]) > PACKET_RATE_THRESHOLD or sum(s for _, s in bandwidth_usage[ip]) > BANDWIDTH_THRESHOLD:
        analyze_traffic(ip)

def handle_tcp_packet(ip, packet):
    if packet[scapy.TCP].flags & 0x02:
        syn_flood_count[ip] += 1
        if syn_flood_count[ip] > SYN_FLOOD_THRESHOLD:
            analyze_traffic(ip)
    
    if packet[scapy.TCP].dport in [80, 443]:
        connection_count[ip].append(time.time())
        connection_count[ip] = [t for t in connection_count[ip] if t > time.time() - TIME_WINDOW]
        
        if len(connection_count[ip]) > MAX_CONNECTIONS_PER_IP:
            analyze_traffic(ip)
        
        if scapy.Raw in packet:
            payload = packet[scapy.Raw].load
            if b"GET" in payload or b"POST" in payload:
                http_flood_count[ip] += 1
                if http_flood_count[ip] > HTTP_FLOOD_THRESHOLD:
                    analyze_traffic(ip)

def handle_udp_packet(ip):
    udp_flood_count[ip] += 1
    if udp_flood_count[ip] > UDP_FLOOD_THRESHOLD:
        analyze_traffic(ip)

def handle_icmp_packet(ip):
    icmp_flood_count[ip] += 1
    if icmp_flood_count[ip] > ICMP_FLOOD_THRESHOLD:
        analyze_traffic(ip)

def analyze_traffic(ip):
    data = {
        "ip": ip,
        "packet_count": len(packet_count[ip]),
        "bandwidth_usage": sum(s for _, s in bandwidth_usage[ip]),
        "syn_count": syn_flood_count[ip],
        "udp_count": udp_flood_count[ip],
        "icmp_count": icmp_flood_count[ip],
        "http_count": http_flood_count[ip],
        "connection_count": len(connection_count[ip])
    }
    update_ip_data(ip, data, False)  # Store the data, not blocked yet
    analysis = chatgpt_analyze(data)
    if analysis:
        take_action(ip, analysis)

def block_ip(ip, reason):
    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    subprocess.run(cmd, shell=True)
    blocked_ip_logger.info(f"Blocked IP: {ip}, Reason: {reason}")
    update_ip_data(ip, get_ip_data(ip), True)  # Mark as blocked in the database
    threading.Timer(BLOCK_TIME, unblock_ip, args=[ip]).start()

def unblock_ip(ip):
    cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
    subprocess.run(cmd, shell=True)
    blocked_ip_logger.info(f"Unblocked IP: {ip}")
    update_ip_data(ip, get_ip_data(ip), False)  # Mark as unblocked in the database

def rate_limit_ip(ip):
    cmd = f"sudo iptables -A INPUT -s {ip} -m limit --limit 10/minute -j ACCEPT"
    subprocess.run(cmd, shell=True)
    ai_logger.info(f"Rate limited IP: {ip}")

def add_to_watchlist(ip):
    ai_logger.info(f"Added IP to watchlist: {ip}")
    # The IP is already being monitored in the database

def reset_counters():
    global syn_flood_count, udp_flood_count, icmp_flood_count, http_flood_count
    syn_flood_count.clear()
    udp_flood_count.clear()
    icmp_flood_count.clear()
    http_flood_count.clear()
    main_logger.info("Reset all counters")
    threading.Timer(TIME_WINDOW, reset_counters).start()

def main():
    main_logger.info("Starting AI-enhanced DoS and DDoS protection script...")
    init_db()
    reset_counters()
    threading.Thread(target=clean_old_data, daemon=True).start()
    scapy.sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
