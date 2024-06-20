import scapy.all as scapy
import subprocess
import time
import threading
import logging
from collections import defaultdict
import statistics
import requests
import json
import os

# Configuration
BLOCK_TIME = 300  # seconds
TIME_WINDOW = 60  # seconds
MAX_CONNECTIONS_PER_IP = 100
SYN_FLOOD_THRESHOLD = 100
UDP_FLOOD_THRESHOLD = 1000
ICMP_FLOOD_THRESHOLD = 50
HTTP_FLOOD_THRESHOLD = 200
PACKET_RATE_THRESHOLD = 1000  # packets per second
BANDWIDTH_THRESHOLD = 10 * 1024 * 1024  # 10 MB/s

# ChatGPT API configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

# Tracking dictionaries
connection_count = defaultdict(list)
syn_flood_count = defaultdict(int)
udp_flood_count = defaultdict(int)
icmp_flood_count = defaultdict(int)
http_flood_count = defaultdict(int)
packet_count = defaultdict(list)
bandwidth_usage = defaultdict(list)

# Whitelist
WHITELIST = set(['192.168.1.1', '10.0.0.1'])  # Add your trusted IPs here

logging.basicConfig(filename='ai_ddos_protection.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

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
    response = requests.post(OPENAI_API_URL, headers=headers, json=payload)
    if response.status_code == 200:
        return response.json()['choices'][0]['message']['content']
    else:
        logging.error(f"Failed to get ChatGPT response: {response.text}")
        return None

def take_action(ip, analysis):
    if "block" in analysis.lower():
        block_ip(ip, f"AI recommendation: {analysis}")
    elif "rate limit" in analysis.lower():
        rate_limit_ip(ip)
    elif "monitor" in analysis.lower():
        add_to_watchlist(ip)
    else:
        logging.info(f"No action taken for {ip}. AI analysis: {analysis}")

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
    analysis = chatgpt_analyze(data)
    if analysis:
        take_action(ip, analysis)

def block_ip(ip, reason):
    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    subprocess.run(cmd, shell=True)
    logging.info(f"Blocked {ip} for {BLOCK_TIME} seconds. Reason: {reason}")
    threading.Timer(BLOCK_TIME, unblock_ip, args=[ip]).start()

def unblock_ip(ip):
    cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
    subprocess.run(cmd, shell=True)
    logging.info(f"Unblocked {ip}")

def rate_limit_ip(ip):
    cmd = f"sudo iptables -A INPUT -s {ip} -m limit --limit 10/minute -j ACCEPT"
    subprocess.run(cmd, shell=True)
    logging.info(f"Rate limited {ip}")

def add_to_watchlist(ip):
    logging.info(f"Added {ip} to watchlist for closer monitoring")
    # Implement additional monitoring logic here

def reset_counters():
    global syn_flood_count, udp_flood_count, icmp_flood_count, http_flood_count
    syn_flood_count.clear()
    udp_flood_count.clear()
    icmp_flood_count.clear()
    http_flood_count.clear()
    threading.Timer(TIME_WINDOW, reset_counters).start()

def main():
    logging.info("Starting AI-enhanced DoS and DDoS protection script...")
    reset_counters()
    scapy.sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
