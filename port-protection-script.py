import os
import requests
import json
import logging
import time
import threading
from scapy.all import sniff, IP

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
    "MAX_AI_RESPONSE_TIME": 10
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

# Set up logging
logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
ai_logger = logging.getLogger("AI_Analysis")
action_logger = logging.getLogger("Action_Logger")
action_handler = logging.FileHandler('aiaction.txt')
action_logger.addHandler(action_handler)
action_logger.setLevel(logging.INFO)

# In-memory database for storing IP data
ip_database = {
    "blacklist": set(),
    "monitor": {}
}

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

def analyze_traffic(ip):
    data = {
        "ip": ip,
        "packet_count": len(packet_count.get(ip, [])),
        "bandwidth_usage": sum(s for _, s in bandwidth_usage.get(ip, [])),
        "syn_count": syn_flood_count.get(ip, 0),
        "udp_count": udp_flood_count.get(ip, 0),
        "icmp_count": icmp_flood_count.get(ip, 0),
        "http_count": http_flood_count.get(ip, 0),
        "connection_count": len(connection_count.get(ip, []))
    }
    ai_logger.info(f"Analyzing traffic data for IP {ip}: {data}")
    print(f"Analyzing traffic data for IP {ip}: {data}")  # Real-time console notification
    update_ip_data(ip, data, False)  # Store the data, not blocked yet
    
    server_health = get_server_health()
    
    analysis = chatgpt_analyze(data)
    if analysis is None:
        ai_logger.warning("AI analysis failed. Using fallback mechanism.")
        analysis = fallback_analysis(data, server_health)
    
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
        block_ip(ip, f"Analysis: {explanation}")
        ip_database["blacklist"].add(ip)
    elif action == "temp_block":
        temp_block_ip(ip, f"Analysis: {explanation}")
    elif action == "rate_limit":
        rate_limit_ip(ip, f"Analysis: {explanation}")
    elif action == "captcha":
        captcha_challenge_ip(ip, f"Analysis: {explanation}")
    elif action == "watchlist":
        add_to_watchlist(ip, f"Analysis: {explanation}")
    elif action == "adjust_resources":
        adjust_server_resources(f"Analysis: {explanation}")
    elif action == "none":
        ai_logger.info(f"No action taken for {ip}. Analysis: {explanation}")
        print(f"No action taken for {ip}. Analysis: {explanation}")  # Real-time console notification
    else:
        ai_logger.warning(f"Unknown action '{action}' for {ip}. Using default action.")
        print(f"Unknown action '{action}' for {ip}. Using default action.")  # Real-time console notification
        add_to_watchlist(ip, f"Unknown action suggested: {explanation}")

# Functions to take actions
def update_ip_data(ip, data, blocked):
    print(f"Updated IP data for {ip}: {data}, Blocked: {blocked}")
    ip_database["monitor"][ip] = data

def block_ip(ip, reason):
    print(f"Blocked IP {ip} for reason: {reason}")

def temp_block_ip(ip, reason):
    print(f"Temporarily blocked IP {ip} for reason: {reason}")

def rate_limit_ip(ip, reason):
    print(f"Rate limited IP {ip} for reason: {reason}")

def captcha_challenge_ip(ip, reason):
    print(f"Captcha challenge for IP {ip} for reason: {reason}")

def add_to_watchlist(ip, reason):
    print(f"Added IP {ip} to watchlist for reason: {reason}")

def adjust_server_resources(reason):
    print(f"Adjusted server resources for reason: {reason}")

# Example placeholders for traffic and connection metrics
packet_count = {}
bandwidth_usage = {}
syn_flood_count = {}
udp_flood_count = {}
icmp_flood_count = {}
http_flood_count = {}
connection_count = {}

def capture_traffic(packet):
    if IP in packet:
        ip = packet[IP].src
        if ip == "0.0.0.0" or ip in config["WHITELIST"]:
            return  # Skip the server IP itself and whitelisted IPs
        
        if ip not in packet_count:
            packet_count[ip] = []
            bandwidth_usage[ip] = []
            syn_flood_count[ip] = 0
            udp_flood_count[ip] = 0
            icmp_flood_count[ip] = 0
            http_flood_count[ip] = 0
            connection_count[ip] = []
        
        # Update traffic data
        packet_count[ip].append(1)
        bandwidth_usage[ip].append((time.time(), len(packet)))
        syn_flood_count[ip] += 1 if packet.haslayer('TCP') and packet['TCP'].flags == 'S' else 0
        udp_flood_count[ip] += 1 if packet.haslayer('UDP') else 0
        icmp_flood_count[ip] += 1 if packet.haslayer('ICMP') else 0
        http_flood_count[ip] += 1 if packet.haslayer('HTTP') else 0
        connection_count[ip].append(1)
        
def start_sniffing():
    sniff(prn=capture_traffic, filter="ip", store=0)

def main():
    # Start traffic capture in a separate thread
    traffic_thread = threading.Thread(target=start_sniffing)
    traffic_thread.daemon = True
    traffic_thread.start()
    
    # Main monitoring loop
    while True:
        for ip in list(packet_count.keys()):
            analyze_traffic(ip)
        time.sleep(60)  # Wait for 60 seconds before the next iteration

if __name__ == "__main__":
    main()
