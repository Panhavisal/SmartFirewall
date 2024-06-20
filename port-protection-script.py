import os
import requests
import json
import logging

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
    "WHITELIST": ["192.168.1.1", "10.0.0.1"],
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

ai_logger = logging.getLogger("AI_Analysis")
logging.basicConfig(level=logging.INFO)

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
        return
    
    if not analysis:
        ai_logger.warning(f"No analysis available for IP: {ip}. Using default action.")
        analysis = "watchlist, No analysis available"
    
    action, explanation = analysis.lower().split(',', 1)
    action = action.strip()

    if action == "block":
        block_ip(ip, f"Analysis: {explanation}")
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
    else:
        ai_logger.warning(f"Unknown action '{action}' for {ip}. Using default action.")
        add_to_watchlist(ip, f"Unknown action suggested: {explanation}")

# Mock functions to replace placeholders
def update_ip_data(ip, data, blocked):
    print(f"Updated IP data for {ip}: {data}, Blocked: {blocked}")

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
packet_count = {
    "192.168.1.100": [1, 2, 3, 4],
    "192.168.1.101": [1, 2]
}
bandwidth_usage = {
    "192.168.1.100": [(1, 200), (2, 300)],
    "192.168.1.101": [(1, 100)]
}
syn_flood_count = {
    "192.168.1.100": 50,
    "192.168.1.101": 20
}
udp_flood_count = {
    "192.168.1.100": 30,
    "192.168.1.101": 10
}
icmp_flood_count = {
    "192.168.1.100": 5,
    "192.168.1.101": 2
}
http_flood_count = {
    "192.168.1.100": 100,
    "192.168.1.101": 50
}
connection_count = {
    "192.168.1.100": [1, 2, 3],
    "192.168.1.101": [1, 2]
}

def main():
    analyze_traffic("192.168.1.100")
    analyze_traffic("192.168.1.101")

if __name__ == "__main__":
    main()
