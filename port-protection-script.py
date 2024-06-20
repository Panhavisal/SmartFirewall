# [Previous imports and configurations remain the same]

# Add a configuration for maximum AI response time
MAX_AI_RESPONSE_TIME = config.get('MAX_AI_RESPONSE_TIME', 5)  # seconds

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
        "packet_count": len(packet_count[ip]),
        "bandwidth_usage": sum(s for _, s in bandwidth_usage[ip]),
        "syn_count": syn_flood_count[ip],
        "udp_count": udp_flood_count[ip],
        "icmp_count": icmp_flood_count[ip],
        "http_count": http_flood_count[ip],
        "connection_count": len(connection_count[ip])
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

# [The rest of the script remains the same]
