# [Previous imports and configurations remain the same]

# Load AI prompt template from config
AI_PROMPT_TEMPLATE = config.get('AI_PROMPT_TEMPLATE', """
You are an AI assistant focused on maintaining server stability and performance while protecting against DDoS attacks. 
Analyze the following network traffic data and server health metrics. Suggest appropriate actions to mitigate potential threats 
while ensuring the server continues to operate smoothly.

Server Health Metrics:
- CPU Usage: {cpu_usage}%
- Memory Usage: {memory_usage}%
- Disk I/O Utilization: {disk_io}%

Network Traffic Data:
{traffic_data}

Consider the following options and their impact on server performance:
1. Block IP (most severe, may impact legitimate traffic if used too broadly)
2. Temporary block (moderate, allows recovery of false positives)
3. Rate limit (less severe, helps manage traffic without full blocking)
4. CAPTCHA challenge (for potential bot activity, may slow down legitimate users)
5. Add to watchlist (for mild suspicion, no immediate impact)
6. Adjust server resources (e.g., scaling up, load balancing)
7. No action (if behavior seems normal)

Provide your recommendation as a single word (e.g., "block", "temp_block", "rate_limit", "captcha", "watchlist", "adjust_resources", "none"), 
followed by a brief explanation. Prioritize server stability and performance in your decision.
""")

def chatgpt_analyze(traffic_data):
    if not OPENAI_API_KEY:
        ai_logger.error("OpenAI API key is not set. Skipping AI analysis.")
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
        response = requests.post(OPENAI_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        analysis = response.json()['choices'][0]['message']['content']
        ai_logger.info(f"AI Analysis for IP {traffic_data['ip']}: {analysis}")
        return analysis
    except requests.exceptions.RequestException as e:
        ai_logger.error(f"Failed to get ChatGPT response: {str(e)}")
        return None

# [The rest of the script remains the same]
