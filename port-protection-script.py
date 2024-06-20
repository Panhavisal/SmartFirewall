OPENAI_API_KEY: "your_openai_api_key"
OPENAI_API_URL: "https://api.openai.com/v1/engines/gpt-3.5-turbo/completions"
AI_PROMPT_TEMPLATE: |
  The current server status is as follows:
  - CPU Usage: {cpu_usage}%
  - Memory Usage: {memory_usage}%
  - Disk I/O: {disk_io} operations/sec
  The following traffic data has been recorded:
  {traffic_data}
  Based on this information, please advise on the appropriate actions to take.
CPU_THRESHOLD: 80
MEMORY_THRESHOLD: 80
PACKET_RATE_THRESHOLD: 1000
SYN_FLOOD_THRESHOLD: 200
HTTP_FLOOD_THRESHOLD: 300
WHITELIST: ["192.168.1.1", "10.0.0.1"]
MAX_AI_RESPONSE_TIME: 10
