import scapy.all as scapy
import subprocess
import time
import threading
import logging
from collections import defaultdict
import statistics

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

logging.basicConfig(filename='ddos_protection.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def packet_callback(packet):
    if scapy.IP in packet:
        src_ip = packet[scapy.IP].src
        
        if src_ip in WHITELIST:
            return

        # Update packet count and bandwidth usage
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
    
    # Remove old entries
    packet_count[ip] = [t for t in packet_count[ip] if t > current_time - TIME_WINDOW]
    bandwidth_usage[ip] = [(t, s) for t, s in bandwidth_usage[ip] if t > current_time - TIME_WINDOW]
    
    # Check for abnormal packet rate or bandwidth usage
    if len(packet_count[ip]) > PACKET_RATE_THRESHOLD:
        block_ip(ip, "High packet rate detected")
    
    total_bandwidth = sum(s for _, s in bandwidth_usage[ip])
    if total_bandwidth > BANDWIDTH_THRESHOLD:
        block_ip(ip, "High bandwidth usage detected")

def handle_tcp_packet(ip, packet):
    if packet[scapy.TCP].flags & 0x02:  # SYN flag is set
        syn_flood_count[ip] += 1
        if syn_flood_count[ip] > SYN_FLOOD_THRESHOLD:
            block_ip(ip, "SYN flood detected")
    
    if packet[scapy.TCP].dport in [80, 443]:
        connection_count[ip].append(time.time())
        connection_count[ip] = [t for t in connection_count[ip] if t > time.time() - TIME_WINDOW]
        
        if len(connection_count[ip]) > MAX_CONNECTIONS_PER_IP:
            block_ip(ip, "Too many connections")
        
        if scapy.Raw in packet:
            payload = packet[scapy.Raw].load
            if b"GET" in payload or b"POST" in payload:
                http_flood_count[ip] += 1
                if http_flood_count[ip] > HTTP_FLOOD_THRESHOLD:
                    block_ip(ip, "HTTP flood detected")

def handle_udp_packet(ip):
    udp_flood_count[ip] += 1
    if udp_flood_count[ip] > UDP_FLOOD_THRESHOLD:
        block_ip(ip, "UDP flood detected")

def handle_icmp_packet(ip):
    icmp_flood_count[ip] += 1
    if icmp_flood_count[ip] > ICMP_FLOOD_THRESHOLD:
        block_ip(ip, "ICMP flood detected")

def block_ip(ip, reason):
    cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
    subprocess.run(cmd, shell=True)
    logging.info(f"Blocked {ip} for {BLOCK_TIME} seconds. Reason: {reason}")
    threading.Timer(BLOCK_TIME, unblock_ip, args=[ip]).start()

def unblock_ip(ip):
    cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
    subprocess.run(cmd, shell=True)
    logging.info(f"Unblocked {ip}")

def reset_counters():
    global syn_flood_count, udp_flood_count, icmp_flood_count, http_flood_count
    syn_flood_count.clear()
    udp_flood_count.clear()
    icmp_flood_count.clear()
    http_flood_count.clear()
    threading.Timer(TIME_WINDOW, reset_counters).start()

def analyze_traffic_patterns():
    while True:
        time.sleep(60)  # Analyze every minute
        for ip, counts in packet_count.items():
            if len(counts) > 100:  # Only analyze if we have enough data
                rates = [counts.count(t) for t in set(counts)]
                mean_rate = statistics.mean(rates)
                std_dev = statistics.stdev(rates)
                if any(abs(rate - mean_rate) > 3 * std_dev for rate in rates):
                    block_ip(ip, "Abnormal traffic pattern detected")

def main():
    logging.info("Starting enhanced DoS and DDoS protection script...")
    reset_counters()
    threading.Thread(target=analyze_traffic_patterns, daemon=True).start()
    scapy.sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
