from scapy.all import sniff, IP
from collections import defaultdict
import time

THRESHOLD = 100
INTERVAL = 10
BLOCK_DURATION = 60

ip_counts = defaultdict(int)
blocked_ips = {}
start_time = time.time()

def reset_counts():
    global ip_counts, start_time
    ip_counts.clear()
    start_time = time.time()

def block_ip(ip):
    blocked_ips[ip] = time.time()
    print(f"[ALERT] Blocking IP: {ip}")

def is_blocked(ip):
    if ip in blocked_ips:
        if time.time() - blocked_ips[ip] > BLOCK_DURATION:
            del blocked_ips[ip]
            print(f"[INFO] Unblocked IP: {ip}")
            return False
        return True
    return False

def monitor_packet(packet):
    global start_time
    if IP in packet:
        src_ip = packet[IP].src

        if is_blocked(src_ip):
            return

        ip_counts[src_ip] += 1

        if ip_counts[src_ip] > THRESHOLD:
            block_ip(src_ip)

        if time.time() - start_time > INTERVAL:
            reset_counts()

        print(f"Packet from {src_ip} - Count: {ip_counts[src_ip]}")

print("[*] Starting DoS protection tool... Press Ctrl+C to stop.")
try:
    sniff(prn=monitor_packet, store=0)
except KeyboardInterrupt:
    print("\n[*] Stopped packet monitoring.")
