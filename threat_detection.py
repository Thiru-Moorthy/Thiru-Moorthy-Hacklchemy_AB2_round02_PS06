import psutil
import os
import scapy.all as scapy
from datetime import datetime

def log_threat(ip, reason):
    """Logs detected threats with timestamps."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("threat_log.txt", "a") as log_file:
        log_file.write(f"[{timestamp}] Threat Detected: {ip} | Reason: {reason}\n")

def detect_fake_malware():
    """Detects Fake Malware Execution."""
    malware_path = "C:\\Windows\\System32\\fake_malware.exe"
    if os.path.exists(malware_path):
        print("⚠️ Fake Malware Detected! Removing...")
        os.remove(malware_path)
        log_threat("127.0.0.1", "Fake Malware File Detected")

def detect_mitm_attack():
    """Detects ARP Spoofing (MITM Attack)."""
    arp_table = scapy.ARP()
    suspicious_ips = []

    for packet in scapy.sniff(filter="arp", count=10, timeout=5):
        if packet[arp_table].op == 2:
            attacker_ip = packet[arp_table].psrc
            if attacker_ip not in suspicious_ips:
                suspicious_ips.append(attacker_ip)
                log_threat(attacker_ip, "Possible MITM Attack Detected")
                print(f"⚠️ MITM Attack Detected from {attacker_ip}")

def monitor_connections():
    """Monitors all network connections."""
    suspicious_ips = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            ip = conn.raddr.ip
            if ip not in suspicious_ips:
                suspicious_ips.append(ip)
                log_threat(ip, "Suspicious Network Activity")
    return suspicious_ips
