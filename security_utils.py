import os
import time
import threading
import psutil
from plyer import notification

HONEYPOT_FILE = "C:/Users/Public/SecretPassword.txt"
SAFE_PROCESSES = ["chrome.exe", "explorer.exe", "python.exe"]

def create_honeypot():
    """Creates a fake honeypot file to bait hackers."""
    with open(HONEYPOT_FILE, "w") as f:
        f.write("This is a fake password file. If accessed, it triggers an alert.")

def monitor_honeypot():
    """Continuously monitors the honeypot file for unauthorized access."""
    last_modified = os.path.getmtime(HONEYPOT_FILE)

    def watch_file():
        nonlocal last_modified
        while True:
            try:
                new_modified = os.path.getmtime(HONEYPOT_FILE)
                if new_modified > last_modified:
                    notify_honeypot_access()
                    last_modified = new_modified
                time.sleep(2)  # Check every 2 seconds
            except FileNotFoundError:
                print("⚠️ Honeypot file missing! Recreating it...")
                create_honeypot()

    threading.Thread(target=watch_file, daemon=True).start()

def notify_honeypot_access():
    """Alerts user if honeypot file is accessed."""
    notification.notify(
        title="⚠️ Honeypot Alert!",
        message="Someone accessed your honeypot file!",
        timeout=5
    )
    print("⚠️ Unauthorized access detected in honeypot file!")

def check_suspicious_processes():
    """Detects and lists suspicious running processes."""
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if proc.info['name'].lower() not in SAFE_PROCESSES:
            print(f"⚠️ Suspicious Process: {proc.info['name']} (PID: {proc.info['pid']})")

def block_ip(ip):
    """Blocks an attacker's IP address using firewall rules."""
    if os.name == "nt":
        os.system(f"netsh advfirewall firewall add rule name='Block {ip}' dir=in action=block remoteip={ip}")
    else:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
