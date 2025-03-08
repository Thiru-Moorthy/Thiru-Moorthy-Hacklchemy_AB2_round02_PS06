import sys
import time
import threading
import requests
from stem.control import Controller
from datetime import datetime
from PyQt5 import QtWidgets, QtGui, QtCore
from threat_detection import monitor_connections
from security_utils import check_suspicious_processes, monitor_honeypot, create_honeypot, block_ip
from ip_utils import get_ip_details
from threat_graph import threat_graph
from gnn_model import predict_threat

# **TOR Configuration**
TOR_PROXY = "socks5h://127.0.0.1:9050"  # Make sure TOR is running!

def get_dark_web_links(query):
    """Searches dark web links using TOR or falls back to a predefined list."""
    dark_web_sources = [
        "http://example1.onion",
        "http://example2.onion",
        "http://example3.onion",
    ]
    
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()  # Ensure TOR control access
            tor_session = requests.Session()
            tor_session.proxies = {"http": TOR_PROXY, "https": TOR_PROXY}

            # Simulated search query (replace with actual dark web search service)
            search_url = f"http://searchengine.onion/search?q={query}"
            response = tor_session.get(search_url, timeout=10)
            
            if response.status_code == 200:
                return extract_onion_links(response.text)  # Implement this parser
            else:
                return dark_web_sources  # Fallback to predefined list

    except Exception as e:
        print(f"⚠️ TOR Connection Failed: {e}")
        return dark_web_sources  # Fallback

def extract_onion_links(html):
    """Extracts .onion links from HTML (Placeholder - implement parser)."""
    return ["http://sampledarkweb.onion"]

class DarkWebGuardApp(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.monitoring = False  
        self.monitor_thread = None  
        self.init_ui()

    def init_ui(self):
        """Initializes the GUI components."""
        self.setWindowTitle("Dark Web Guardian")
        self.setGeometry(100, 100, 600, 450)

        main_layout = QtWidgets.QVBoxLayout()

        # Title Label
        self.label = QtWidgets.QLabel("Dark Web Threat Detection Running...")
        self.label.setFont(QtGui.QFont("Arial", 14, QtGui.QFont.Bold))
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        main_layout.addWidget(self.label)

        button_size = (200, 45)

        # First Row (Start & Stop Monitoring)
        row1_layout = QtWidgets.QHBoxLayout()
        row1_layout.addStretch()

        self.monitor_btn = QtWidgets.QPushButton("Start Monitoring")
        self.monitor_btn.setFixedSize(*button_size)
        self.monitor_btn.clicked.connect(self.start_monitoring)
        row1_layout.addWidget(self.monitor_btn)

        self.stop_btn = QtWidgets.QPushButton("Stop Monitoring")
        self.stop_btn.setFixedSize(*button_size)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        row1_layout.addWidget(self.stop_btn)

        row1_layout.addStretch()
        main_layout.addLayout(row1_layout)

        # Second Row (Check for Malware & Monitor Honeypot)
        row2_layout = QtWidgets.QHBoxLayout()
        row2_layout.addStretch()

        self.process_btn = QtWidgets.QPushButton("Check for Malware")
        self.process_btn.setFixedSize(*button_size)
        self.process_btn.clicked.connect(self.detect_fake_malware)
        row2_layout.addWidget(self.process_btn)

        self.honeypot_btn = QtWidgets.QPushButton("Monitor Honeypot File")
        self.honeypot_btn.setFixedSize(*button_size)
        self.honeypot_btn.clicked.connect(self.start_honeypot_monitoring)
        row2_layout.addWidget(self.honeypot_btn)

        row2_layout.addStretch()
        main_layout.addLayout(row2_layout)

        # Third Row (View GNN Threat Graph)
        row3_layout = QtWidgets.QHBoxLayout()
        row3_layout.addStretch()

        self.view_graph_btn = QtWidgets.QPushButton("View Threat Graph")
        self.view_graph_btn.setFixedSize(*button_size)
        self.view_graph_btn.clicked.connect(self.view_threat_graph)  # Connect button to function
        row3_layout.addWidget(self.view_graph_btn)

        row3_layout.addStretch()
        main_layout.addLayout(row3_layout)

        # Threat Log
        self.threat_log = QtWidgets.QTextEdit(self)
        self.threat_log.setReadOnly(True)
        self.threat_log.setFont(QtGui.QFont("Arial", 12))
        self.threat_log.setFixedHeight(200)
        main_layout.addWidget(self.threat_log)

        # Close Button (Right-Aligned)
        close_layout = QtWidgets.QHBoxLayout()
        close_layout.addStretch()

        self.close_btn = QtWidgets.QPushButton("Close App")
        self.close_btn.setFixedSize(*button_size)
        self.close_btn.clicked.connect(self.close_application)
        close_layout.addWidget(self.close_btn)

        main_layout.addLayout(close_layout)

        self.setLayout(main_layout)

    def log_threat(self, ip, reason):
        """Logs threat details and analyzes it using GNN."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        details = get_ip_details(ip)
        related_ips = monitor_connections()  # Get related IPs
        threat_graph.add_threat(ip, related_ips)  # Add to graph

        # Predict threat level using GNN
        threat_score = predict_threat(ip)

        log_entry = f"[{timestamp}] Threat Detected: {ip} | {details.get('country', 'Unknown')}, {details.get('city', 'Unknown')} | Reason: {reason} | Threat Score: {threat_score}\n"

        with open("threat_log.txt", "a") as log_file:
            log_file.write(log_entry)

        self.threat_log.append(log_entry)

    def start_monitoring(self):
        """Runs network monitoring in a separate thread."""
        if self.monitoring:  
            self.label.setText("Already Monitoring!")
            return

        self.label.setText("Monitoring Network for Threats...")
        self.monitoring = True

        def monitor():
            while self.monitoring:
                threats = monitor_connections() if self.monitoring else []
                
                for ip in threats:
                    if not self.monitoring:
                        break
                    self.log_threat(ip, "Suspicious Network Activity")
                    block_ip(ip)

                time.sleep(5)

        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """Stops the monitoring thread safely."""
        self.monitoring = False  
        self.label.setText("Monitoring Stopped!")

    def start_honeypot_monitoring(self):
        """Creates and starts monitoring the honeypot file."""
        create_honeypot()  # Ensure honeypot file is created
        self.label.setText("Honeypot File Created and Monitoring Started!")

        thread = threading.Thread(target=monitor_honeypot, daemon=True)
        thread.start()

    def detect_fake_malware(self):
        """Simulates a malware detection."""
        self.label.setText("Fake Malware Download Detected!")
        self.log_threat("127.0.0.1", "Fake Malware File Detected")

    def view_threat_graph(self):
        """Opens the threat graph visualization."""
        try:
            threat_graph.visualize()  # This should open the GNN visualization
        except Exception as e:
            self.threat_log.append(f"⚠️ Failed to visualize graph: {e}\n")

    def close_application(self):
        """Stops monitoring and closes the app."""
        self.stop_monitoring()  
        self.label.setText("Shutting down...")
        QtWidgets.QApplication.quit()

def apply_styles():
    """Loads and applies the QSS stylesheet."""
    with open("style.qss", "r") as f:
        app.setStyleSheet(f.read())

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    apply_styles()  
    window = DarkWebGuardApp()
    window.show()
    sys.exit(app.exec_())
