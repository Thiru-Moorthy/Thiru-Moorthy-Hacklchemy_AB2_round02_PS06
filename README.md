
# DarkWebGuard


DarkWebGuard is an advanced cybersecurity tool designed to detect threats originating from the **dark web**, monitor network activity for malicious actors, and use **honeypot traps** to log unauthorized access attempts. It also integrates **Graph Neural Networks (GNNs)** for threat analysis.  



##  Features

✅ **Dark Web Link Monitoring** – Searches for threats on the dark web using TOR.  
✅ **Network Activity Monitoring** – Detects suspicious connections and blocks malicious IPs.  
✅ **Honeypot Protection** – Creates a honeypot file and monitors unauthorized access.  
✅ **Threat Graph Visualization** – Uses **GNNs** to map and predict cyber threats.  
✅ **Real-Time Threat Alerts** – Displays threat scores and logs incidents.  



## Installation & Setup

###  Prerequisites 
Ensure you have the following installed:  
- **Python 3.8+** (Recommended: Python 3.10)  
- **TOR** (Running on port `9050` & `9051`)  
- **Git** (For cloning the repository)  


###Step 1: Clone the Repository**  

git clone https://github.com/yourusername/DarkWebGuard.git
cd DarkWebGuard
🔹 Step 2: Install Dependencies


pip install -r requirements.txt
This installs required libraries, including:

PyQt5 (GUI Framework)
Requests (For web requests)
Transformers (For NLP models)
NetworkX (For threat graph visualization)
TOR Stem (To interact with the TOR network)

🔹 Step 3: Start the TOR Service
Ensure that TOR is running before using DarkWebGuard.

If you installed TOR, start it via:
Windows: tor.exe
Linux/macOS: tor &

🔹 Step 4: Run DarkWebGuard
sh
Copy
Edit
python darkweb_guard.py

 How It Works

1️ Dark Web Threat Detection
Uses TOR Proxy (socks5h://127.0.0.1:9050) to browse hidden .onion sites.
Queries dark web search engines for potential threats.
Extracts .onion links and logs suspicious activity.

 Network Monitoring
Scans active connections for unusual behavior.
Uses IP geolocation to identify attackers.
Automatically blocks flagged malicious IPs.

 Honeypot Monitoring
Creates a fake sensitive file (honeypot.txt) as bait.
Monitors for unauthorized access attempts.
If someone opens, edits, or deletes it, an alert is logged.

 Graph-Based Threat Intelligence
Uses Graph Neural Networks (GNNs) to analyze threat patterns.
Builds a threat map of detected malicious actors.
Predicts the threat score of new IPs based on past attacks.

📌 Usage Guide
 Start Monitoring
Click "Start Monitoring" to begin real-time threat detection.
It will monitor network traffic and honeypot activity.
 Stop Monitoring
Click "Stop Monitoring" to halt all background monitoring.
 Check Malware Activity
Click "Check for Malware" to simulate a malware scan.
 View Honeypot Logs
Click "Monitor Honeypot File" to track any unauthorized file access.
 View Threat Graph
Click "View Threat Graph" to visualize attack patterns.
 Project Structure


DarkWebGuard/
│── darkweb_guard.py           # Main GUI Application
│── threat_detection.py        # Network Monitoring
│── security_utils.py          # Honeypot & Malware Detection
│── ip_utils.py                # IP Analysis & Geolocation
│── threat_graph.py            # Graph Neural Network Threat Mapping
│── gnn_model.py               # AI-Based Threat Prediction
│── requirements.txt           # Dependencies
│── README.md                  # Project Documentation
│── style.qss                  # GUI Styling
└── logs/
    ├── threat_log.txt         # Threat activity logs
    ├── honeypot.txt           # Honeypot file

🔧 Troubleshooting
TOR Connection Fails
Make sure TOR is running (tor.exe or tor &).
Try restarting TOR or reinstalling it.
No Threats Detected?
Run the app as Administrator to get full access to network monitoring.
Manually open honeypot.txt – it should trigger a detection.
Graph Visualization Not Showing?
Ensure NetworkX and Matplotlib are installed (pip install networkx matplotlib).
💡 Future Enhancements
✅ Dark Web Marketplace Scanning
✅ Advanced AI-based Anomaly Detection
✅ Automated Threat Intelligence Reports

Disclaimer
DarkWebGuard is for research and security testing purposes only. Do not use it for illegal activities or to access the dark web unethically.



Keep Cybersecurity Strong!



### How to Use It?
1. **Create a new file** in your project directory and name it **README.md**  
2. **Copy & paste** the above content into the file.  
3. Save the file.  







