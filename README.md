Windows Packet Firewall with Python Logger
This project implements a real-time packet-sniffing firewall using C (WinPcap + Winsock) and a Python-based logging server. It actively monitors TCP packets on a selected network interface, enforces IP and port-based blocking rules, and logs traffic to a file with a simple classification (BLOCKED or ALLOWED).

🧰 Features
🖥️ C-based packet sniffer using pcap for live traffic capture on Windows.

🔥 Firewall logic that dynamically blocks suspicious IPs/ports using netsh.

🔄 Python logging server to classify and record packets in real-time.

🧠 Rule-based filtering on the Python side for better extensibility and quick testing.

🧱 Modular & Extensible — easily plug in new logic or threat detection mechanisms.

🗃️ Project Structure
firewall.c

Main packet capture and firewall logic.

Connects to a local Python server over TCP to log packet info.

Dynamically blocks IPs via Windows Firewall using netsh.

firewall_manager.py

Acts as a TCP server listening on 127.0.0.1:9090.

Filters traffic based on rules (BLOCKED_IPS, BLOCKED_PORTS).

Logs classified packets (ALLOWED / BLOCKED) to firewall_log.txt.

🛡️ Blocking Logic
C Firewall (Hard Block):
Keeps track of connections from the IPs and Ports, it is blocked using a Windows firewall rule.

Python Logger (Soft Filter):
Analyzes packet metadata from the C client.

Uses regex-based parsing and filtering based on BLOCKED_IPS and BLOCKED_PORTS.

Logs whether packets are allowed or blocked — useful for auditing and tuning rules.

⚙️ Requirements:

Windows
Npcap (Need to be installed separately) 

Visual Studio (or any C compiler for Windows)

Python 3.x

🚀 Getting Started
Build and run the C project (firewall.c) with gcc and covert it to .exe file using the below command to include Npcap (if not included in environment path variables) 
Choose the network interface when prompted.

Python logger (firewall_manager.py) will launch automatically

Ensure Python is installed and in your PATH.

Watch logs and block activity in real time!

📝 Example Log Output:
✅ ALLOWED: [2025-04-22 12:34:56] SRC: 192.168.1.100: 5353 -> DST: 192.168.1.1: 80
🚫 BLOCKED: [2025-04-22 12:35:02] SRC: 192.168.128.4: 4444 -> DST: 10.0.0.2: 80
🧠 Future Improvements
🔍 Deep packet inspection (DPI)

🌐 Remote logging and alert dashboard

🧪 Integrate with threat intelligence APIs

🧬 Machine learning-based anomaly detection

⚠️ Disclaimer
This project is for educational and experimental purposes only. Improper use of firewall rules can affect system/network connectivity. Use responsibly!
