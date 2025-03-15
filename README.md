A Network Packet Sniffer built with Python, Scapy, and Tkinter. This tool captures live network packets, displays them in a GUI, and provides insights into network traffic.

📌 Features
✅ Capture live network packets (TCP, UDP, ICMP)
✅ Display packet details (Source IP, Destination IP, Protocol)
✅ User-friendly Tkinter GUI
✅ Start/Stop packet sniffing with a button
✅ Multi-threaded sniffing (doesn’t freeze GUI)
✅ Works on Windows & Linux (requires admin/root access)

🛠 Installation
1. Install Dependencies
bash
pip install scapy tk

2. Install Npcap (Windows Only)
Download and install Npcap from npcap.com
Check: "Install Npcap in WinPcap API-compatible mode"

3. Run the Application
python main.py
🔹 Windows Users: Run the script as Administrator
🔹 Linux Users: Use sudo python main.py

📌 Future Enhancements
🚀 Packet filtering (by protocol, IP)
🚀 Save packets to a log file
🚀 Detailed packet analysis


