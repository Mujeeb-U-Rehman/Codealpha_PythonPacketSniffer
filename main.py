import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

class NetworkSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")
        self.root.geometry("800x400")

        self.sniffing = False
        self.packet_list = []

        self.create_widgets()

    def create_widgets(self):
        # Start Sniffing Button
        self.start_button = tk.Button(self.root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        # Stop Sniffing Button
        self.stop_button = tk.Button(self.root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        # Packet Display Table
        self.tree = ttk.Treeview(self.root, columns=("#1", "#2", "#3"), show="headings")
        self.tree.heading("#1", text="Source IP")
        self.tree.heading("#2", text="Destination IP")
        self.tree.heading("#3", text="Protocol")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def packet_callback(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "Other"

            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"

            self.packet_list.append((src_ip, dst_ip, protocol))
            self.tree.insert("", tk.END, values=(src_ip, dst_ip, protocol))

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=False)

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSniffer(root)
    root.mainloop()
