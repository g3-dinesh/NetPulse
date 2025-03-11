# -*- coding: utf-8 -*-
"""
Created on Tue Mar 11 22:49:15 2025

@author: gayat
"""

# -*- coding: utf-8 -*-
"""
NetPulse: Packet Sniffer with Protocol Analysis, LSTM IDS, and DPI (PyTorch)
Created on Sun Mar  2 02:41:21 2025
@author: gayat
"""

from scapy.all import *
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import time
import threading
import socket
import requests
import re
import numpy as np
import torch
import torch.nn as nn
import pickle
import netifaces

# Define the PyTorch LSTM model
class LSTMPacketClassifier(nn.Module):
    def __init__(self, input_size=5, hidden_size=64, num_layers=2):
        super(LSTMPacketClassifier, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm1 = nn.LSTM(input_size, hidden_size, num_layers=1, batch_first=True)
        self.lstm2 = nn.LSTM(hidden_size, 32, num_layers=1, batch_first=True)
        self.dropout = nn.Dropout(0.2)
        self.fc1 = nn.Linear(32, 16)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(16, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        h0_1 = torch.zeros(1, x.size(0), self.hidden_size).to(x.device)
        c0_1 = torch.zeros(1, x.size(0), self.hidden_size).to(x.device)
        h0_2 = torch.zeros(1, x.size(0), 32).to(x.device)
        c0_2 = torch.zeros(1, x.size(0), 32).to(x.device)
        out, _ = self.lstm1(x, (h0_1, c0_1))
        out = self.dropout(out)
        out, _ = self.lstm2(out, (h0_2, c0_2))
        out = self.dropout(out[:, -1, :])
        out = self.fc1(out)
        out = self.relu(out)
        out = self.fc2(out)
        out = self.sigmoid(out)
        return out

# Load PyTorch model and scaler
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
try:
    model = LSTMPacketClassifier(input_size=5, hidden_size=64, num_layers=2).to(device)
    model.load_state_dict(torch.load("lstm_netpulse_model.pth", map_location=device))
    model.eval()
    with open("scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
except FileNotFoundError:
    print("Error: Model or scaler file not found. Please run train_netpulse.py first.")
    exit(1)

# Global flag to stop sniffing
stop_sniffing = False

def get_interface_details():
    """Get a list of interfaces with their names and IPs for display."""
    interfaces = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            mac = get_if_hwaddr(iface)
            friendly_name = iface
            if ip and ip != "0.0.0.0":
                friendly_name += f" (IP: {ip})"
            if mac:
                friendly_name += f" (MAC: {mac})"
            interfaces.append((friendly_name, iface))
        except:
            continue
    return interfaces if interfaces else [("No interfaces found", "default")]

def get_geolocation(ip, token="YOUR_IPINFO_TOKEN"):
    """Fetch geolocation data using ipinfo.io. Replace token in code or use environment variable."""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={token}")
        data = response.json()
        return data.get("city", "Unknown"), data.get("country", "Unknown")
    except:
        return "Unknown", "Unknown"

def detect_sensitive_data(payload):
    patterns = {
        "Password": r"(?i)pass(?:word)?=[^&]+",
        "API Key": r"(?i)(?:api|key|token)=[a-zA-Z0-9]{16,}",
        "Credit Card": r"\b(?:\d[ -]*?){13,16}\b"
    }
    findings = []
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="ignore")
    for key, pattern in patterns.items():
        if re.search(pattern, payload):
            findings.append(f"Detected {key}")
    return findings

def is_anomalous_lstm(packet, packet_num):
    if IP not in packet:
        return False, "No IP layer"
    
    features = [
        len(packet),
        packet[IP].len if IP in packet else 0,
        0,
        packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0),
        1
    ]
    
    dst_port = features[3]
    if dst_port in [53, 80, 443]:
        print(f"Packet #{packet_num} Features: {features} -> Whitelisted (Benign Port {dst_port})")
        return False, f"Whitelisted: Benign Port {dst_port}"
    
    X = np.array(features).reshape(1, -1)
    X_scaled = scaler.transform(X).reshape(1, 1, len(features))
    
    X_tensor = torch.tensor(X_scaled, dtype=torch.float32).to(device)
    
    with torch.no_grad():
        prediction = model(X_tensor).item()
    
    print(f"Packet #{packet_num} Features: {features} -> LSTM Prediction: {prediction:.2f}")
    return prediction > 0.5, f"LSTM Prediction: {prediction:.2f}"

def guess_app_and_server(packet):
    app = "Unknown"
    server = "Unknown"
    if IP not in packet:
        return app, server
    dst_ip = packet[IP].dst
    if TCP in packet or UDP in packet:
        port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        if port == 80:
            app = "Web Browser (HTTP)"
        elif port == 443:
            app = "Web Browser (HTTPS)" if TCP in packet else "QUIC/HTTP3 (UDP)"
        elif port == 53:
            app = "DNS Client"
        elif port in (1935, 554):
            app = "Video Streaming"
    try:
        server = socket.gethostbyaddr(dst_ip)[0]
    except:
        server = dst_ip
    return app, server

def explain_flags(flags):
    if not flags:
        return "N/A"
    flag_desc = []
    if "S" in flags:
        flag_desc.append("SYN")
    if "A" in flags:
        flag_desc.append("ACK")
    if "F" in flags:
        flag_desc.append("FIN")
    if "R" in flags:
        flag_desc.append("RST")
    if "P" in flags:
        flag_desc.append("PSH")
    if "U" in flags:
        flag_desc.append("URG")
    return ", ".join(flag_desc) if flag_desc else str(flags)

def analyze_packet(packet, all_packets_widget, suspicious_packets_widget, packet_count):
    packet_count[0] += 1
    packet_num = packet_count[0]
    if IP not in packet:
        return
    
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = ip_layer.proto
    ttl = ip_layer.ttl
    ip_flags = str(ip_layer.flags) if ip_layer.flags else "None"
    
    src_port = dst_port = protocol_name = "Unknown"
    flags = ""
    extra_info = ""
    
    if TCP in packet:
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        protocol_name = "TCP"
        flags = str(tcp_layer.flags)
        extra_info = f"TCP Window: {tcp_layer.window}"
    elif UDP in packet:
        udp_layer = packet[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
        protocol_name = "UDP"
        extra_info = f"UDP Length: {udp_layer.len}"
    elif ICMP in packet:
        protocol_name = "ICMP"
        extra_info = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
    
    payload_size = len(packet)
    payload_preview = ""
    sensitive_data = []
    if Raw in packet:
        payload = packet[Raw].load
        payload_preview = payload.hex()[:40]
        sensitive_data = detect_sensitive_data(payload)
    
    anomalous, reason = is_anomalous_lstm(packet, packet_num)
    app, server = guess_app_and_server(packet)
    flags_explanation = explain_flags(flags)
    dst_city, dst_country = get_geolocation(dst_ip)
    
    web_server = "Unknown"
    if dst_port == 443 and "1e100.net" in server:
        web_server = "Google Server (likely Nginx)"
    elif dst_port == 80 or dst_port == 443:
        web_server = "Generic HTTP/HTTPS Server"
    
    packet_info = (
        f"[Packet #{packet_num}] [{time.ctime()}] {protocol_name} Packet:\n"
        f"  Source: {src_ip}:{src_port}\n"
        f"  Destination: {dst_ip}:{dst_port} ({dst_city}, {dst_country})\n"
        f"  TTL: {ttl}\n"
        f"  IP Flags: {ip_flags}\n"
        f"  Protocol Flags: {flags} ({flags_explanation})\n"
        f"  Payload Size: {payload_size} bytes\n"
        f"  Payload (hex, first 40 bytes): {payload_preview or 'N/A'}\n"
        f"  Guessed App: {app}\n"
        f"  Domain Name: {server}\n"
        f"  Web Server: {web_server}\n"
        f"  Extra Info: {extra_info}\n"
        f"  {reason}\n"
    )
    if anomalous:
        packet_info += f"  ANOMALY DETECTED\n"
    if sensitive_data:
        packet_info += f"  SENSITIVE DATA DETECTED: {', '.join(sensitive_data)}\n"
    
    packet_info += "-" * 50 + "\n"
    
    all_packets_widget.config(state=tk.NORMAL)
    all_packets_widget.insert(tk.END, packet_info)
    all_packets_widget.config(state=tk.DISABLED)
    all_packets_widget.see(tk.END)
    
    if anomalous or sensitive_data:
        suspicious_packets_widget.config(state=tk.NORMAL)
        suspicious_packets_widget.insert(tk.END, packet_info, "anomaly")
        suspicious_packets_widget.config(state=tk.DISABLED)
        suspicious_packets_widget.see(tk.END)

def start_sniffer(interface, count, filter, all_packets_widget, suspicious_packets_widget):
    global stop_sniffing
    stop_sniffing = False
    packet_count = [0]
    
    def sniff_thread():
        all_packets_widget.config(state=tk.NORMAL)
        all_packets_widget.insert(tk.END, f"Sniffing on {interface} with filter: {filter or 'none'}\n")
        all_packets_widget.config(state=tk.DISABLED)
        
        try:
            conf.use_pcap = True
            sniff(
                iface=interface,
                prn=lambda pkt: analyze_packet(pkt, all_packets_widget, suspicious_packets_widget, packet_count),
                count=count,
                filter=filter,
                stop_filter=lambda x: stop_sniffing
            )
            all_packets_widget.config(state=tk.NORMAL)
            all_packets_widget.insert(tk.END, "Sniffing completed.\n")
            all_packets_widget.config(state=tk.DISABLED)
        except Exception as e:
            all_packets_widget.config(state=tk.NORMAL)
            all_packets_widget.insert(tk.END, f"Error: {e}\nPlease ensure you have admin/root privileges and a valid interface.\n")
            all_packets_widget.config(state=tk.DISABLED)
    
    threading.Thread(target=sniff_thread, daemon=True).start()

def create_gui():
    root = tk.Tk()
    root.title("NetPulse: Packet Sniffer with LSTM IDS (PyTorch)")
    root.geometry("800x600")
    
    notebook = ttk.Notebook(root)
    notebook.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    
    all_packets_frame = ttk.Frame(notebook)
    notebook.add(all_packets_frame, text="All Packets")
    all_packets_widget = scrolledtext.ScrolledText(all_packets_frame, wrap=tk.WORD, state=tk.DISABLED, height=20)
    all_packets_widget.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
    
    suspicious_packets_frame = ttk.Frame(notebook)
    notebook.add(suspicious_packets_frame, text="Suspicious Packets")
    suspicious_packets_widget = scrolledtext.ScrolledText(suspicious_packets_frame, wrap=tk.WORD, state=tk.DISABLED, height=20)
    suspicious_packets_widget.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
    suspicious_packets_widget.tag_config("anomaly", foreground="red")
    
    control_frame = tk.Frame(root)
    control_frame.pack(pady=5)
    
    tk.Label(control_frame, text="Select Interface:").pack(side=tk.LEFT, padx=5)
    interfaces = get_interface_details()
    interface_var = tk.StringVar(value=interfaces[0][0] if interfaces else "No interfaces found")
    interface_menu = tk.OptionMenu(control_frame, interface_var, *[i[0] for i in interfaces])
    interface_menu.pack(side=tk.LEFT, padx=5)
    
    def start():
        selected = interface_var.get()
        for friendly_name, iface in interfaces:
            if friendly_name == selected:
                interface = iface
                break
        else:
            messagebox.showerror("Error", "Invalid interface selected.")
            return
        
        count = 0
        filter = None
        start_sniffer(interface, count, filter, all_packets_widget, suspicious_packets_widget)
    
    tk.Button(control_frame, text="Start Sniffing", command=start).pack(side=tk.LEFT, padx=5)
    
    def stop():
        global stop_sniffing
        stop_sniffing = True
        all_packets_widget.config(state=tk.NORMAL)
        all_packets_widget.insert(tk.END, "Sniffing stopped by user.\n")
        all_packets_widget.config(state=tk.DISABLED)
    
    tk.Button(control_frame, text="Stop Sniffing", command=stop).pack(side=tk.LEFT, padx=5)
    
    root.mainloop()

if __name__ == "__main__":
    if not hasattr(conf, "use_pcap"):
        print("Error: Npcap/libpcap not found. Please install it (see README).")
        exit(1)
    create_gui()