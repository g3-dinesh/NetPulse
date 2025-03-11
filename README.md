# NetPulse
**NetPulse** is a powerful packet sniffer that captures network traffic, analyzes packets, and detects anomalies using a PyTorch-based LSTM model. It includes deep packet inspection (DPI) and geolocation features, all presented in an intuitive GUI.
## Features
- Real-time packet capture and protocol analysis (TCP, UDP, ICMP).
- LSTM-based intrusion detection system (IDS) using PyTorch.
- Deep packet inspection for sensitive data (e.g., passwords, API keys).
- Geolocation of destination IPs using ipinfo.io.
- Cross-platform interface selection with IP and MAC details.

## Prerequisites
- Python 3.7+
- Administrative/root privileges (required for packet sniffing)
- **Npcap** (Windows) or **libpcap** (Linux/Mac) for packet capture
- ipinfo.io access token (for geolocation)
- CICIDS2017 dataset (optional, for training)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/NetPulse.git
   cd NetPulse
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Install Npcap (Windows) or libpcap (Linux/Mac):
Windows: Download and install Npcap from https://nmap.org/npcap/.
Linux: Install libpcap with sudo apt-get install libpcap-dev.
Mac: Install libpcap via Homebrew: brew install libpcap.
Obtain an ipinfo.io access token:
Sign up at https://ipinfo.io/signup to get a free token.
Replace "YOUR_IPINFO_TOKEN" in netpulse.py (line ~70) with your token

Usage
1.Train the Model (Optional):
Download the CICIDS2017 dataset CSVs from https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset
Place them in the archive (2) folder (or adjust folder_path in train_netpulse.py).
Run:
   ```bash
python train_netpulse.py
```
This generates lstm_netpulse_model.pth and scaler.pkl.
2.Run the Sniffer:
Ensure you’ve replaced the ipinfo.io token in netpulse.py.
Run with admin/root privileges:
 ```bash

sudo python netpulse.py  # Linux/Mac
# Windows: Run as Administrator via cmd or PowerShell
```
Select an interface from the dropdown (e.g., "eth0 (IP: 192.168.1.2)") and click "Start Sniffing".

Interface Selection
The GUI displays all available network interfaces with their IPs and MAC addresses (e.g., "Wi-Fi (IP: 192.168.1.3) (MAC: 80:38:fb:f7:d4:ec)").
Choose the interface connected to the network you want to monitor.

Notes
If lstm_netpulse_model.pth or scaler.pkl are missing, run train_netpulse.py first.
The current model is trained on CICIDS2017 flow data, which may misclassify single packets. For better accuracy, retrain with single-packet features from CICIDS2017 PCAPs.

Troubleshooting
Permission Denied: Run with admin/root privileges (sudo or as Administrator).
No Interfaces Found: Ensure Npcap/libpcap is installed and network adapters are active.
Geolocation Fails: Verify your ipinfo.io token is correct and you have internet access.
Model Errors: Confirm lstm_netpulse_model.pth and scaler.pkl exist in the directory.

Contributing
Feel free to fork, submit pull requests, or report issues on GitHub!


