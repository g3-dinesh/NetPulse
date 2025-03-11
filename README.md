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
