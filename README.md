# Antigravity Port Scanner

A multi-threaded, GUI-based port scanner written in Python using PyQt5 and Scapy. This tool supports both standard TCP Connect scans and stealthier SYN scans, along with banner grabbing and basic OS fingerprinting.

## Features

- **Multi-threaded Scanning**: Scans multiple ports simultaneously for high speed.
- **Scan Types**:
  - **Connect Scan**: Standard TCP handshake (non-privileged).
  - **SYN Scan**: Stealthy half-open scanning (requires Admin/Root privileges).
- **Service Detection**: Grabs banners from open ports to identify running services.
- **OS Fingerprinting**: Basic operating system guessing based on TTL analysis.
- **GUI**: User-friendly interface with real-time results table.
- **Exportable Results**: (Planned for future release) - Results are currently displayed in the GUI.

## Prerequisites

- Python 3.8+
- [Npcap](https://npcap.com/) (Required for SYN scanning on Windows)

## Installation

1. **Clone the repository** (or download the files).
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   *Dependencies include `PyQt5` and `scapy`.*

## Usage

### standard Run (Connect Scan)
1. Open a terminal.
2. Run the application:
   ```bash
   python main.py
   ```
3. Enter the Target IP (e.g., `google.com` or `192.168.1.1`).
4. Enter the Port Range (e.g., `20` to `100`).
5. Click **Start Scan**.

### SYN Scan (Stealth Mode)
**Note**: SYN scanning requires Administrator privileges to create raw sockets.

1. Open a terminal as **Administrator** (Windows) or use `sudo` (Linux).
2. Run the application:
   ```bash
   python main.py
   ```
3. Select "SYN Scan" from the dropdown menu.
4. Click **Start Scan**.

## Troubleshooting
- **PermissionError**: If you select "SYN Scan" without admin privileges, the scanner will fail or default to error states. Restart the app as Administrator.
- **Missing DLL / Npcap**: On Windows, ensure Npcap is installed with "WinPcap API-compatible mode".

## Disclaimer
This tool is for educational and authorized testing purposes only. Do not scan networks or hosts without permission.
