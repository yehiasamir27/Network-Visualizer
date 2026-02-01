
# Network-Visualizer
=======
﻿# Network Visualizer — Attack Surface Mapper 🛰️

A **blue-team style network visibility tool** that turns raw Nmap discovery into a **clean hacker-style dashboard** and a **topology graph** that links **IPs ↔ open ports** in one view.

Instead of reading long terminal output, you get a **GUI that shows exactly what is exposed, where, and why it matters**.

**Stack:** Nmap + Python (python-nmap) + NetworkX + Matplotlib + Flask

## Demo
![Demo](screenshots/demo.png)

## Why this tool is strong
- **Topology View (IP ↔ Port Mapping):** Every host is linked to its exposed ports visually, so you can spot risky systems fast.
- **Risk Tags & Exposure Summary:** Each host gets a **risk level (LOW / MED / HIGH)** based on exposed services (ex: SMB/RPC/NetBIOS).
- **Fast Review UI:** A hacker-style interface that lists:
  - IP address
  - open ports + protocol
  - service name
  - short “why it matters”
  - risk points + top exposures
- **Evidence-Friendly Output:** Generates:
  - a **graph image** you can attach in reports
  - a **human-readable exposure report** inside the dashboard (not just JSON)

## What it detects (safe + practical)
This tool does **NOT claim malware detection**.  
It flags **risky exposure** that is commonly abused in real attacks (example: SMB 445, RPC 135, NetBIOS 139) so defenders can review and harden systems quickly.

## Run locally

### 1) Install Nmap (Windows)
Make sure Nmap exists here:  
C:\Program Files (x86)\Nmap\nmap.exe

### 2) Create venv + install dependencies
\\\ash
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
\\\

### 3) Run the app
python network_visualizer.py

Then open:
http://127.0.0.1:5000

## Notes
- Scan only networks you own or have permission to test.
- Risk levels are based on exposed services, not malware verdicts.
 (Add Network Visualizer project + README)
