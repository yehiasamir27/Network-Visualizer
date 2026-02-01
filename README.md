# Network Visualizer — Attack Surface Mapper 

A **blue-team style network visibility tool** that turns raw Nmap discovery into a **hacker-style web dashboard** and a **topology graph** that links **IPs ↔ open ports** in one view.

Instead of reading long terminal output, you get a **GUI that shows what is exposed, where, and why it matters**.

**Stack:** Nmap + Python (python-nmap) + NetworkX + Matplotlib + Flask

## Problem solved
Network scanning results are usually hard to review fast:
- Nmap output is long and easy to miss details in
- It’s not clear which ports belong to which IP at a glance
- Quick “what should I review first?” is not obvious

This project solves that by mapping **IP → open ports visually**, and adding a **short exposure summary per host** so risky systems stand out faster.

## UI

<img width="2527" height="1167" alt="Screenshot 2026-02-01 185726" src="https://github.com/user-attachments/assets/f8d87a0c-cdf6-4caa-9e74-fc58c3b1b5ad" />

<img width="2362" height="421" alt="image" src="https://github.com/user-attachments/assets/4228f915-a53b-455e-90ae-bb44ac257901" />

<img width="1716" height="1132" alt="Screenshot 2026-02-01 191306" src="https://github.com/user-attachments/assets/1f6b011e-fb9f-4dde-b747-9df10f3b478b" />
Visual mapping of hosts ↔ open ports with exposure scoring for quick triage. (Private/internal IPs are redacted.)

## Why this tool is strong
- **Topology View (IP ↔ Port Mapping):** Every host is linked to its exposed ports visually, so risky systems stand out fast.
- **Risk Tags & Exposure Summary:** Each host gets a **risk level (LOW / MED / HIGH)** based on exposed services (example: SMB/RPC/NetBIOS).
- **Fast Review UI:** The dashboard shows:
  - IP address
  - open ports + protocol
  - service name
  - short “why it matters”
  - risk points + top exposures
- **Evidence-Friendly Output:** Generates:
  - a **graph image** you can attach in reports
  - a **human-readable exposure report** inside the dashboard (not just JSON)

## What it detects (safe + practical)
This tool does **NOT** claim malware detection.  
It flags **risky exposure** that is commonly abused in real attacks (example: SMB 445, RPC 135, NetBIOS 139) so defenders can review and harden systems quickly.

## Run locally

## Notes - Scan only networks you own or have permission to test. - Risk levels are based on exposed services, not malware verdicts. (Add Network Visualizer project + README) add what proplem we solved with this project

### 1) Install Nmap (Windows)
Make sure Nmap exists here:
`C:\Program Files (x86)\Nmap\nmap.exe`

### 2) Create venv + install dependencies
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt



