# 🍯 SSH Honeypot & Threat Intelligence Dashboard
 
A fully functional SSH honeypot deployed on AWS EC2 that captures real-world attack data and visualizes it through a live threat intelligence dashboard with GeoIP mapping.
 
---
 
## 📌 Overview
 
This project simulates a legitimate Linux server to attract and log unauthorized SSH access attempts. All captured data is structured in JSON format and displayed through a real-time Flask dashboard featuring attack timelines, credential analysis, and a world map showing attack origins.
 
---
 
## 🏗️ Architecture
 
```
Internet (Attackers)
        │
        ▼
   EC2 Instance (AWS)
        │
   Port 22 (Public)
        │
   iptables redirect
        │
        ▼
   Port 2222 → honeypot.py (Paramiko SSH Server)
                    │
                    ├── Logs to auth_attempts.json
                    └── Logs to commands.json
                              │
                              ▼
                    dashboard.py (Flask Backend)
                              │
                              ▼
                    static/index.html (Frontend)
                    http://server-ip:5000
```
 
---
 
## 📁 Project Structure
 
```
honeypot/
├── honeypot.py          # SSH honeypot server (Paramiko)
├── dashboard.py         # Flask backend + GeoIP API
├── static/
│   └── index.html       # Dashboard frontend (Chart.js + Leaflet)
├── requirements.txt     # Python dependencies
├── .gitignore           # Excludes logs and keys
└── README.md            # Project documentation
```
 
---
 
## ✨ Features
 
- **SSH Honeypot** — Emulates a real Debian Linux server using Paramiko
- **Convincing Shell** — Fake filesystem with `secrets.txt`, `jumpbox1.conf`, bash history, `/etc/passwd`, and more
- **JSON Structured Logging** — All auth attempts and commands logged in structured JSON
- **Real-time Dashboard** — Live Flask dashboard with auto-refresh every 30 seconds
- **GeoIP World Map** — Interactive Leaflet map showing attack origins
- **Attack Timeline** — Hourly chart showing attack patterns
- **Credential Analysis** — Top usernames, passwords, and source IPs
- **Country Breakdown** — Flag emoji + bar chart by country
- **Persistent RSA Host Key** — Consistent fingerprint across restarts
- **Systemd Services** — Both services auto-start on reboot
- **Legal Banner** — Proper authorized-use-only warning under Maryland Code
 
---
 
## 🛠️ Tech Stack
 
| Component | Technology |
|-----------|------------|
| Honeypot Server | Python, Paramiko |
| Web Framework | Flask |
| Frontend | HTML, CSS, JavaScript |
| Charts | Chart.js |
| Map | Leaflet.js + OpenStreetMap |
| GeoIP | ip-api.com (free, no key required) |
| Logging | Python RotatingFileHandler (JSON) |
| Hosting | AWS EC2 (Ubuntu 22.04) |
| Process Management | systemd |
| Network | iptables NAT redirect |
 
---
 
## 🚀 Deployment
 
### Prerequisites
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3-pip -y
sudo pip3 install paramiko flask --break-system-packages --ignore-installed
```
 
### Setup Order (Critical!)
```bash
# 1. Set up real SSH on port 2200 FIRST
sudo nano /etc/ssh/sshd_config   # Add: Port 2200
sudo systemctl restart ssh
 
# 2. Test port 2200 works before continuing
ssh -i your-key.pem ubuntu@your-ip -p 2200
 
# 3. THEN set up iptables redirect
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```
 
### Run as Services
```bash
# Honeypot service
sudo nano /etc/systemd/system/honeypot.service
 
# Dashboard service
sudo nano /etc/systemd/system/honeypot-dashboard.service
 
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable honeypot honeypot-dashboard
sudo systemctl start honeypot honeypot-dashboard
```
 
### AWS Security Group Rules
 
| Port | Source | Purpose |
|------|--------|---------|
| 22 | 0.0.0.0/0 | Honeypot bait (public) |
| 2200 | Your IP only | Real SSH admin access |
| 5000 | Your IP only | Dashboard access |
 
---
 
## 📊 Sample Dashboard
 
The dashboard displays:
- Total auth attempts, unique IPs, commands run, and connections
- Hourly attack timeline chart
- Interactive world map with attack origins
- Top attacking countries with flag emojis
- Top usernames and passwords attempted
- Live auth feed with GeoIP location
 
---
 
## 📋 Sample JSON Log Format
 
**auth_attempts.json**
```json
{"timestamp": "2026-03-01T14:23:01+00:00", "level": "INFO", "logger": "AuthLogger", "message": "Login attempt", "event": "auth_attempt", "ip": "185.220.101.45", "username": "root", "password": "123456"}
```
 
**commands.json**
```json
{"timestamp": "2026-03-01T14:23:05+00:00", "level": "INFO", "logger": "CmdLogger", "message": "Command entered", "event": "command", "ip": "185.220.101.45", "command": "cat secrets.txt"}
```
 
---
 
## 🔍 Key Findings
 
After running the honeypot for approximately two weeks:
 
- **2,400+ authentication attempts** captured
- **87+ unique IP addresses** identified
- **12+ countries** represented in attack traffic
- **Top attacking regions:** Singapore, Germany, Netherlands
- **Most common usernames:** root, admin, pi, ubuntu
- **Most common passwords:** 123456, password, admin, 12345678, qwerty
- **First attack detected within minutes** of deployment
- **~95% automated bot traffic** — credential stuffing via wordlists
- **~5% potential human attackers** — explored shell, ran multiple commands
 
---
 
## 🧠 Lessons Learned
 
- **Bots scan the entire internet constantly** — an open port 22 gets hit within minutes
- **Credential stuffing is real** — the same weak passwords appear repeatedly from global sources
- **Attribution is hard** — most attacks route through VPS providers in Singapore/EU to hide origin
- **SSH keys >> passwords** — not a single attacker used a valid key, only password brute force
- **Always secure admin access before locking down** — learned this the hard way after getting locked out by our own honeypot!
- **JSON logging is powerful** — structured logs made dashboard analysis much easier than plain text
