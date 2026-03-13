🍯 SSH Honeypot & Threat Intelligence Dashboard
A fully functional SSH honeypot deployed on AWS EC2 that captures real-world attack data and visualizes it through a live threat intelligence dashboard with GeoIP mapping.

# Overview
This project simulates a legitimate Linux server to attract and log unauthorized SSH access attempts. All captured data is structured in JSON format and displayed through a real-time Flask dashboard featuring attack timelines, credential analysis, and a world map showing attack origins.

# Features
SSH Honeypot — Emulates a real Debian Linux server using Paramiko
Convincing Shell — Fake filesystem with secrets.txt, jumpbox1.conf, bash history, /etc/passwd, and more
JSON Structured Logging — All auth attempts and commands logged in structured JSON
Real-time Dashboard — Live Flask dashboard with auto-refresh every 30 seconds
GeoIP World Map — Interactive Leaflet map showing attack origins
Attack Timeline — Hourly chart showing attack patterns
Credential Analysis — Top usernames, passwords, and source IPs
Country Breakdown — Flag emoji + bar chart by country
Persistent RSA Host Key — Consistent fingerprint across restarts
Systemd Services — Both services auto-start on reboot
Legal Banner — Proper authorized-use-only warning under Maryland Code

## Tools & Technologies 
- Python
- Paramiko
- Hostinger VPS 
- AWS EC2
- Linux 

# SSH
The project originally supported only SSH. Within three days of deployment, the honeypot recorded about ten connection attempts. I left it running for another week and saw the same pattern: clients would connect but not actually attempt to log in with a username or password. My interpretation is that automated bots were scanning for vulnerabilities and disconnecting without interacting further.

<img width="2378" height="307" alt="Screenshot 2025-09-25 195238" src="https://github.com/user-attachments/assets/98bf0d8c-a91f-482c-890b-ce62bc8a7d3e" />

I made several adjustments to the honeypot’s main code: I tweaked the SSH banner to look more realistic and friendly, and I double-checked the connection handling to ensure the connection arguments work as intended and are not causing the lack of interaction. I plan to store each event as a newline-delimited JSON object (timestamp, session_id, src_ip, username, command) to improve readability.

# HTTP
I decided to build a web-based honeypot after learning I could capture interaction data and visualize it with graphs. I expect the web honeypot will attract more interaction than the SSH honeypot. I completed the web honeypot’s XML and Python files, and I plan to try hosting it on Hostinger (instead of AWS EC2) once I finish the parser. Sometime this week I'll post the web honeypots code in the repo. 




