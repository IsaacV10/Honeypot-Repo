# SSH & Web Honeypot
A modular, graphic-based honeypot written in Python that supports SSH and HTTP and is deployed on AWS EC2. Using Paramiko for SSH emulation, it simulates a vulnerable Linux server to capture IPs, usernames, passwords, and attacker commands for logging and analysis.

## Features
- Logs IP addresses, login attempts, and shell commands
- Uses RotatingFileHandler for efficient logging
- Dashboard showing live traffic, login attempts, top source IPs, and command timelines.(Comming Soon) 

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




