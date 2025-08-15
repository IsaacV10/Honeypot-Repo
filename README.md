# SSH Honeypot

A lightweight SSH honeypot built in Python using Paramiko to simulate a vulnerable Linux server and capture real-world brute-force login attempts. Deployed on AWS EC2 for attacker interaction and logging.

## Features
- Logs IP addresses, login attempts, and shell commands
- Uses RotatingFileHandler for efficient logging
- Deployable on any cloud VM (tested on Ubuntu EC2)
- Somewhat realistic banner to simulates SSH service

## Tools Used
- Python
- Paramiko
- AWS EC2 (Ubuntu)
- Linux CLI








