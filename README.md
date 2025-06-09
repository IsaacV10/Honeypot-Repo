# Cloud-Based SSH Honeypot

A lightweight SSH honeypot built in Python using Paramiko to simulate a vulnerable Linux server and capture real-world brute-force login attempts. Deployed on AWS EC2 for attacker interaction and logging.

## Features
- Logs IP addresses, login attempts, and shell commands
- Uses RotatingFileHandler for efficient logging
- Deployable on any cloud VM (tested on Ubuntu EC2)
- Somewhat realistic banner to simulates SSH service

## Technologies Used
- Python
- Paramiko
- AWS EC2 (Ubuntu)
- Linux CLI



Date 5/15/25

I successfully deployed the honeypot on an AWS EC2 instance.

During the initial deployment, I received a few connection attempts from bots. Most of them disconnected shortly after establishing connection, and no credentials or commands were captured beyond the initial handshake. 
To ensure everything was working as intended, I tested the honeypot on my local machine to make sure it was working, then deployed it to the cloud. Everything appeared to be functioning as intended on both ends. 
- did not receive a lot of traffic on port 2222; plan on rerouting to port 22




