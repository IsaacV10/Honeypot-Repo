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

Managed to get the honeypot up and running using AWS EC2

I received some bot connections, but most disconnected shortly after establishing contact and no commands were captured beyond the initial connection attempts. 
Tested the honeypot on my local machine to make sure it was working, then deployed it to the cloud. Everything appeared to be functioning as intended on both ends. It seems the lack of interaction may have been due to the way some bots handle connections likely an issue on their end.
I want to attract more traffic, I plan to reroute the honeypot to port 22. 





