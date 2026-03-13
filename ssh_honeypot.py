# libraries
import logging
import json
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
import socket
import paramiko
import threading
import signal
import sys
import time

# ---- JSON Formatter ----
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("ip", "username", "password", "command", "key_type", "event"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
        return json.dumps(log_entry)

# ---- SSH banner ----
banner = (
    "\n*******************************************************************************\n"
    "*                        NOTICE TO USERS                                      *\n"
    "*                                                                             *\n"
    "* This Computer System is for the proper use of authorized users only.       *\n"
    "* Individuals accessing, attempting to access, or using this Computer System *\n"
    "* without authority, in violation of their authority, or in excess of their  *\n"
    "* authority, are subject to prosecution and to having all their activities    *\n"
    "* on this System monitored and recorded by JM Technologies personnel.        *\n"
    "*                                                                             *\n"
    "* Certain activity on this System is logged and monitored to ensure          *\n"
    "* continued desirable operation. If such monitoring reveals unauthorized use  *\n"
    "* and/or possible evidence of criminal activity, JM Technologies personnel   *\n"
    "* may provide information and evidence to officials and, as appropriate, law  *\n"
    "* enforcement agencies.                                                       *\n"
    "*                                                                             *\n"
    "* All users of this Computer System:                                         *\n"
    "*  - Consent to use monitoring by JM Technologies for security and system    *\n"
    "*    maintenance purposes.                                                   *\n"
    "*  - Consent to End User Agreements of the University licensed solutions     *\n"
    "*    accessed via this Computer System.                                      *\n"
    "*  - Agree to use the Computer System in compliance with JM Technologies     *\n"
    "*    Acceptable Use Policy.                                                  *\n"
    "*                                                                             *\n"
    "* WARNING: UNAUTHORIZED ACCESS to this Computer System is in violation of    *\n"
    "* the Maryland Code, Criminal Law Article section 8-606 and 7-302 and        *\n"
    "* JM Technologies Policy. Violators will be subject to prosecution and/or    *\n"
    "* discipline.                                                                 *\n"
    "*                                                                             *\n"
    "* JM Technologies maintains the right to examine, or adjust or limit access  *\n"
    "* rights of, JM Technologies accounts, files, mail, and other IT Resources   *\n"
    "* for the purpose of diagnosing and correcting problems with the Computer     *\n"
    "* System or for legal purposes or business continuity. JM Technologies may   *\n"
    "* restrict or rescind IT Resource privileges for cause or to ensure the      *\n"
    "* security of JM Technologies IT Resources.                                  *\n"
    "*                                                                             *\n"
    "*******************************************************************************\n\n"
)

# --- Logger Setup ---
auth_logger = logging.getLogger('AuthLogger')
auth_logger.setLevel(logging.INFO)
auth_handler = RotatingFileHandler('auth_attempts.json', maxBytes=5_000_000, backupCount=10)
auth_handler.setFormatter(JSONFormatter())
auth_logger.addHandler(auth_handler)

cmd_logger = logging.getLogger('CmdLogger')
cmd_logger.setLevel(logging.INFO)
cmd_handler = RotatingFileHandler('commands.json', maxBytes=5_000_000, backupCount=10)
cmd_handler.setFormatter(JSONFormatter())
cmd_logger.addHandler(cmd_handler)
cmd_logger.addHandler(logging.StreamHandler(sys.stdout))


# ---- Emulated Shell ----
def emulated_shell(channel, client_ip):
    try:
        cmd_logger.info(f'Shell session started for {client_ip}', extra={"event": "session_start", "ip": client_ip})
        channel.send(banner.encode())
        channel.send(b"Debian GNU/Linux 11 bullseye \n")
        channel.send(b"Kernel 5.10.0-21-amd64 on an x86_64 \n\n")
        channel.send(f"Last login: Wed Apr 24 10:48:33 2025 from {client_ip}\n".encode())

        # --- Command loop ---
        while True:
            prompt = f"{client_ip}@devops-node:~$ ".encode()
            channel.send(prompt)

            command = b""
            while True:
                char = channel.recv(1)
                if not char:
                    cmd_logger.info(f"Channel closed by {client_ip}", extra={"event": "channel_closed", "ip": client_ip})
                    channel.close()
                    return
                if char == b'\x08' or char == b'\x7f':
                    if len(command) > 0:
                        channel.send(b'\x08 \x08')
                        command = command[:-1]
                elif char == b'\r' or char == b'\n':
                    channel.send(b'\r\n')
                    break
                elif len(char) == 1 and 32 <= ord(char) < 127:
                    channel.send(char)
                    command += char

            stripped_command = command.strip()
            decoded_command = stripped_command.decode(errors="ignore")

            cmd_logger.info("Command entered", extra={
                "event": "command",
                "ip": client_ip,
                "command": decoded_command
            })

            response = b""

            if stripped_command in [b'exit', b'logout']:
                response = b"\r\nlogout\r\nConnection to host closed.\r\n"
                channel.send(response)
                time.sleep(0.5)
                channel.close()
                cmd_logger.info(f"Shell session ended for {client_ip}", extra={"event": "session_end", "ip": client_ip})
                return
            elif decoded_command == 'pwd':
                response = "\r\n/home/svc-devops1\r\n".encode()
            elif decoded_command == 'whoami':
                response = "\r\nsvc-devops1\r\n".encode()
            elif decoded_command == 'hostname':
                response = "\r\ndevops-node\r\n".encode()
            elif decoded_command == 'id':
                response = "\r\nuid=1001(svc-devops1) gid=1001(devops) groups=1001(devops)\r\n".encode()
            elif decoded_command == 'ls':
                response = "\r\njumpbox1.conf  secrets.txt\r\n".encode()
            elif decoded_command == 'cat jumpbox1.conf':
                response = (
                    "\r\n# /home/svc-devops1/.ssh/jumpbox1.conf\n"
                    "Host internal.corp\r\n"
                    "    User devops-admin\r\n"
                    "    ProxyJump 10.0.0.12\r\n"
                    "    Port 22\r\n"
                ).encode()
            elif decoded_command == 'cat secrets.txt':
                response = "\r\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\r\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n".encode()
            elif decoded_command in ['ls -al', 'ls -la', 'ls -a -l']:
                response = (
                    "\r\ntotal 16\r\n"
                    "drwxr-xr-x 3 svc-devops1 devops 4096 Apr 24 10:15 .\r\n"
                    "drwxr-xr-x 4 root        root   4096 Apr 23 08:00 ..\r\n"
                    "-rw------- 1 svc-devops1 devops  512 Apr 24 09:30 .bash_history\r\n"
                    "-rw-r--r-- 1 svc-devops1 devops  220 Apr 15 11:20 .bash_logout\r\n"
                    "-rw-r--r-- 1 svc-devops1 devops 3771 Apr 15 11:20 .bashrc\r\n"
                    "-rw-r--r-- 1 svc-devops1 devops   87 Apr 24 10:15 jumpbox1.conf\r\n"
                    "-rw-r--r-- 1 svc-devops1 devops  128 Apr 24 10:15 secrets.txt\r\n"
                    "-rw-r--r-- 1 svc-devops1 devops  807 Apr 15 11:20 .profile\r\n"
                    "drwx------ 2 svc-devops1 devops 4096 Apr 18 14:00 .ssh\r\n"
                ).encode()
            elif decoded_command == 'cat /etc/passwd':
                response = (
                    "\r\nroot:x:0:0:root:/root:/bin/bash\r\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
                    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
                    "svc-devops1:x:1001:1001::/home/svc-devops1:/bin/bash\r\n"
                ).encode()
            elif decoded_command == 'cat /etc/shadow':
                response = b"\r\ncat: /etc/shadow: Permission denied\r\n"
            elif decoded_command in ['ifconfig', 'ip a', 'ip addr']:
                response = (
                    "\r\neth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\r\n"
                    "        inet 10.0.1.45  netmask 255.255.255.0  broadcast 10.0.1.255\r\n"
                    "        ether 02:42:ac:11:00:02  txqueuelen 1000  (Ethernet)\r\n"
                    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
                    "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
                ).encode()
            elif decoded_command == 'ps aux':
                response = (
                    "\r\nUSER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
                    "root         1  0.0  0.1  10520  3120 ?        Ss   Apr24   0:01 /sbin/init\r\n"
                    "root       512  0.0  0.2  72296  5432 ?        Ss   Apr24   0:00 /usr/sbin/sshd\r\n"
                    "svc-devops1 1024  0.0  0.1  21532  3876 pts/0    Ss   10:15   0:00 -bash\r\n"
                ).encode()
            elif decoded_command == 'history':
                response = (
                    "\r\n    1  ssh devops-admin@internal.corp\r\n"
                    "    2  ls\r\n"
                    "    3  cat secrets.txt\r\n"
                    "    4  cat jumpbox1.conf\r\n"
                    "    5  exit\r\n"
                ).encode()
            elif decoded_command in ['sudo su', 'sudo -s', 'sudo bash']:
                response = b"\r\n[sudo] password for svc-devops1: \r\nSorry, try again.\r\n"
            elif decoded_command == 'uname -a':
                response = "\r\nLinux devops-node 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2024-01-21) x86_64 GNU/Linux\r\n".encode()
            elif decoded_command in ['w', 'who']:
                response = (
                    "\r\n 17:30:00 up 5 days,  2:10,  1 user,  load average: 0.01, 0.02, 0.05\r\n"
                    "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n"
                    f"svc-devops1 pts/0    {client_ip:<15} 10:15    0.00s  0.02s  0.00s -bash\r\n"
                ).encode()
            elif decoded_command.startswith('wget') or decoded_command.startswith('curl'):
                parts = decoded_command.split()
                url = parts[1] if len(parts) > 1 else "unknown"
                response = f"\r\n--2025-04-24 17:30:00-- {url}\r\nResolving {url}... failed: Name or service not known.\r\nwget: unable to resolve host address '{url}'\r\n".encode()
            elif decoded_command.startswith('ping'):
                response = "\r\nPING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\r\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.030 ms\r\n".encode()
            else:
                response = f"\r\nbash: {decoded_command}: command not found\r\n".encode()

            if response:
                channel.send(response)

            command = b""

    except (socket.error, EOFError, paramiko.SSHException) as e:
        cmd_logger.error(f"Error in shell session for {client_ip}: {e}", extra={"event": "shell_error", "ip": client_ip})
    except Exception as e:
        cmd_logger.exception(f"Unexpected error in shell session for {client_ip}: {e}")
    finally:
        if channel and not channel.closed:
            channel.close()
            cmd_logger.info(f'Shell session ended {client_ip}', extra={"event": "session_end", "ip": client_ip})


# ---- Persistent Host Key ----
KEY_PATH = "honeypot_rsa_key"
if os.path.exists(KEY_PATH):
    HOST_KEY = paramiko.RSAKey(filename=KEY_PATH)
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(KEY_PATH)


# ---- SSH Server ----
class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        auth_logger.info("Login attempt", extra={
            "event": "auth_attempt",
            "ip": self.client_ip,
            "username": username,
            "password": password
        })
        time.sleep(0.1)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        auth_logger.info("Public key auth attempt", extra={
            "event": "pubkey_attempt",
            "ip": self.client_ip,
            "username": username,
            "key_type": key.get_name()
        })
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


# --- Connection Handler ---
def handle_connection(client_socket, address):
    client_ip = address[0]
    auth_logger.info(f"Connection received from: {client_ip}:{address[1]}", extra={
        "event": "connection",
        "ip": client_ip
    })

    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1"
        transport.add_server_key(HOST_KEY)

        server_interface = SSHServer(client_ip=client_ip)
        transport.start_server(server=server_interface)

        auth_logger.info(f"SSH negotiation started for {client_ip}", extra={"event": "negotiation", "ip": client_ip})
        channel = transport.accept(20)

        if channel is None:
            auth_logger.warning(f"No channel opened by {client_ip}", extra={"event": "no_channel", "ip": client_ip})
            transport.close()
            return

        auth_logger.info(f'Channel opened for {client_ip}', extra={"event": "channel_open", "ip": client_ip})
        server_interface.event.wait(10)

        if not server_interface.event.is_set():
            auth_logger.warning(f"Client {client_ip} did not request shell", extra={"event": "no_shell", "ip": client_ip})
            channel.close()
            return

        emulated_shell(channel, client_ip)

    except Exception as e:
        auth_logger.exception(f"Exception with {client_ip}: {e}")
    finally:
        if 'transport' in locals() and transport.is_active():
            transport.close()
            auth_logger.info(f"Transport closed for {client_ip}", extra={"event": "transport_closed", "ip": client_ip})


# --- Server Start ---
def start_server(host='0.0.0.0', port=2222):
    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(100)
        auth_logger.info(f"SSH Honeypot started on {host}:{port}", extra={"event": "server_start"})
        print(f"SSH Honeypot listening on {host}:{port}...")

        def shutdown_handler(sig, frame):
            print("\n[!] Shutdown signal received.")
            if server_socket:
                server_socket.close()
            auth_logger.info("Server stopped.", extra={"event": "server_stop"})
            sys.exit(0)

        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)

        while True:
            try:
                client_socket, addr = server_socket.accept()
                threading.Thread(target=handle_connection, args=(client_socket, addr), daemon=True).start()
            except Exception as e:
                auth_logger.exception(f"Accept error: {e}")
                break
    finally:
        if server_socket:
            server_socket.close()


# --- Main ---
if __name__ == "__main__":
    print("Starting SSH Honeypot...")
    start_server()
