#libraries 
import logging 
from logging.handlers import RotatingFileHandler
import socket 
import paramiko
import threading
import signal
import sys
import time

#constants 
logging_format = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')


# ---- SSH banner ----

banner = (
    "\n************************************************************************\n"
    "*                          NOTICE TO USERS                             *\n"
    "*                                                                      *\n"
    "* This system is for authorized use only. All activity is monitored.  *\n"
    "* Disconnect immediately if you are not an authorized user.           *\n"
    "************************************************************************\n\n"
)
# The banner will be sent after the channel is initialized in the emulated_shell function.
# --- Logger Setup ---
auth_logger = logging.getLogger('FunnelLogger')
auth_logger.setLevel(logging.INFO)
auth_handler = RotatingFileHandler('auth_attempt.log', maxBytes=2000, backupCount=5)
auth_handler.setFormatter(logging_format)
auth_logger.addHandler(auth_handler)

cmd_logger = logging.getLogger('CmdLogger')
cmd_logger.setLevel(logging.INFO)
cmd_handler = RotatingFileHandler('commands_entered.log', maxBytes=2000, backupCount=5)
cmd_handler.setFormatter(logging_format)
cmd_logger.addHandler(cmd_handler)

cmd_console_handler = logging.StreamHandler(sys.stdout)
cmd_console_handler.setFormatter(logging_format)
cmd_logger.addHandler(cmd_console_handler)

# ---- emulated Shells ----
def emulated_shell(channel, client_ip):

    try:
        cmd_logger.info(f'Shell session started for {client_ip}')
        channel.send(banner.encode())  
        channel.send(b"Debian GNU/Linux 11 bullseye \\n")
        channel.send(b"Kernel 5.10.0-21-amd64 on an x86_64 \\n\n")
        channel.send(f"Last login: Wed Apr 24 10:48:33 2025 from {client_ip}\n".encode())

    # --- Command loop ---
        while True:
            prompt = f"{client_ip}@devops-node:~$ ".encode()
            channel.send(prompt)

            command = b""
            while True:
                char = channel.recv(1)
                if not char: # Handle channel closure gracefully
                    cmd_logger.info(f"Channel closed by {client_ip}")
                    channel.close()
                    return # Exit the shell function
                if char == b'\x08' or char == b'\x7f':
                    if len(command) > 0:
                        channel.send(b'\x08 \x08')
                        command = command[:-1]
             
                elif char == b'\r' or char == b'\n':
                    channel.send(b'\r\n')
                    break 
                elif 32 <= ord(char) < 127:
                    channel.send(char)
                    command += char
            stripped_command = command.strip()
            decoded_command = stripped_command.decode(errors="ignore")
            cmd_logger.info(f"IP: {client_ip}, Command: {decoded_command}")
            response = b""
            

            if stripped_command == b'exit' or stripped_command == b"logout":
                response = b"\r\nlogout\r\nConnection to host closed.\r\n"
                channel.send(response)
                time.sleep(0.5)
                channel.close()
                cmd_logger.info(f"Shell session ended for {client_ip}")
                return
            elif decoded_command == 'pwd':
                response = "\r\n/home/svc-devops1\r\n"
            elif decoded_command == 'whoami':
                response = "\r\nsvc-devops1\r\n"
            elif decoded_command == 'hostname':
                response = "\r\ndevops-node\r\n"
            elif decoded_command == 'id':
                response = "\r\nuid=1001(svc-devops1) gid=1001(devops) groups=1001(devops)\r\n"
                # -- File and directory simulation --
            elif decoded_command == 'ls':
                response = "\r\njumpbox1.conf  secrets.txt\r\n"
            elif decoded_command == 'cat jumpbox1.conf':
                response = (
                    "\r\n# /home/svc-devops1/.ssh/jumpbox1.conf\n"
                    "# SSH Config for internal jump\r\n"
                    "Host internal.corp\r\n"
                    "    User devops-admin\r\n"
                    "    ProxyJump 10.0.0.12\r\n"
                    "    Port 22\r\n"
                )
            elif decoded_command == 'cat secrets.txt':
                response = "\r\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\r\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n"
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
                )
             # Handlers for common attacler commands 
            elif decoded_command.startswith('wget') or decoded_command.startswith('curl'):
                response = "\r\n--2025-04-24 17:30:00-- URL_HERE\r\nResolving URL_HERE... failed: Name or service not known.\r\nwget: unable to resolve host address 'URL_HERE'\r\n"
            elif decoded_command.startswith('ping'):
                 response = "\r\nPING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\r\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.030 ms\r\n" # Fake ping loopback
            elif decoded_command == 'uname -a':
                response = "\r\nLinux devops-node 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2024-01-21) x86_64 GNU/Linux\r\n"
            elif decoded_command == 'w' or decoded_command == 'who':
                response = "\r\n 17:30:00 up 5 days,  2:10,  1 user,  load average: 0.01, 0.02, 0.05\r\n" \
                           "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\r\n" \
                           f"svc-devops1 pts/0    {client_ip:<15} 10:15    0.00s  0.02s  0.00s -bash\r\n".encode()
            # Generic response for unknown commands
           
                response = f"\r\nbash: {decoded_command}: command not found\r\n".encode()
            else:
                # If the command was empty (just Enter pressed), send nothing but the next prompt
                pass
            if response:
                channel.send(response)
            
            command = b""
    except (socket.error, EOFError, paramiko.SSHException) as e:
        cmd_logger.error(f"Error in shell session for {client_ip}: {e}")
    except Exception as e:
        cmd_logger.exception(f"Unexpected error in shell session for {client_ip}: {e}")
    finally: 
        if channel and not channel.closed:
            channel.close()
            cmd_logger.info(f'Shell session ended {client_ip}')
    



# SSH Server + Port 
HOST_KEY = paramiko.RSAKey.generate(2048)

# Define fake SSH server

        
# provison SSH-based Honeypot/SSH Server Implementation
class SSHServer(paramiko.ServerInterface):

    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event() # Event for signaling channel readiness

    def check_channel_request(self, kind, chanid):
       
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        
        attempt_info = f"Login attempt: IP={self.client_ip}, User ='{username}', Pass='{password}'"
        auth_logger.info(attempt_info)
        time.sleep(0.1)
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        
        key_info = f"Public key auth attempt: IP={self.client_ip}, User ='{username}', Key Type='{key.get_name()}'"
        auth_logger.info(key_info)
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set() # Signal that the shell is ready
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        
        return True


# --- Connection handling ---

def handle_connection(client_socket,address):
    client_ip = address[0]
    auth_logger.info(f"Connection received from: {client_ip}:{address[1]}")


    try:
        transport = paramiko.Transport(client_socket)
        SERVER_IDENTIFICATION = "SSH-2.0-OpenSSH_8.2p1"  # Define the SSH server version string
        transport.local_version = SERVER_IDENTIFICATION  # Set the SSH version string
        transport.add_server_key(HOST_KEY) 

        server_interface = SSHServer(client_ip=client_ip) # Pass client_ip to the server interface

        # Start the server protocol negotiation
        transport.start_server(server=server_interface)
        auth_logger.info(f"SSH negotiation started for {client_ip}")

        channel = transport.accept(20)
        if channel is None:
            auth_logger.warning(f"No channel opened by {client_ip}, closing transport.")
            transport.close()
            return
        auth_logger.info(f'Channel opened for {client_ip}')

        server_interface.event.wait(10)
        if not server_interface.event.is_set():
            auth_logger.warning(f"Client {client_ip} did not request shell, closing channel.")
            channel.close()
            return
        auth_logger.info(f"Shell requested by {client_ip}, launching emulated shell.")
        # Launch the emulated shell environment
        emulated_shell(channel, client_ip)

    except paramiko.SSHException as ssh_err:
        auth_logger.error(f"SSH negotiation/protocol error for {client_ip}: {ssh_err}")
    except socket.error as sock_err:
         auth_logger.error(f"Socket error during handling for {client_ip}: {sock_err}")
    except Exception as e:
        # Log unexpected errors during connection handling
        auth_logger.exception(f"Unexpected error handling connection for {client_ip}: {e}") # Use exception for traceback
    finally:
        # Ensure transport is closed if it exists
        if 'transport' in locals() and transport.is_active():
            transport.close()
            auth_logger.info(f"Transport closed for {client_ip}")
        # Socket is implicitly closed when the thread exits
        
# --- Server startup ---

def start_server():
    server_socket = None 
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow reusing the address quickly after shutdown
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", 2222))
        server_socket.listen(100) # Listen for up to 100 queued connections
        auth_logger.info(f"SSH Honeypot server started on 0.0.0.0:2222")
        print(f"SSH Honeypot listening on 0.0.0.0:2222...") # Also print to console


        def shutdown_handler(sig,frame):
            print("\nShutdown signal received. Closing server socket...")
            auth_logger.info("Shutdown signal received. Closing server socket.")
            if server_socket:
                server_socket.close()
            print("Server stopped.")
            auth_logger.info("server stopped.")
            sys.exit(0)

        signal.signal(signal.SIGINT, shutdown_handler)  # Handle Ctrl+C
        signal.signal(signal.SIGTERM, shutdown_handler) # Handle termination signal

        while True:
            try:
                # Accept new connections
                client_socket, addr = server_socket.accept()
                # Create and start a new thread for each connection
                conn_thread = threading.Thread(target=handle_connection, args=(client_socket, addr), daemon=True)
                conn_thread.start()
            except OSError:
                # This likely happens when the socket is closed during shutdown
                auth_logger.info("Server socket closed, exiting accept loop.")
                break # Exit the loop if the socket is closed
            except Exception as e:
                auth_logger.exception(f"Error accepting connection: {e}") # Log other accept errors

    except socket.error as bind_err:
         print(f"[ERROR] Could not bind to 0.0.0.0:2222 - {bind_err}. Is the port already in use?")
         auth_logger.error(f"Could not bind to 0.0.0.0:2222 - {bind_err}")
    except Exception as e:
        print(f"[ERROR] Failed to start server: {e}")
        auth_logger.exception(f"Failed to start server: {e}")
    finally:
        if server_socket:
            server_socket.close() # Ensure socket is closed on any error during startup


# --- Main Execution Guard ---
if __name__ == "__main__":
    print("Starting SSH Honeypot...")
    start_server()


