import socket
import re

LOG_FILE = "firewall_log.txt"

# Define filtering rules
BLOCKED_IPS = {"192.168.1.0","100.79.117.63"}  # Block specific IPs
BLOCKED_PORTS = {80}      # Block specific ports

# Improved regex to handle timestamps, spacing, and multiple formats
PACKET_REGEX = re.compile(
    r"(?:\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] )?"  # Optional timestamp
    r"SRC: ([\d\.]+):\s*(\d+)\s*->\s*DST: ([\d\.]+):\s*(\d+)"
)

def should_block(packet_info):
    """Check if a packet should be blocked based on filtering rules."""
    match = PACKET_REGEX.search(packet_info)
    if not match:
        print(f"[DEBUG] Failed to parse packet: {packet_info}")  # Debugging info
        return False  # Ignore invalid logs

    src_ip, src_port, dst_ip, dst_port = match.groups()
    src_port, dst_port = int(src_port), int(dst_port)

    # Blocking logic
    if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
        print(f"🚫 Blocking due to IP: {src_ip} or {dst_ip}")  # Debugging
        return True

    if src_port in BLOCKED_PORTS or dst_port in BLOCKED_PORTS:
        print(f"🚫 Blocking due to Port: {src_port} or {dst_port}")  # Debugging
        return True

    return False

def start_logger():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 9090))
    server_socket.listen(5)

    print("Python Firewall Server Running... Waiting for C client.")
    
    try:
        conn, addr = server_socket.accept()
        print(f"🔗 Connected to C Firewall: {addr}")
        conn.settimeout(10)  # Set a timeout for receiving data

        with open(LOG_FILE, "a") as log_file:
            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        print("[INFO] Connection closed by C client.")
                        break

                    packet_info = data.decode("utf-8").strip()
                    
                    if should_block(packet_info):
                        print(f"BLOCKED: {packet_info}")
                        log_file.write(f"BLOCKED: {packet_info}\n")
                        log_file.flush()
                    else:
                        print(f"ALLOWED: {packet_info}")
                        log_file.write(f"ALLOWED: {packet_info}\n")
                        log_file.flush()

                except socket.timeout:
                    print("[WARNING] No data received from C client for 10 seconds. Waiting...")
                    continue

    except KeyboardInterrupt:
        print("\n[INFO] Firewall Logger stopped by user.")
    
    finally:
        conn.close()
        server_socket.close()
        print("[INFO] Firewall Logger shut down.")

if __name__ == "__main__":
    start_logger()
