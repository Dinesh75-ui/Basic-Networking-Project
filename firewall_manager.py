import socket
import re
import os
import signal
import sys
import time

LOG_BLOCKED_FILE = "blocked_firewall_log.txt"
LOG_ALLOWED_FILE = "allowed_firewall_log.txt"
BLOCKED_ENTRIES = set()

# Extract IP and port info
PACKET_REGEX = re.compile(
    r"SRC: ([\d\.]+):\s*(\d+)\s*->\s*DST: ([\d\.]+):\s*(\d+)"
)

BLOCKED_IPS = {"192.168.128.4","100.79.117.63"}
BLOCKED_PORTS = {80}

def block_in_windows(ip, port):
    key = f"{ip}:{port}"
    if key in BLOCKED_ENTRIES:
        print(f"[INFO] {key} is already blocked. Skipping.")
        return

    BLOCKED_ENTRIES.add(key)

    cmd_check = f'netsh advfirewall firewall show rule name="Blocked {key}"'
    result = os.popen(cmd_check).read()
    if "No rules match" not in result:
        print(f"🛑 [Rule already exists for {key}] Skipping blocking.")
        return

    cmd = (
        f'netsh advfirewall firewall add rule name="Blocked {key}" '
        f'dir=in action=block remoteip={ip} protocol=TCP remoteport={port}'
    )
    os.system(cmd)
    print(f"[!] Blocked IP {ip} on port {port} using Windows Firewall.")


def should_block(packet_info):
    match = PACKET_REGEX.search(packet_info)
    if not match:
        print(f"[DEBUG] ❌ Failed to parse: {packet_info}")
        return False, None, None

    src_ip, src_port, dst_ip, dst_port = match.groups()
    src_port, dst_port = int(src_port), int(dst_port)

    if src_ip in BLOCKED_IPS or dst_ip in BLOCKED_IPS:
        return True, src_ip, src_port

    if src_port in BLOCKED_PORTS or dst_port in BLOCKED_PORTS:
        return True, src_ip, src_port

    return False, None, None

def start_logger():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    retries = 5
    while retries > 0:
        try:
            server_socket.bind(("127.0.0.1", 9090))
            server_socket.listen(1)
            print("🔥 Python Firewall Logger is running... Waiting for C client...")
            break
        except OSError as e:
            retries -= 1
            print(f"[ERROR] Failed to bind to port. Retrying... {e}")
            if retries == 0:
                print("[ERROR] Unable to start server after 5 attempts. Exiting.")
                sys.exit(1)
            time.sleep(2)

    conn = None
    try:
        conn, addr = server_socket.accept()
        print(f"🔗 Connected to C client: {addr}")
        conn.settimeout(10)

        with open(LOG_BLOCKED_FILE, "a") as blocked_log_file, open(LOG_ALLOWED_FILE, "a") as allowed_log_file:
            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        print("[INFO] C client disconnected.")
                        break

                    packet_info = data.decode("utf-8").strip()

                    if packet_info == "FIREWALL_SHUTDOWN":
                        print("[⚠️] Received shutdown signal from C firewall.")
                        break

                    should_block_flag, ip_to_block, port_to_block = should_block(packet_info)

                    if should_block_flag:
                        block_in_windows(ip_to_block, port_to_block)
                        status = "BLOCKED"
                        blocked_log_file.write(f"{status}: {packet_info}\n")
                    else:
                        status = "ALLOWED"
                        allowed_log_file.write(f"{status}: {packet_info}\n")

                    print(f"{status}: {packet_info}")
                    blocked_log_file.flush()
                    allowed_log_file.flush()

                except socket.timeout:
                    print("[WARNING] No data for 10 seconds. Waiting...")
                    continue
                except ConnectionResetError as e:
                    print(f"[ERROR] Connection was reset: {e}")
                    break
                except Exception as e:
                    print(f"[ERROR] Unexpected error: {e}")
                    break

    except KeyboardInterrupt:
        print("\n[INFO] Logger stopped by user.")
        try:
            if conn:
                conn.sendall(b"FIREWALL_SHUTDOWN")
        except Exception as e:
            print(f"[WARNING] Could not notify C client: {e}")

    finally:
        try:
            if conn:
                conn.close()
            server_socket.close()
        except Exception as e:
            print(f"[ERROR] Error closing connection: {e}")

        print("[INFO] Logger shut down.")


if __name__ == "__main__":
    start_logger()
