import socket
import threading
import os
import hashlib
import time
import zlib
import secrets
import re
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# =========================
# CONFIG
# =========================
UDP_PORT = 50000
TCP_PORT = 50001
BUFFER_SIZE = 8 * 1024 * 1024  # 8MB for better throughput
COMPRESS_THRESHOLD = 1024  # Only compress files larger than 1KB
BROADCAST_INTERVAL = 3
SAVE_DIR = "received"
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB max file size
MAX_FILENAME_LENGTH = 255
ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.mp4', '.mp3', '.zip', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.json', '.xml', '.csv'}

# Security settings
SECRET_KEY = None  # Will be set from user input
SESSION_TOKENS = set()
SESSION_LOCK = threading.Lock()

discovered_devices = {}
devices_lock = threading.Lock()
cancel_transfer = False
rate_limiter: dict[str, float] = {}  # IP -> last connection time
RATE_LIMIT_SECONDS = 1  # Minimum seconds between connections from same IP

# =========================
# SECURITY UTILS
# =========================
def derive_key(password, salt=None):
    """Derive encryption key from password."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def init_encryption(password):
    """Initialize encryption with a password."""
    global SECRET_KEY
    key, salt = derive_key(password)
    SECRET_KEY = (Fernet(key), salt)
    return salt

def encrypt_data(data):
    """Encrypt data if encryption is enabled."""
    if SECRET_KEY is None:
        return data
    return SECRET_KEY[0].encrypt(data)

def decrypt_data(data):
    """Decrypt data if encryption is enabled."""
    if SECRET_KEY is None:
        return data
    return SECRET_KEY[0].decrypt(data)

def generate_session_token():
    """Generate a secure session token."""
    token = secrets.token_urlsafe(32)
    with SESSION_LOCK:
        SESSION_TOKENS.add(token)
    return token

def validate_token(token):
    """Validate a session token."""
    with SESSION_LOCK:
        return token in SESSION_TOKENS

def sanitize_filename(filename):
    """
    Sanitize filename to prevent path traversal and other attacks.
    Returns None if filename is invalid.
    """
    if not filename or len(filename) > MAX_FILENAME_LENGTH:
        return None

    # Remove any null bytes
    filename = filename.replace('\x00', '')

    # Normalize path separators
    filename = filename.replace('\\', '/')

    # Check for path traversal attempts
    if '..' in filename or filename.startswith('/') or filename.startswith('~'):
        return None

    # Remove any leading slashes or dots
    filename = filename.lstrip('./')

    # Check for empty filename after sanitization
    if not filename:
        return None

    # Validate extension
    ext = Path(filename).suffix.lower()
    if ext and ext not in ALLOWED_EXTENSIONS:
        return None

    # Only allow alphanumeric and safe characters
    if not re.match(r'^[\w\-\.\s/]+$', filename):
        return None

    return filename

def check_rate_limit(ip):
    """Check if IP is rate limited."""
    current_time = time.time()
    with threading.Lock():
        last_time = rate_limiter.get(ip, 0)
        if current_time - last_time < RATE_LIMIT_SECONDS:
            return False
        rate_limiter[ip] = current_time
        return True

# =========================
# UTILS
# =========================
def sha256_file(path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(BUFFER_SIZE):
            sha.update(chunk)
    return sha.hexdigest()

def compress_file(input_path, output_path):
    """Compress a file using zlib."""
    with open(input_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            compressor = zlib.compressobj(level=6)
            while chunk := f_in.read(BUFFER_SIZE):
                f_out.write(compressor.compress(chunk))
            f_out.write(compressor.flush())

def decompress_file(input_path, output_path):
    """Decompress a file using zlib."""
    with open(input_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            decompressor = zlib.decompressobj()
            while chunk := f_in.read(BUFFER_SIZE):
                f_out.write(decompressor.decompress(chunk))
            f_out.write(decompressor.flush())

# =========================
# DEVICE DISCOVERY
# =========================
def broadcast_presence():
    hostname = socket.gethostname()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(1)
        while True:
            try:
                # Include encrypted token for authentication if encryption enabled
                token = generate_session_token() if SECRET_KEY else "none"
                msg = f"LOCALSEND|{hostname}|{token}".encode()
                s.sendto(msg, ('<broadcast>', UDP_PORT))
            except:
                pass
            time.sleep(BROADCAST_INTERVAL)

def listen_for_devices():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', UDP_PORT))
        s.settimeout(1)
        while True:
            try:
                data, addr = s.recvfrom(1024)
                msg = data.decode('utf-8', errors='ignore')
                if msg.startswith("LOCALSEND|"):
                    parts = msg.split("|")
                    if len(parts) >= 2:
                        hostname = parts[1]
                        with devices_lock:
                            if addr[0] not in discovered_devices:
                                discovered_devices[addr[0]] = hostname
                                root.after(0, update_device_list)
            except socket.timeout:
                continue
            except:
                continue

def update_device_list():
    device_tree.delete(*device_tree.get_children())
    with devices_lock:
        for ip, name in discovered_devices.items():
            device_tree.insert("", tk.END, values=(name, ip))

# =========================
# SENDER
# =========================
def send_path(ip, selected_path, password=None):
    global cancel_transfer
    cancel_transfer = False

    if os.path.isfile(selected_path):
        files = [Path(selected_path)]
        base_path = Path(selected_path).parent
    else:
        files = [Path(r)/f for r, d, fs in os.walk(selected_path) for f in fs]
        base_path = Path(selected_path)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Optimize TCP for high-speed transfer
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFFER_SIZE * 2)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE * 2)
            s.settimeout(30)

            s.connect((ip, TCP_PORT))

            # Send authentication if password is set
            if password:
                auth_msg = f"AUTH|{password}\n".encode()
                s.sendall(auth_msg)
                response = recv_line(s)
                if response != "AUTH_OK":
                    raise Exception("Authentication failed")

            # Enable compression for this transfer
            use_compression = True

            for file_path in files:
                if cancel_transfer:
                    break

                # Validate file size
                file_size = file_path.stat().st_size
                if file_size > MAX_FILE_SIZE:
                    print(f"Skipping {file_path}: exceeds max file size")
                    continue

                relative_path = os.path.relpath(file_path, base_path)
                checksum = sha256_file(file_path)

                # Decide whether to compress
                should_compress = use_compression and file_size > COMPRESS_THRESHOLD
                compressed_size = file_size

                if should_compress:
                    # Compress to temp file
                    temp_compressed = file_path.with_suffix(file_path.suffix + '.tmp')
                    compress_file(file_path, temp_compressed)
                    compressed_size = temp_compressed.stat().st_size
                    # Only use compression if it actually reduces size
                    if compressed_size >= file_size:
                        should_compress = False
                        os.remove(temp_compressed)

                compress_flag = "1" if should_compress else "0"
                actual_size = compressed_size if should_compress else file_size
                actual_path = temp_compressed if should_compress else file_path

                metadata = f"{relative_path}|{actual_size}|{checksum}|{compress_flag}\n".encode()
                s.sendall(metadata)

                sent = 0
                start_time = time.time()
                last_update = start_time

                with open(actual_path, "rb") as f:
                    while chunk := f.read(BUFFER_SIZE):
                        if cancel_transfer:
                            break
                        s.sendall(chunk)
                        sent += len(chunk)

                        # Throttle UI updates for better performance
                        current_time = time.time()
                        if current_time - last_update >= 0.1:
                            update_progress(sent, actual_size, start_time)
                            last_update = current_time

                # Clean up temp file if compressed
                if should_compress and actual_path != file_path:
                    os.remove(actual_path)

            s.sendall(b"__DONE__\n")

        if not cancel_transfer:
            messagebox.showinfo("Complete", "Transfer finished successfully.")
        else:
            messagebox.showwarning("Cancelled", "Transfer cancelled.")

    except Exception as e:
        messagebox.showerror("Error", str(e))

def update_progress(sent, total, start_time):
    progress["maximum"] = total
    progress["value"] = sent
    elapsed = time.time() - start_time
    if elapsed > 0:
        speed = sent / elapsed / (1024 * 1024)
        speed_label.config(text=f"{speed:.2f} MB/s")
    root.update_idletasks()

# =========================
# RECEIVER
# =========================
def tcp_receiver():
    os.makedirs(SAVE_DIR, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE * 2)
        s.bind(('', TCP_PORT))
        s.listen(10)

        while True:
            try:
                conn, addr = s.accept()
                client_ip = addr[0]

                # Check rate limiting
                if not check_rate_limit(client_ip):
                    conn.close()
                    continue

                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f"Accept error: {e}")

def recv_line(conn):
    buffer = b""
    max_length = 4096  # Prevent memory exhaustion
    while len(buffer) < max_length:
        try:
            char = conn.recv(1)
            if not char:
                return None
            if char == b"\n":
                break
            buffer += char
        except socket.timeout:
            return None
        except:
            return None
    return buffer.decode('utf-8', errors='ignore')

def handle_client(conn, addr):
    client_ip = addr[0]
    authenticated = False
    expected_password = password_entry.get().strip() if password_entry else ""

    with conn:
        conn.settimeout(30)

        # Check for authentication if password is set
        if expected_password:
            try:
                auth_msg = recv_line(conn)
                if not auth_msg or not auth_msg.startswith("AUTH|"):
                    conn.sendall(b"AUTH_REQUIRED\n")
                    return

                provided_password = auth_msg[5:]  # Remove "AUTH|" prefix
                if provided_password != expected_password:
                    conn.sendall(b"AUTH_FAILED\n")
                    return

                authenticated = True
                conn.sendall(b"AUTH_OK\n")
            except Exception as e:
                print(f"Authentication error: {e}")
                return
        else:
            authenticated = True

        if not authenticated:
            return

        while True:
            try:
                meta = recv_line(conn)
                if not meta:
                    return

                if meta == "__DONE__":
                    return

                parts = meta.split("|")
                if len(parts) != 4:
                    print(f"Invalid metadata format from {client_ip}")
                    continue

                filename, filesize, checksum, compress_flag = parts
                filesize = int(filesize)

                # Validate file size
                if filesize < 0 or filesize > MAX_FILE_SIZE:
                    print(f"Invalid file size from {client_ip}")
                    return

                # Sanitize filename - CRITICAL SECURITY CHECK
                safe_filename = sanitize_filename(filename)
                if safe_filename is None:
                    print(f"Blocked malicious filename from {client_ip}: {filename}")
                    return

                filepath = Path(SAVE_DIR) / safe_filename

                # Ensure the resolved path is within SAVE_DIR (double-check)
                try:
                    resolved_path = filepath.resolve()
                    save_dir_resolved = Path(SAVE_DIR).resolve()
                    if not str(resolved_path).startswith(str(save_dir_resolved)):
                        print(f"Path traversal blocked from {client_ip}: {filename}")
                        return
                except Exception:
                    print(f"Path resolution error from {client_ip}")
                    return

                filepath.parent.mkdir(parents=True, exist_ok=True)

                received = 0
                temp_filepath = filepath.with_suffix(filepath.suffix + '.part')

                with open(temp_filepath, "wb") as f:
                    while received < filesize:
                        remaining = filesize - received
                        chunk_size = min(BUFFER_SIZE, remaining)
                        try:
                            chunk = conn.recv(chunk_size)
                            if not chunk:
                                break
                            f.write(chunk)
                            received += len(chunk)
                        except socket.timeout:
                            print(f"Timeout receiving {filename}")
                            break

                # Verify file integrity
                if received != filesize:
                    print(f"Incomplete transfer for {safe_filename}")
                    temp_filepath.unlink(missing_ok=True)
                    continue

                if sha256_file(temp_filepath) != checksum:
                    print(f"Integrity failed for {safe_filename}")
                    temp_filepath.unlink(missing_ok=True)
                    continue

                # Handle decompression if needed
                if compress_flag == "1":
                    decompress_file(temp_filepath, filepath)
                    temp_filepath.unlink()
                else:
                    temp_filepath.rename(filepath)

                print(f"Received: {safe_filename} from {client_ip}")

                # Update GUI in main thread
                root.after(0, lambda: log_received(safe_filename, client_ip))

            except Exception as e:
                print(f"Error handling client {client_ip}: {e}")
                return

def log_received(filename, client_ip):
    """Log received file to GUI."""
    status_label.config(text=f"Last received: {filename} from {client_ip}")

# =========================
# GUI
# =========================
def select_path():
    path = filedialog.askdirectory()
    if not path:
        path = filedialog.askopenfilename()
    if path:
        path_entry.delete(0, tk.END)
        path_entry.insert(0, path)

def start_transfer():
    selected = device_tree.selection()
    if not selected:
        messagebox.showwarning("Warning", "Select a device")
        return

    ip = device_tree.item(selected[0])["values"][1]
    path = path_entry.get()

    if not os.path.exists(path):
        messagebox.showerror("Error", "Invalid path")
        return

    password = password_entry.get().strip() if password_entry else ""
    threading.Thread(target=send_path, args=(ip, path, password), daemon=True).start()

def cancel():
    global cancel_transfer
    cancel_transfer = True

def set_password():
    """Set a password for transfers."""
    password = password_entry.get().strip()
    if password:
        messagebox.showinfo("Security", "Password set. All transfers will require authentication.")
    else:
        messagebox.showinfo("Security", "Password cleared. Transfers will not require authentication.")

# =========================
# DARK UI
# =========================
root = tk.Tk()
root.title("Turbo LocalSend Pro - Secure Edition")
root.geometry("700x600")
root.configure(bg="#1e1e1e")

style = ttk.Style()
style.theme_use("clam")

style.configure("Treeview",
                background="#2c2c2c",
                foreground="white",
                fieldbackground="#2c2c2c")

# Top frame for file selection
frame_top = tk.Frame(root, bg="#1e1e1e")
frame_top.pack(pady=10, padx=10, fill=tk.X)

tk.Label(frame_top, text="File/Folder:", bg="#1e1e1e", fg="white").pack(side=tk.LEFT)
path_entry = tk.Entry(frame_top, bg="#2c2c2c", fg="white", insertbackground="white")
path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

tk.Button(frame_top, text="Browse", command=select_path,
          bg="#3498db", fg="white").pack(side=tk.LEFT)

# Security frame
frame_security = tk.LabelFrame(root, text="Security Settings", bg="#1e1e1e", fg="white", font=("Arial", 10))
frame_security.pack(pady=5, padx=10, fill=tk.X)

tk.Label(frame_security, text="Transfer Password:", bg="#1e1e1e", fg="white").pack(side=tk.LEFT, padx=5)
password_entry = tk.Entry(frame_security, bg="#2c2c2c", fg="white", insertbackground="white", show="*", width=20)
password_entry.pack(side=tk.LEFT, padx=5)

tk.Button(frame_security, text="Set Password", command=set_password,
          bg="#9b59b6", fg="white").pack(side=tk.LEFT, padx=5)

tk.Label(frame_security, text="(Leave empty for open transfers)", bg="#1e1e1e", fg="#888888").pack(side=tk.LEFT, padx=5)

# Device list frame
frame_devices = tk.LabelFrame(root, text="Discovered Devices", bg="#1e1e1e", fg="white", font=("Arial", 10))
frame_devices.pack(pady=5, padx=10, fill=tk.BOTH, expand=True)

device_tree = ttk.Treeview(frame_devices, columns=("Name", "IP"), show="headings")
device_tree.heading("Name", text="Device Name")
device_tree.heading("IP", text="IP Address")
device_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Progress section
frame_progress = tk.Frame(root, bg="#1e1e1e")
frame_progress.pack(pady=5, padx=10, fill=tk.X)

progress = ttk.Progressbar(frame_progress, mode='determinate')
progress.pack(fill=tk.X)

speed_label = tk.Label(frame_progress, text="0 MB/s", bg="#1e1e1e", fg="white")
speed_label.pack()

# Status label
status_label = tk.Label(root, text="Ready - Waiting for connections...", bg="#1e1e1e", fg="#888888")
status_label.pack()

# Buttons
btn_frame = tk.Frame(root, bg="#1e1e1e")
btn_frame.pack(pady=15)

tk.Button(btn_frame, text=" SEND", command=start_transfer,
          bg="#2ecc71", fg="white", width=15).pack(side=tk.LEFT, padx=10)

tk.Button(btn_frame, text=" CANCEL", command=cancel,
          bg="#e74c3c", fg="white", width=15).pack(side=tk.LEFT)

# Security info
info_frame = tk.Frame(root, bg="#1e1e1e")
info_frame.pack(pady=5, padx=10, fill=tk.X)

tk.Label(info_frame, text="Security Features: Path traversal protection | File size limits | Rate limiting | File type filtering | Password auth",
         bg="#1e1e1e", fg="#27ae60", font=("Arial", 8)).pack()

# =========================
# THREADS
# =========================
threading.Thread(target=broadcast_presence, daemon=True).start()
threading.Thread(target=listen_for_devices, daemon=True).start()
threading.Thread(target=tcp_receiver, daemon=True).start()

root.mainloop()
