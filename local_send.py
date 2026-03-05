import socket
import threading
import os
import hashlib
import time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# =========================
# CONFIG
# =========================
UDP_PORT = 50000
TCP_PORT = 50001
BUFFER_SIZE = 1024 * 1024  # 1MB
BROADCAST_INTERVAL = 3
SAVE_DIR = "received"

discovered_devices = {}
cancel_transfer = False

# =========================
# UTILS
# =========================
def sha256_file(path):
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(BUFFER_SIZE):
            sha.update(chunk)
    return sha.hexdigest()

# =========================
# DEVICE DISCOVERY
# =========================
def broadcast_presence():
    hostname = socket.gethostname()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            try:
                msg = f"LOCALSEND|{hostname}".encode()
                s.sendto(msg, ('<broadcast>', UDP_PORT))
            except:
                pass
            time.sleep(BROADCAST_INTERVAL)

def listen_for_devices():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('', UDP_PORT))
        while True:
            try:
                data, addr = s.recvfrom(1024)
                msg = data.decode()
                if msg.startswith("LOCALSEND|"):
                    hostname = msg.split("|")[1]
                    if addr[0] not in discovered_devices:
                        discovered_devices[addr[0]] = hostname
                        root.after(0, update_device_list)
            except:
                continue

def update_device_list():
    device_tree.delete(*device_tree.get_children())
    for ip, name in discovered_devices.items():
        device_tree.insert("", tk.END, values=(name, ip))

# =========================
# SENDER
# =========================
def send_path(ip, selected_path):
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
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFFER_SIZE)
            s.connect((ip, TCP_PORT))

            for file_path in files:
                if cancel_transfer:
                    break

                relative_path = os.path.relpath(file_path, base_path)
                size = file_path.stat().st_size
                checksum = sha256_file(file_path)

                metadata = f"{relative_path}|{size}|{checksum}\n".encode()
                s.sendall(metadata)

                sent = 0
                start_time = time.time()

                with open(file_path, "rb") as f:
                    while chunk := f.read(BUFFER_SIZE):
                        if cancel_transfer:
                            break
                        s.sendall(chunk)
                        sent += len(chunk)
                        update_progress(sent, size, start_time)

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

# =========================
# RECEIVER
# =========================
def tcp_receiver():
    os.makedirs(SAVE_DIR, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', TCP_PORT))
        s.listen(5)

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

def recv_line(conn):
    buffer = b""
    while True:
        char = conn.recv(1)
        if not char:
            return None
        if char == b"\n":
            break
        buffer += char
    return buffer.decode()


def handle_client(conn):
    with conn:
        while True:
            meta = recv_line(conn)
            if not meta:
                return

            if meta == "__DONE__":
                return

            filename, filesize, checksum = meta.split("|")
            filesize = int(filesize)

            filepath = Path(SAVE_DIR) / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)

            received = 0

            with open(filepath, "wb") as f:
                while received < filesize:
                    chunk = conn.recv(min(BUFFER_SIZE, filesize - received))
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)

            if sha256_file(filepath) != checksum:
                print(f"Integrity failed for {filename}")
            else:
                print(f"Received: {filename}")

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

    threading.Thread(target=send_path, args=(ip, path), daemon=True).start()

def cancel():
    global cancel_transfer
    cancel_transfer = True

# =========================
# DARK UI
# =========================
root = tk.Tk()
root.title("Turbo LocalSend Pro")
root.geometry("650x500")
root.configure(bg="#1e1e1e")

style = ttk.Style()
style.theme_use("clam")

style.configure("Treeview",
                background="#2c2c2c",
                foreground="white",
                fieldbackground="#2c2c2c")

frame_top = tk.Frame(root, bg="#1e1e1e")
frame_top.pack(pady=10, padx=10, fill=tk.X)

path_entry = tk.Entry(frame_top, bg="#2c2c2c", fg="white")
path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

tk.Button(frame_top, text="Browse", command=select_path,
          bg="#3498db", fg="white").pack(side=tk.LEFT)

device_tree = ttk.Treeview(root, columns=("Name", "IP"), show="headings")
device_tree.heading("Name", text="Device Name")
device_tree.heading("IP", text="IP Address")
device_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

progress = ttk.Progressbar(root, mode='determinate')
progress.pack(fill=tk.X, padx=10)

speed_label = tk.Label(root, text="0 MB/s", bg="#1e1e1e", fg="white")
speed_label.pack()

btn_frame = tk.Frame(root, bg="#1e1e1e")
btn_frame.pack(pady=15)

tk.Button(btn_frame, text="🚀 SEND", command=start_transfer,
          bg="#2ecc71", fg="white", width=15).pack(side=tk.LEFT, padx=10)

tk.Button(btn_frame, text="❌ CANCEL", command=cancel,
          bg="#e74c3c", fg="white", width=15).pack(side=tk.LEFT)

# =========================
# THREADS
# =========================
threading.Thread(target=broadcast_presence, daemon=True).start()
threading.Thread(target=listen_for_devices, daemon=True).start()
threading.Thread(target=tcp_receiver, daemon=True).start()

root.mainloop()
