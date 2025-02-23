from scapy.all import *
import time
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# Configuration
THRESHOLD_MAC = 50  # Max MAC addresses per second to detect MAC flooding
THRESHOLD_ARP = 5    # Max ARP responses per second to detect ARP spoofing
THRESHOLD_DHCP = 10  # Max DHCP requests per second to detect DHCP starvation
LOG_FILE = "layer2_alerts.log"
INTERFACE = "Ethernet"  # Change to match your GNS3 network interface

# Data structures for tracking packets
mac_table = {}
arp_table = {}
dhcp_table = {}
stp_table = {}
monitoring = False

# Function to log alerts
def log_alert(message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    alert_msg = f"[{timestamp}] ALERT: {message}\n"
    with open(LOG_FILE, "a") as log_file:
        log_file.write(alert_msg)
    update_gui(alert_msg)

# Function to update GUI
def update_gui(message):
    alert_text.insert(tk.END, message, "alert")
    alert_text.yview(tk.END)
    status_label.config(text="Monitoring Active", bootstyle="success")
    progressbar.start()

# Function to detect MAC flooding
def detect_mac_flooding():
    current_time = time.time()
    mac_table_filtered = {mac: (count, timestamp) for mac, (count, timestamp) in mac_table.items() if current_time - timestamp < 1}
    if len(mac_table_filtered) > THRESHOLD_MAC:
        log_alert(f"MAC Flooding detected! Unique MACs: {len(mac_table_filtered)}")

# Function to detect ARP Spoofing
def detect_arp_spoofing(pkt):
    if ARP in pkt and pkt[ARP].op == 2:
        sender_ip = pkt[ARP].psrc
        sender_mac = pkt[ARP].hwsrc
        if sender_ip in arp_table and arp_table[sender_ip] != sender_mac:
            log_alert(f"ARP Spoofing detected! IP: {sender_ip} MAC: {sender_mac}")
        arp_table[sender_ip] = sender_mac

# Function to detect DHCP starvation
def detect_dhcp_starvation(pkt):
    if DHCP in pkt and pkt[DHCP].options[0][1] == 1:
        mac_address = pkt[Ether].src
        dhcp_table[mac_address] = dhcp_table.get(mac_address, 0) + 1
        if dhcp_table[mac_address] > THRESHOLD_DHCP:
            log_alert(f"DHCP Starvation detected! MAC: {mac_address}")

# Function to detect STP attacks
def detect_stp_attack(pkt):
    if pkt.haslayer(Dot3) and pkt.haslayer(LLC) and pkt.haslayer(STP):
        sender_mac = pkt.src
        stp_table[sender_mac] = stp_table.get(sender_mac, 0) + 1
        if stp_table[sender_mac] > 3:
            log_alert(f"STP Attack detected! Suspicious MAC: {sender_mac}")

# Packet Sniffing Function
def packet_handler(pkt):
    if not monitoring:
        return
    if Ether in pkt:
        mac_src = pkt[Ether].src
        count, timestamp = mac_table.get(mac_src, (0, time.time()))
        mac_table[mac_src] = (count + 1, time.time())
        detect_mac_flooding()
    if ARP in pkt:
        detect_arp_spoofing(pkt)
    if DHCP in pkt:
        detect_dhcp_starvation(pkt)
    if pkt.haslayer(Dot3) and pkt.haslayer(LLC) and pkt.haslayer(STP):
        detect_stp_attack(pkt)

# Start Sniffing
def start_monitoring():
    global monitoring
    monitoring = True
    log_alert("Monitoring started...")
    try:
        sniff(prn=packet_handler, store=0, iface=INTERFACE, stop_filter=lambda x: not monitoring)
    except Exception as e:
        log_alert(f"Error while sniffing: {e}")

# Stop Sniffing
def stop_monitoring():
    global monitoring
    monitoring = False
    log_alert("Monitoring stopped.")
    status_label.config(text="Monitoring Stopped", bootstyle="danger")
    progressbar.stop()

# Clear Log
def clear_log():
    alert_text.delete(1.0, tk.END)
    with open(LOG_FILE, "w") as log_file:
        log_file.write("")
    log_alert("Logs cleared.")

# GUI Setup
root = ttk.Window(themename="darkly")
root.title("Layer 2 Attack Monitor")
root.geometry("800x550")

frame = ttk.Frame(root, padding=10)
frame.pack(pady=10)

start_button = ttk.Button(frame, text="Start Monitoring", command=lambda: threading.Thread(target=start_monitoring).start(), bootstyle="success")
start_button.grid(row=0, column=0, padx=5)

stop_button = ttk.Button(frame, text="Stop Monitoring", command=stop_monitoring, bootstyle="danger")
stop_button.grid(row=0, column=1, padx=5)

clear_button = ttk.Button(frame, text="Clear Logs", command=clear_log, bootstyle="info")
clear_button.grid(row=0, column=2, padx=5)

status_label = ttk.Label(root, text="Monitoring Stopped", bootstyle="danger", font=("Arial", 12, "bold"))
status_label.pack(pady=5)

progressbar = ttk.Progressbar(root, mode='indeterminate', bootstyle="success")
progressbar.pack(fill=tk.X, padx=20, pady=5)

alert_text = scrolledtext.ScrolledText(root, width=90, height=20, font=("Courier", 10))
alert_text.pack()
alert_text.tag_config("alert", foreground="red")

root.mainloop()