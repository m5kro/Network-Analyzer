import psutil
from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, Raw, wrpcap
from collections import Counter
import tkinter as tk
from tkinter import ttk
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Global variables to store packet counts, threading, and saving options
protocol_counts = Counter()
total_packets = 0
lock = threading.Lock()
sniffing_thread = None
save_to_pcap = False
pcap_path = ""

# Predefined colors for each protocol
protocol_colors = {
    "ARP": "#FF9999", "DNS": "#66B2FF", "HTTP": "#99FF99", "HTTPS": "#FFCC99",
    "FTP": "#FF6666", "Telnet": "#6699FF", "SSH": "#99CC99", "SMB": "#FF9933",
    "BitTorrent": "#FF66B2", "ICMP": "#66FFB2", "TCP": "#CC99FF", "UDP": "#FF99CC", "Other": "#CCCCCC"
}

def list_interfaces():
    interfaces = psutil.net_if_addrs()
    return list(interfaces.keys())

def check_packet_identifier(packet, identifiers):
    try:
        if Raw in packet:
            payload = packet[Raw].load
            for identifier in identifiers:
                if identifier in payload:
                    return True
    except Exception:
        pass
    return False

def is_bittorrent_packet(packet):
    return check_packet_identifier(packet, [b"BitTorrent protocol", b"announce", b"info_hash"])

def is_http_packet(packet):
    return check_packet_identifier(packet, [b"GET", b"POST", b"HTTP/1.1", b"Host:"])

def is_https_packet(packet):
    return check_packet_identifier(packet, [b"\x16\x03\x01", b"\x16\x03\x03"])

def is_ftp_packet(packet):
    return check_packet_identifier(packet, [b"220 ", b"USER ", b"PASS ", b"RETR ", b"STOR "])

def is_ssh_packet(packet):
    return check_packet_identifier(packet, [b"SSH-"])

def analyze_packet(packet):
    if ARP in packet:
        return "ARP"
    elif DNS in packet:
        return "DNS"
    elif IP in packet:
        ip_packet = packet[IP]
        
        if is_bittorrent_packet(packet):
            return "BitTorrent"
        elif is_http_packet(packet):
            return "HTTP"
        elif is_https_packet(packet):
            return "HTTPS"
        elif is_ftp_packet(packet):
            return "FTP"
        elif is_ssh_packet(packet):
            return "SSH"
        
        if TCP in ip_packet or UDP in ip_packet:
            sport = ip_packet[TCP].sport if TCP in ip_packet else ip_packet[UDP].sport
            dport = ip_packet[TCP].dport if TCP in ip_packet else ip_packet[UDP].dport
            
            if sport == 80 or dport == 80:
                return "HTTP"
            elif sport == 443 or dport == 443:
                return "HTTPS"
            elif sport == 22 or dport == 22:
                return "SSH"
            elif sport == 21 or dport == 21:
                return "FTP"
            elif sport == 23 or dport == 23:
                return "Telnet"
            elif sport == 445 or dport == 445:
                return "SMB"
            elif sport == 6881 or dport == 6881:
                return "BitTorrent"
            else:
                if TCP in ip_packet:
                    return "TCP"
                elif UDP in ip_packet:
                    return "UDP"
        
        elif ip_packet.proto == 1:
            return "ICMP"
    
    return "Other"

def packet_callback(packet):
    global total_packets
    protocol = analyze_packet(packet)
    with lock:
        protocol_counts[protocol] += 1
        total_packets += 1
        # Save packet to PCAP if enabled
        if save_to_pcap and pcap_path:
            wrpcap(pcap_path, [packet], append=True)

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=False)

def update_ui():
    with lock:
        data = [protocol_counts.get(protocol, 0) / total_packets * 100 if total_packets > 0 else 0 
                for protocol in protocol_counts.keys()]
        for protocol, percentage in zip(protocol_counts.keys(), data):
            protocol_var[protocol].set(f"{percentage:.2f}%")
        update_graph(data)
    root.after(1000, update_ui)

def update_graph(data):
    ax.clear()
    ax.pie(
        data, 
        labels=protocol_counts.keys(), 
        autopct="%1.1f%%", 
        startangle=140,
        colors=[protocol_colors.get(protocol, "#CCCCCC") for protocol in protocol_counts.keys()],
        textprops={'fontsize': 12}  # Set font size for graph text to 12
    )
    canvas.draw()

def start_sniffing_thread(interface):
    global sniffing_thread
    sniffing_thread = threading.Thread(target=start_sniffing, args=(interface,), daemon=True)
    sniffing_thread.start()

def on_done_button_click():
    selected_interface = interface_var.get()
    if selected_interface:
        global save_to_pcap, pcap_path
        save_to_pcap = save_to_pcap_var.get()
        pcap_path = pcap_path_var.get()
        
        # Close the selection window and start the main UI
        interface_selection_window.destroy()
        start_sniffing_thread(selected_interface)
        root.deiconify()  # Show the main window

def on_interface_selection_window_close():
    #Kill the process if the interface selection window is closed without pressing 'Done'
    root.quit()
    root.destroy()

# Initialize the main analysis window but hide it initially
root = tk.Tk()
root.title("Network Traffic Analyzer")
root.protocol("WM_DELETE_WINDOW", root.quit)  # Ensures the window close event kills the process
root.withdraw()  # Hide main window until an interface is selected

# UI Components for Main Window
protocol_var = {}
for protocol in ["ARP", "DNS", "HTTP", "HTTPS", "FTP", "Telnet", "SSH", "SMB", "BitTorrent", "ICMP", "TCP", "UDP", "Other"]:
    frame = ttk.Frame(root)
    frame.pack(fill="x", padx=5, pady=5)

    label = ttk.Label(frame, text=protocol, width=15, font=("Arial", 20))
    label.pack(side="left")

    protocol_var[protocol] = tk.StringVar(value="0.00%")
    value_label = ttk.Label(frame, textvariable=protocol_var[protocol], font=("Arial", 20, "bold"))
    value_label.pack(side="right")

# Initialize Matplotlib Figure for Main Window
fig, ax = plt.subplots(figsize=(5, 5))
canvas = FigureCanvasTkAgg(fig, master=root)
canvas.get_tk_widget().pack(pady=10)

# Start UI update loop
root.after(1000, update_ui)

# Interface Selection Window
interface_selection_window = tk.Toplevel()
interface_selection_window.title("Select Network Interface")
interface_selection_window.protocol("WM_DELETE_WINDOW", on_interface_selection_window_close)  # Ensure process termination if window closed

interface_label = ttk.Label(interface_selection_window, text="Choose a network interface:", font=("Arial", 20))
interface_label.pack(pady=10)

interfaces = list_interfaces()
interface_var = tk.StringVar()

# Interface Dropdown
interface_dropdown = ttk.Combobox(interface_selection_window, textvariable=interface_var, values=interfaces, state="readonly", font=("Arial", 20))
interface_dropdown.pack(pady=10)

# Save to PCAP Checkbox
save_to_pcap_var = tk.BooleanVar()
save_checkbox = tk.Checkbutton(interface_selection_window, text="Save to PCAP", variable=save_to_pcap_var, font=("Arial", 20))
save_checkbox.pack(pady=10)

# PCAP Path Entry
pcap_path_var = tk.StringVar()
pcap_path_label = ttk.Label(interface_selection_window, text="PCAP Path:", font=("Arial", 20))
pcap_path_label.pack(pady=(10, 0))
pcap_path_entry = ttk.Entry(interface_selection_window, textvariable=pcap_path_var, font=("Arial", 20), width=30)
pcap_path_entry.pack(pady=(0, 10))

# Done Button with Font Size 20
done_button = tk.Button(interface_selection_window, text="Done", command=on_done_button_click, font=("Arial", 20))
done_button.pack(pady=10)

# Enable "Done" button only when an interface is selected
def on_dropdown_select(event):
    if interface_var.get():
        done_button.config(state="normal")
    else:
        done_button.config(state="disabled")

interface_dropdown.bind("<<ComboboxSelected>>", on_dropdown_select)
done_button.config(state="disabled")  # Initially disabled

# Start the Tkinter main loop
root.mainloop()
