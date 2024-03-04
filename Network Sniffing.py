import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from scapy.all import sniff, IP, TCP, UDP
import threading

# Global variable to control the state of packet capturing
capturing_paused = False

# Global variable to store the filter value
filter_value = ""

# Packet handler function to analyze and display packet information
def packet_handler(packet):
    global capturing_paused
    global filter_value
    
    if capturing_paused:
        return
    
    # Check if filter is applied
    if not filter_value:
        # If filter is not applied, display all packets
        display_packet(packet)
    else:
        # If filter is applied, check if packet matches filter criteria
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = "TCP"
                data = packet[TCP].payload
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = "UDP"
                data = packet[UDP].payload
            else:
                src_port = None
                dst_port = None
                protocol = "Unknown"
                data = None

            # Check if the packet matches the filter
            if (filter_value.upper() in (src_ip, dst_ip, str(src_port), str(dst_port), protocol)):
                # If packet matches the filter, display it
                display_packet(packet)

# Function to display packet information
def display_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
            data = packet[TCP].payload
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
            data = packet[UDP].payload
        else:
            src_port = None
            dst_port = None
            protocol = "Unknown"
            data = None

        info = f"Source: {src_ip}:{src_port} | Destination: {dst_ip}:{dst_port} | Protocol: {protocol}"
        if data:
            info += f"\nData: {data}"
        
        # Schedule GUI update within the main thread
        root.after(0, lambda: text_area.insert(tk.END, info + "\n"))
        root.after(0, text_area.see, tk.END)  # Scroll to the bottom

# Sniff packets on the network in a separate thread
def start_sniffing():
    global capturing_paused
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)
    capturing_paused = False
    threading.Thread(target=sniff, kwargs={"prn": packet_handler, "store": 0}).start()

# Function to pause packet capturing
def pause_sniffing():
    global capturing_paused
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    capturing_paused = True

# Function to apply filter and display matching packets
def apply_filter():
    global filter_value
    filter_value = filter_entry.get()
    text_area.delete(1.0, tk.END)  # Clear previous packets

# Create the main window
root = tk.Tk()
root.title("Network Monitor")

# Create a text area to display network activities
text_area = ScrolledText(root, width=80, height=30)
text_area.pack(expand=True, fill=tk.BOTH)

# Create a filter entry
filter_label = tk.Label(root, text="Filter:")
filter_label.pack(side=tk.LEFT, padx=5, pady=5)

filter_entry = tk.Entry(root, width=20)
filter_entry.pack(side=tk.LEFT, padx=5, pady=5)

# Create a button to apply the filter
apply_button = tk.Button(root, text="Apply Filter", command=apply_filter)
apply_button.pack(side=tk.LEFT, padx=5, pady=5)

# Create buttons to start and stop sniffing
start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack(side=tk.BOTTOM, padx=5, pady=5)

stop_button = tk.Button(root, text="Pause Sniffing", command=pause_sniffing, state=tk.DISABLED)
stop_button.pack(side=tk.BOTTOM, padx=5, pady=5)

# Run the Tkinter event loop
root.mainloop()

