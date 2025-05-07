import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import time
import random
from scapy.all import IP, TCP, UDP, Ether, send, sr1, ICMP
import dns.resolver
import subprocess
import platform

class NetworkStressTool:
    def __init__(self, master):
        self.master = master
        master.title("Network Stress Testing Tool")

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")

        self.create_tcp_flood_tab()
        self.create_udp_flood_tab()
        self.create_packet_gen_tab()
        self.create_ping_tab()
        self.create_dns_lookup_tab()
        self.create_traceroute_tab()

    def create_tcp_flood_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="TCP Flood")

        ttk.Label(tab, text="Target IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.tcp_target_ip_entry = ttk.Entry(tab)
        self.tcp_target_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(tab, text="Target Port:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.tcp_target_port_entry = ttk.Entry(tab)
        self.tcp_target_port_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.tcp_target_port_entry.insert(0, "80")  # Default HTTP port

        ttk.Label(tab, text="Number of Packets/Connections:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.tcp_num_packets_entry = ttk.Entry(tab)
        self.tcp_num_packets_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.tcp_num_packets_entry.insert(0, "1000")

        self.tcp_flood_button = ttk.Button(tab, text="Start TCP Flood", command=self.start_tcp_flood)
        self.tcp_flood_button.grid(row=3, column=0, columnspan=2, pady=10)

        self.tcp_flood_status = tk.Text(tab, height=5, state=tk.DISABLED)
        self.tcp_flood_status.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        tab.grid_columnconfigure(1, weight=1)

    def start_tcp_flood(self):
        target_ip = self.tcp_target_ip_entry.get()
        try:
            target_port = int(self.tcp_target_port_entry.get())
            num_packets = int(self.tcp_num_packets_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid input for port or number of packets.")
            return

        threading.Thread(target=self._tcp_flood, args=(target_ip, target_port, num_packets)).start()
        self._update_status(self.tcp_flood_status, f"Starting TCP flood against {target_ip}:{target_port} with {num_packets} packets...\n")

    def _tcp_flood(self, target_ip, target_port, num_packets):
        try:
            for _ in range(num_packets):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.connect((target_ip, target_port))
                    self._update_status(self.tcp_flood_status, f"TCP connection established with {target_ip}:{target_port}\n")
                    # Send some dummy data if needed
                    # s.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                except ConnectionRefusedError:
                    self._update_status(self.tcp_flood_status, f"Connection refused by {target_ip}:{target_port}\n")
                except TimeoutError:
                    self._update_status(self.tcp_flood_status, f"Connection to {target_ip}:{target_port} timed out\n")
                finally:
                    s.close()
                time.sleep(0.01)  # Small delay to avoid overwhelming the local machine
            self._update_status(self.tcp_flood_status, f"TCP flood against {target_ip}:{target_port} completed.\n")
        except Exception as e:
            self._update_status(self.tcp_flood_status, f"An error occurred during TCP flood: {e}\n")

    def create_udp_flood_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="UDP Flood")

        ttk.Label(tab, text="Target IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.udp_target_ip_entry = ttk.Entry(tab)
        self.udp_target_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(tab, text="Target Port:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.udp_target_port_entry = ttk.Entry(tab)
        self.udp_target_port_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.udp_target_port_entry.insert(0, "53")  # Default DNS port

        ttk.Label(tab, text="Number of Packets:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.udp_num_packets_entry = ttk.Entry(tab)
        self.udp_num_packets_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.udp_num_packets_entry.insert(0, "1000")

        ttk.Label(tab, text="Packet Size (bytes):").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.udp_packet_size_entry = ttk.Entry(tab)
        self.udp_packet_size_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        self.udp_packet_size_entry.insert(0, "64")

        self.udp_flood_button = ttk.Button(tab, text="Start UDP Flood", command=self.start_udp_flood)
        self.udp_flood_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.udp_flood_status = tk.Text(tab, height=5, state=tk.DISABLED)
        self.udp_flood_status.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        tab.grid_columnconfigure(1, weight=1)

    def start_udp_flood(self):
        target_ip = self.udp_target_ip_entry.get()
        try:
            target_port = int(self.udp_target_port_entry.get())
            num_packets = int(self.udp_num_packets_entry.get())
            packet_size = int(self.udp_packet_size_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid input for port, number of packets, or packet size.")
            return

        threading.Thread(target=self._udp_flood, args=(target_ip, target_port, num_packets, packet_size)).start()
        self._update_status(self.udp_flood_status, f"Starting UDP flood against {target_ip}:{target_port} with {num_packets} packets of size {packet_size} bytes...\n")

    def _udp_flood(self, target_ip, target_port, num_packets, packet_size):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = random._urandom(packet_size)
            for _ in range(num_packets):
                sock.sendto(data, (target_ip, target_port))
                self._update_status(self.udp_flood_status, f"Sent UDP packet to {target_ip}:{target_port}\n")
                time.sleep(0.01)
            sock.close()
            self._update_status(self.udp_flood_status, f"UDP flood against {target_ip}:{target_port} completed.\n")
        except Exception as e:
            self._update_status(self.udp_flood_status, f"An error occurred during UDP flood: {e}\n")

    def create_packet_gen_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Packet Generation")

        ttk.Label(tab, text="Target IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.pktgen_target_ip_entry = ttk.Entry(tab)
        self.pktgen_target_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        ttk.Label(tab, text="Target Port:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.pktgen_target_port_entry = ttk.Entry(tab)
        self.pktgen_target_port_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.pktgen_target_port_entry.insert(0, "12345")

        ttk.Label(tab, text="Protocol (TCP/UDP/ICMP):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.pktgen_protocol_combo = ttk.Combobox(tab, values=["TCP", "UDP", "ICMP"])
        self.pktgen_protocol_combo.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.pktgen_protocol_combo.set("TCP")

        ttk.Label(tab, text="Number of Packets:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.pktgen_num_packets_entry = ttk.Entry(tab)
        self.pktgen_num_packets_entry.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
        self.pktgen_num_packets_entry.insert(0, "10")

        self.pktgen_button = ttk.Button(tab, text="Generate and Send Packets", command=self.start_packet_generation)
        self.pktgen_button.grid(row=4, column=0, columnspan=2, pady=10)

        self.pktgen_status = tk.Text(tab, height=5, state=tk.DISABLED)
        self.pktgen_status.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        tab.grid_columnconfigure(1, weight=1)

    def start_packet_generation(self):
        target_ip = self.pktgen_target_ip_entry.get()
        try:
            target_port = int(self.pktgen_target_port_entry.get())
            num_packets = int(self.pktgen_num_packets_entry.get())
            protocol = self.pktgen_protocol_combo.get()
        except ValueError:
            messagebox.showerror("Error", "Invalid input for port or number of packets.")
            return

        threading.Thread(target=self._packet_generation, args=(target_ip, target_port, num_packets, protocol)).start()
        self._update_status(self.pktgen_status, f"Generating and sending {num_packets} {protocol} packets to {target_ip}:{target_port}...\n")

    def _packet_generation(self, target_ip, target_port, num_packets, protocol):
        try:
            for _ in range(num_packets):
                if protocol == "TCP":
                    ip_layer = IP(dst=target_ip)
                    tcp_layer = TCP(dport=target_port, flags='S')  # SYN packet
                    packet = ip_layer / tcp_layer
                elif protocol == "UDP":
                    ip_layer = IP(dst=target_ip)
                    udp_layer = UDP(dport=target_port)
                    packet = ip_layer / udp_layer / b"Hello, Network!"
                elif protocol == "ICMP":
                    ip_layer = IP(dst=target_ip)
                    icmp_layer = ICMP()
                    packet = ip_layer / icmp_layer
                else:
                    self._update_status(self.pktgen_status, f"Unsupported protocol: {protocol}\n")
                    return

                send(packet, verbose=0)
                self._update_status(self.pktgen_status, f"Sent {protocol} packet to {target_ip}:{target_port}\n")
                time.sleep(0.1)
            self._update_status(self.pktgen_status, f"Packet generation and sending completed.\n")
        except Exception as e:
            self._update_status(self.pktgen_status, f"An error occurred during packet generation: {e}\n")

    def create_ping_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Ping Hostname")

        ttk.Label(tab, text="Hostname/IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ping_target_entry = ttk.Entry(tab)
        self.ping_target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.ping_button = ttk.Button(tab, text="Ping", command=self.start_ping)
        self.ping_button.grid(row=1, column=0, columnspan=2, pady=10)

        self.ping_status = tk.Text(tab, height=5, state=tk.DISABLED)
        self.ping_status.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        tab.grid_columnconfigure(1, weight=1)

    def start_ping(self):
        target = self.ping_target_entry.get()
        threading.Thread(target=self._ping, args=(target,)).start()
        self._update_status(self.ping_status, f"Pinging {target}...\n")

    def _ping(self, target):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', target]  # Ping 4 times
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while True:
                output = process.stdout.readline().decode()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    self._update_status(self.ping_status, output)
            _, errors = process.communicate()
            if errors:
                self._update_status(self.ping_status, f"Error during ping: {errors.decode()}\n")
        except FileNotFoundError:
            self._update_status(self.ping_status, "Error: 'ping' command not found. Ensure it's in your system's PATH.\n")
        except Exception as e:
            self._update_status(self.ping_status, f"An unexpected error occurred during ping: {e}\n")

    def create_dns_lookup_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="DNS Lookup")

        ttk.Label(tab, text="Hostname:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.dns_hostname_entry = ttk.Entry(tab)
        self.dns_hostname_entry.grid