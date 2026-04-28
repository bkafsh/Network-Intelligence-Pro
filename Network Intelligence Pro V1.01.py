import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext, filedialog
import socket
import struct
import ssl
import datetime
import urllib.request
import json
import threading
import subprocess
import os
import re
from concurrent.futures import ThreadPoolExecutor

# --- Metadata ---
APP_VERSION = "1.0"

class NetworkIntelligencePro:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Network Intelligence Pro v{APP_VERSION}")
        self.root.geometry("1150x950")
        
        self.adapter_map = {}
        self.setup_ui()
        self.refresh_adapters()

    def setup_ui(self):
        self.tab_control = ttk.Notebook(self.root)

        # Tab Frames
        self.tab_local = ttk.Frame(self.tab_control)
        self.tab_port = ttk.Frame(self.tab_control)
        self.tab_subnet = ttk.Frame(self.tab_control)
        self.tab_ssl = ttk.Frame(self.tab_control)
        self.tab_lookup = ttk.Frame(self.tab_control)
        self.tab_trace = ttk.Frame(self.tab_control)
        self.tab_about = ttk.Frame(self.tab_control)

        # Add tabs in order
        self.tab_control.add(self.tab_local, text=' Local Discovery ')
        self.tab_control.add(self.tab_port, text=' Port Scanner ')
        self.tab_control.add(self.tab_subnet, text=' Subnet ')
        self.tab_control.add(self.tab_ssl, text=' SSL Verify ')
        self.tab_control.add(self.tab_lookup, text=' IP Lookup ')
        self.tab_control.add(self.tab_trace, text=' Traceroute ')
        self.tab_control.add(self.tab_about, text=' About ')

        self.setup_local_ui()
        self.setup_port_ui()
        self.setup_subnet_ui()
        self.setup_ssl_ui()
        self.setup_lookup_ui()
        self.setup_trace_ui()
        self.setup_about_ui()
        
        self.tab_control.pack(expand=1, fill="both")

    # --- 1. LOCAL DISCOVERY ---
    def setup_local_ui(self):
        f = tk.LabelFrame(self.tab_local, text=" Network Card & Discovery Settings ", padx=10, pady=10)
        f.pack(fill="x", padx=20, pady=10)
        
        tk.Label(f, text="Select Card:").grid(row=0, column=0, sticky="w")
        self.adapter_combo = ttk.Combobox(f, width=65, state="readonly")
        self.adapter_combo.grid(row=0, column=1, padx=10)
        self.adapter_combo.bind("<<ComboboxSelected>>", self.on_adapter_select)
        tk.Button(f, text="Refresh", command=self.refresh_adapters).grid(row=0, column=2)

        tk.Label(f, text="Scan Base IP:").grid(row=1, column=0, sticky="w", pady=5)
        self.loc_base = tk.Entry(f, width=20); self.loc_base.insert(0, "192.168.1")
        self.loc_base.grid(row=1, column=1, sticky="w", padx=10)

        p_frame = tk.Frame(self.tab_local)
        p_frame.pack(fill="x", padx=20, pady=5)
        
        self.loc_btn = tk.Button(p_frame, text="🚀 START DISCOVERY", command=self.run_local_discovery, 
                                  bg="#0078d4", fg="white", font=("Arial", 10, "bold"), width=25)
        self.loc_btn.pack(side=tk.LEFT)
        
        self.prog_bar = ttk.Progressbar(p_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.prog_bar.pack(side=tk.LEFT, fill="x", expand=True, padx=15)
        
        self.prog_lbl = tk.Label(p_frame, text="0%", width=5, font=("Arial", 9, "bold"))
        self.prog_lbl.pack(side=tk.LEFT)

        self.loc_tree = ttk.Treeview(self.tab_local, columns=("IP", "Status", "MAC", "Vendor", "Hostname"), show="headings")
        for c in ("IP", "Status", "MAC", "Vendor", "Hostname"): 
            self.loc_tree.heading(c, text=c); self.loc_tree.column(c, anchor="center")
        self.loc_tree.pack(fill="both", expand=True, padx=20, pady=10)

    def refresh_adapters(self):
        self.adapter_map = {}
        try:
            ps_cmd = "Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPAddress"
            out = subprocess.check_output(["powershell", "-Command", ps_cmd], text=True)
            for line in out.strip().split('\n')[2:]:
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 2:
                    alias, ip = parts[0], parts[1]
                    if ip != "127.0.0.1": self.adapter_map[f"{alias} ({ip})"] = ip
            self.adapter_combo['values'] = list(self.adapter_map.keys())
            if self.adapter_map: self.adapter_combo.current(0); self.on_adapter_select(None)
        except: pass

    def on_adapter_select(self, event):
        ip = self.adapter_map.get(self.adapter_combo.get(), "127.0.0.1")
        self.loc_base.delete(0, tk.END); self.loc_base.insert(0, ".".join(ip.split(".")[:-1]))

    def get_arp_data(self, ip):
        try:
            out = subprocess.check_output(f"arp -a {ip}", shell=True, text=True)
            match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", out)
            if match:
                mac = match.group(0).replace("-", ":").upper()
                vendors = {"00:0C:29":"VMware", "00:05:02":"Apple", "B8:27:EB":"R-Pi", "00:15:5D":"Microsoft", "00:1A:E2":"Cisco"}
                vendor = vendors.get(mac[:8], "Generic")
                return mac, vendor
        except: pass
        return "Unknown", "Unknown"

    def run_local_discovery(self):
        base = self.loc_base.get().strip()
        current_ip = self.adapter_map.get(self.adapter_combo.get(), "")
        for i in self.loc_tree.get_children(): self.loc_tree.delete(i)
        self.loc_btn.config(state="disabled")
        
        def work():
            if current_ip:
                m, v = self.get_arp_data(current_ip)
                self.root.after(0, lambda: self.loc_tree.insert("", tk.END, values=(current_ip, "Online (Self)", m, v, socket.gethostname())))

            ips = [f"{base}.{i}" for i in range(1, 255)]
            total = len(ips)
            with ThreadPoolExecutor(max_workers=100) as exe:
                futures = {exe.submit(lambda p: subprocess.call(f"ping -n 1 -w 200 {p}", stdout=subprocess.DEVNULL, shell=True), ip): ip for ip in ips}
                for count, f in enumerate(futures):
                    ip = futures[f]
                    if ip != current_ip and f.result() == 0:
                        mac, vendor = self.get_arp_data(ip)
                        try: host = socket.gethostbyaddr(ip)[0]
                        except: host = "Unknown"
                        self.root.after(0, lambda i=ip, s="Online", m=mac, v=vendor, h=host: self.loc_tree.insert("", tk.END, values=(i, s, m, v, h)))
                    
                    pct = int(((count + 1) / total) * 100)
                    self.root.after(0, lambda v=count+1, p=pct: (self.prog_bar.config(value=v, maximum=total), self.prog_lbl.config(text=f"{p}%")))

            self.root.after(0, lambda: self.loc_btn.config(state="normal"))
        threading.Thread(target=work, daemon=True).start()

    # --- 2. UPDATED ADVANCED PORT SCANNER ---
    def setup_port_ui(self):
        f = tk.Frame(self.tab_port, pady=10); f.pack()
        tk.Label(f, text="Target IP:").grid(row=0, column=0)
        self.p_target = tk.Entry(f); self.p_target.insert(0, "127.0.0.1"); self.p_target.grid(row=0, column=1, padx=5)
        tk.Label(f, text="Port(s):").grid(row=0, column=2)
        self.p_range = tk.Entry(f); self.p_range.insert(0, "80, 443, 3389, 47808"); self.p_range.grid(row=0, column=3, padx=5)

        # Boolean vars for simultaneous selection
        self.use_tcp = tk.BooleanVar(value=True)
        self.use_udp = tk.BooleanVar(value=False)

        tk.Label(f, text="Protocols:").grid(row=1, column=0)
        tk.Checkbutton(f, text="TCP", variable=self.use_tcp).grid(row=1, column=1, sticky="w")
        tk.Checkbutton(f, text="UDP", variable=self.use_udp).grid(row=1, column=2, sticky="w")
        
        tk.Button(f, text="BACnet Mode", command=lambda:(self.p_range.delete(0,tk.END), self.p_range.insert(0,"47808"), self.use_udp.set(True), self.use_tcp.set(False)), bg="#6c757d", fg="white").grid(row=1, column=3)
        tk.Button(self.tab_port, text="Run Advanced Port Scan", command=self.run_port_scan, bg="#d63384", fg="white", font=("Arial", 10, "bold"), width=30).pack(pady=5)
        
        self.p_out = scrolledtext.ScrolledText(self.tab_port, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10))
        self.p_out.pack(fill="both", expand=True, padx=20, pady=10)

    def run_port_scan(self):
        target, p_str = self.p_target.get(), self.p_range.get()
        self.p_out.delete(1.0, tk.END)
        self.p_out.insert(tk.END, f"{'PORT':<8} | {'PROTO':<5} | {'SERVICE':<12} | {'STATUS'}\n" + "-"*45 + "\n")
        
        try:
            if '-' in p_str: ports = list(range(*map(int, p_str.split('-'))))
            else: ports = [int(p) for p in p_str.replace(",", " ").split()]
        except: self.p_out.insert(tk.END, "Error: Invalid port input."); return

        active_protos = []
        if self.use_tcp.get(): active_protos.append("TCP")
        if self.use_udp.get(): active_protos.append("UDP")

        def check(p, proto):
            res = "CLOSED"
            try:
                try: service = socket.getservbyport(p, proto.lower())
                except: service = "Unknown"
                
                sock_type = socket.SOCK_STREAM if proto=="TCP" else socket.SOCK_DGRAM
                s = socket.socket(socket.AF_INET, sock_type)
                s.settimeout(1.5)
                
                if proto == "TCP":
                    if s.connect_ex((target, p)) == 0: res = "OPEN"
                else:
                    payload = b'\x81\x0a\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08' if p == 47808 else b'\x00'
                    s.sendto(payload, (target, p))
                    try: 
                        data, _ = s.recvfrom(1024)
                        res = "OPEN (Response)"
                    except: res = "NO RESPONSE"
                s.close()
            except: res = "ERROR"
            self.root.after(0, lambda: self.p_out.insert(tk.END, f"{p:<8} | {proto:<5} | {service:<12} | {res}\n"))

        for p in ports:
            for proto in active_protos:
                threading.Thread(target=check, args=(p, proto), daemon=True).start()

    # --- 3. SUBNET / SSL / LOOKUP / TRACE ---
    def setup_subnet_ui(self):
        f = tk.Frame(self.tab_subnet, pady=20); f.pack()
        tk.Label(f, text="IP Address:").pack(); self.s_ip = tk.Entry(f); self.s_ip.insert(0, "192.168.1.1"); self.s_ip.pack()
        tk.Label(f, text="Subnet Mask:").pack(); self.s_mask = tk.Entry(f); self.s_mask.insert(0, "255.255.255.0"); self.s_mask.pack()
        tk.Button(f, text="Calculate", command=self.calc_sub, bg="#0078d4", fg="white").pack(pady=10)
        self.s_res = tk.Label(self.tab_subnet, font=("Consolas", 10), justify="left"); self.s_res.pack()

    def calc_sub(self):
        try:
            ip, mk = self.s_ip.get(), self.s_mask.get()
            ip_n = struct.unpack('!I', socket.inet_aton(ip))[0]
            mk_n = struct.unpack('!I', socket.inet_aton(mk))[0]
            net, brd = ip_n & mk_n, ip_n | (~mk_n & 0xFFFFFFFF)
            self.s_res.config(text=f"Network: {socket.inet_ntoa(struct.pack('!I', net))}\nBroadcast: {socket.inet_ntoa(struct.pack('!I', brd))}\nRange: {socket.inet_ntoa(struct.pack('!I', net+1))} - {socket.inet_ntoa(struct.pack('!I', brd-1))}")
        except: pass

    def setup_ssl_ui(self):
        f = tk.Frame(self.tab_ssl, pady=20); f.pack()
        tk.Label(f, text="Domain:").pack(); self.ssl_h = tk.Entry(f); self.ssl_h.insert(0, "google.com"); self.ssl_h.pack()
        tk.Button(f, text="Verify SSL", command=self.do_ssl, bg="#28a745", fg="white").pack(pady=10)
        self.ssl_res = tk.Label(self.tab_ssl, text=""); self.ssl_res.pack()

    def do_ssl(self):
        h = self.ssl_h.get()
        try:
            with socket.create_connection((h, 443), timeout=5) as s:
                with ssl.create_default_context().wrap_socket(s, server_hostname=h) as ss:
                    cert = ss.getpeercert(); self.ssl_res.config(text=f"Expires: {cert['notAfter']}", fg="green")
        except: self.ssl_res.config(text="SSL Error", fg="red")

    def setup_lookup_ui(self):
        self.l_ip = tk.Entry(self.tab_lookup); self.l_ip.insert(0, "8.8.8.8"); self.l_ip.pack(pady=20)
        tk.Button(self.tab_lookup, text="Lookup IP", command=self.do_lookup).pack()
        self.l_res = tk.Label(self.tab_lookup, text=""); self.l_res.pack()

    def do_lookup(self):
        try:
            r = urllib.request.urlopen(f"https://ipapi.co/{self.l_ip.get()}/json/").read()
            d = json.loads(r.decode()); self.l_res.config(text=f"Org: {d.get('org')}\nCity: {d.get('city')}")
        except: self.l_res.config(text="Failed")

    def setup_trace_ui(self):
        self.t_host = tk.Entry(self.tab_trace); self.t_host.insert(0, "google.com"); self.t_host.pack(pady=10)
        tk.Button(self.tab_trace, text="Run Trace", command=self.do_trace).pack()
        self.t_out = scrolledtext.ScrolledText(self.tab_trace, height=15, bg="#1e1e1e", fg="white"); self.t_out.pack(padx=20, pady=10)

    def do_trace(self):
        h = self.t_host.get()
        def work():
            p = subprocess.Popen(['tracert', '-d', '-h', '10', h], stdout=subprocess.PIPE, text=True, shell=True)
            for line in p.stdout: self.root.after(0, lambda l=line: self.t_out.insert(tk.END, l))
        threading.Thread(target=work, daemon=True).start()

    def setup_about_ui(self):
        tk.Label(self.tab_about, text="Network Intelligence Pro", font=("Arial", 16, "bold"), fg="#0078d4").pack(pady=20)
        tk.Label(self.tab_about, text=f"Version {APP_VERSION}\nBuilt for Babak Afshari").pack()

if __name__ == "__main__":
    root = tk.Tk(); app = NetworkIntelligencePro(root); root.mainloop()
