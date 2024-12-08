import socket
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, UDP, ICMP, sr1, send, conf
import time

class SpecializedScanner:
    def __init__(self, targets, scan_type='sn', ports=None):
        """
        Initialize Scanner with various scanning types
        
        Args:
            targets (list): List of IP addresses/networks to scan
            scan_type (str): Scan type: 
                - 'sn' (Ping scan)
                - 'sS' (SYN Stealth scan)
                - 'sT' (TCP Connect scan)
                - 'sU' (UDP scan)
            ports (list, optional): List of ports to scan (for -sS, -sT, -sU)
        """
        self.targets = self._expand_targets(targets)
        self.scan_type = scan_type
        self.ports = ports or []
        self.results = []
        conf.verb = 0  # Disable Scapy verbose output

    def _expand_targets(self, targets):
        """
        Expand target list to include all IPs in CIDR ranges
        """
        expanded_targets = []
        for target in targets:
            try:
                # Check if target is a CIDR
                if '/' in target:
                    network = ipaddress.ip_network(target, strict=False)
                    expanded_targets.extend(str(ip) for ip in network.hosts())
                else:
                    expanded_targets.append(target)
            except ValueError:
                print(f"Invalid target: {target}")
        return expanded_targets

    def ping_scan(self):
        """
        Perform Ping Scan (-sn) with enhanced output
        """
        live_hosts = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {
                executor.submit(self._ping_host, target): target 
                for target in self.targets
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
        
        # Sort results for consistent and clean output
        return sorted(live_hosts)

    def _ping_host(self, target):
        """
        Ping a single host and return its IP if reachable
        """
        try:
            packet = IP(dst=target)/ICMP()
            reply = sr1(packet, timeout=1, verbose=0)
            
            if reply is not None and reply.haslayer(ICMP):
                return target
            return None
        except Exception:
            return None

    # Rest of the methods remain the same as in the previous implementation
    def _syn_stealth_port(self, target, port):
        """
        Check a single port with SYN stealth method
        Enhanced with more robust port detection
        """
        try:
            packet = IP(dst=target)/TCP(dport=port, flags="S")
            reply = sr1(packet, timeout=1, verbose=0)
            
            if reply and reply.haslayer(TCP):
                # More robust SYN-ACK detection
                if reply.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
                    return f"{target}:{port}"
            return None
        except Exception as e:
            return None

    def _tcp_connect_port(self, target, port):
        """
        Check a single port with TCP connect method
        Enhanced with more detailed timeout and exception handling
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Reduced timeout
            result = sock.connect_ex((target, port))
            sock.close()
            return f"{target}:{port}" if result == 0 else None
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _udp_port(self, target, port):
        """
        Check a single UDP port
        Enhanced detection method
        """
        try:
            packet = IP(dst=target)/UDP(dport=port)
            reply = sr1(packet, timeout=1, verbose=0)
            
            # More nuanced UDP port detection
            if not reply:
                return f"{target}:{port}"
            
            # Some UDP services might send an ICMP Port Unreachable
            if reply.haslayer(ICMP):
                icmp_type = reply.getlayer(ICMP).type
                if icmp_type != 3:  # Not a "Destination Unreachable"
                    return f"{target}:{port}"
            
            return None
        except Exception:
            return None

    def syn_stealth_scan(self):
        """
        Perform SYN Stealth Scan (-sS)
        """
        results = []
        with ThreadPoolExecutor(max_workers=50) as executor:  # Increased workers
            futures = {
                executor.submit(self._syn_stealth_port, target, port): (target, port)
                for target in self.targets
                for port in self.ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        return sorted(results)

    def tcp_connect_scan(self):
        """
        Perform TCP Connect Scan (-sT)
        """
        results = []
        with ThreadPoolExecutor(max_workers=50) as executor:  # Increased workers
            futures = {
                executor.submit(self._tcp_connect_port, target, port): (target, port)
                for target in self.targets
                for port in self.ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        return sorted(results)

    def udp_scan(self):
        """
        Perform UDP Scan (-sU)
        """
        results = []
        with ThreadPoolExecutor(max_workers=50) as executor:  # Increased workers
            futures = {
                executor.submit(self._udp_port, target, port): (target, port)
                for target in self.targets
                for port in self.ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        return sorted(results)

    def scan(self):
        """
        Perform scan based on selected scan type
        """
        if not self.targets:
            print("No valid targets specified.")
            return []

        if self.scan_type == 'sn':
            return self.ping_scan()
        elif self.scan_type == 'sS':
            return self.syn_stealth_scan()
        elif self.scan_type == 'sT':
            return self.tcp_connect_scan()
        elif self.scan_type == 'sU':
            return self.udp_scan()
        else:
            raise ValueError(f"Unsupported scan type: {self.scan_type}")
