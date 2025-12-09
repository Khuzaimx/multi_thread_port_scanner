import socket
import concurrent.futures
from PyQt5.QtCore import QObject, pyqtSignal
from scapy.all import IP, TCP, sr1, conf
import utils

# Suppress Scapy verbosity
conf.verb = 0

class ScannerWorker(QObject):
    """
    Worker class to handle port scanning in a separate thread.
    """
    result_ready = pyqtSignal(dict)  # Emits: {'port': int, 'status': str, 'service': str, 'os': str}
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, target_ip, start_port, end_port, scan_type="Connect", timeout=1.0, show_closed=False):
        super().__init__()
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.scan_type = scan_type
        self.timeout = timeout
        self.show_closed = show_closed
        self.is_running = True

    def run_scan(self):
        """
        Main execution method for the scanner.
        """
        try:
            ports = range(self.start_port, self.end_port + 1)
            
            # Use ThreadPoolExecutor for concurrent scanning
            # Adjust max_workers based on network limitations/preference
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.scan_port, port): port for port in ports}
                
                for future in concurrent.futures.as_completed(futures):
                    if not self.is_running:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    
                    try:
                        result = future.result()
                        if result:
                            self.result_ready.emit(result)
                    except Exception as e:
                        # Log or ignore individual port errors
                        pass
            
            self.finished.emit()

        except Exception as e:
            self.error.emit(str(e))

    def scan_port(self, port):
        """
        Route to the appropriate scan method.
        """
        if not self.is_running:
            return None

        if self.scan_type == "SYN":
            status = self.scan_port_syn(port)
        else:
            status = self.scan_port_connect(port)

        if status == "Open":
            service, banner, os_guess, vulns = self.deep_inspection(port)
            return {
                'port': port,
                'status': status,
                'service': service, # e.g. "SSH (OpenSSH 8.2...)"
                'os': os_guess,
                'vulns': ", ".join(vulns) if vulns else ""
            }
        elif self.show_closed:
             return {
                'port': port,
                'status': status,
                'service': utils.get_service_name(port),
                'os': "Unknown",
                'vulns': ""
            }
        
        return None

    def scan_port_connect(self, port):
        """
        Standard TCP Connect Scan.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target_ip, port))
                if result == 0:
                    return "Open"
                else:
                    return "Closed"
        except:
            return "Error"

    def scan_port_syn(self, port):
        """
        TCP SYN Scan using Scapy.
        """
        try:
            # Construct SYN packet
            pkt = IP(dst=self.target_ip) / TCP(dport=port, flags="S")
            # Send and wait for response
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if resp:
                if resp.haslayer(TCP):
                    flags = resp.getlayer(TCP).flags
                    if flags == 0x12: # SYN-ACK (0x12 = 010010 = SYN+ACK)
                        # Send RST to close connection politely (optional but good practice)
                        sr1(IP(dst=self.target_ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                        return "Open"
                    elif flags == 0x14: # RST-ACK
                        return "Closed"
            return "Filtered/Closed"
        except PermissionError:
             # This will likely be caught by the overall try/catch in run, but good to handle local
             raise PermissionError("SYN Scan requires Administrator/Root privileges.")
        except Exception as e:
            return f"Error: {e}"

    def deep_inspection(self, port):
        """
        Perform deep inspection: banner grabbing, HTTP headers, specific probes, and OS fingerprinting.
        """
        service = utils.get_service_name(port)
        banner = "Unknown"
        os_guess = "Unknown"
        extra_info = []

        # Reverse DNS (Limit to one attempt per host ideally, but fine here)
        try:
            hostname = socket.gethostbyaddr(self.target_ip)[0]
            if hostname != self.target_ip:
                extra_info.append(f"Host: {hostname}")
        except:
            pass

        # Service Specific Probes
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((self.target_ip, port))
                
                # HTTP/HTTPS Probe
                if port in [80, 443, 8080, 8443]:
                    request = f"HEAD / HTTP/1.1\r\nHost: {self.target_ip}\r\nUser-Agent: AntigravityScanner/1.0\r\n\r\n"
                    s.send(request.encode())
                    try:
                        response = s.recv(4096).decode('utf-8', errors='ignore')
                        # Extract Server and X-Powered-By
                        for line in response.split('\r\n'):
                            if line.lower().startswith("server:"):
                                extra_info.append(line.split(':', 1)[1].strip())
                            if line.lower().startswith("x-powered-by:"):
                                extra_info.append(line.split(':', 1)[1].strip())
                    except socket.timeout:
                        pass
                
                # SMTP Probe
                elif port in [25, 587]:
                    try:
                        # Read initial banner
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        # Send EHLO
                        s.send(b"EHLO antigravity\r\n")
                        response = s.recv(1024).decode('utf-8', errors='ignore')
                        if "250-" in response:
                            extra_info.append("ESMTP Supported")
                    except:
                        pass
                
                # Default Banner Grab
                else:
                    try:
                        # Wait briefly for unsolicited hello
                        data = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        if data:
                            banner = data.split('\n')[0][:50]
                    except socket.timeout:
                        # If no hello, try sending a generic query often triggers a response
                        s.send(b"Help\r\n")
                        try:
                            data = s.recv(1024).decode('utf-8', errors='ignore').strip()
                            if data:
                                banner = data.split('\n')[0][:50]
                        except:
                            pass

        except:
            pass
        
        # Combine Info
        full_service_info = service
        
        details = []
        if banner != "Unknown":
            details.append(banner)
        details.extend(extra_info)
        
        if details:
            full_service_info += f" ({', '.join(details)})"
            
        # Check Vulnerabilities
        vulns = utils.check_vulnerability(banner)
        # Also check extra info for matches (e.g. Server headers)
        for detail in extra_info:
            vulns.extend(utils.check_vulnerability(detail))

        # OS Fingerprinting (TTL based)
        if self.scan_type == "SYN": 
            try:
                pkt = IP(dst=self.target_ip) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=self.timeout, verbose=0)
                if resp and resp.haslayer(IP):
                    ttl = resp.getlayer(IP).ttl
                    os_guess = self.guess_os_from_ttl(ttl)
            except:
                pass
        
        return full_service_info, banner, os_guess, list(set(vulns))
    
    def guess_os_from_ttl(self, ttl):
        """
        Basic TTL-based OS Fingerprinting.
        """
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Solaris/Cisco"
        return "Unknown"

    def stop(self):
        """
        Signal the scanner to stop.
        """
        self.is_running = False
