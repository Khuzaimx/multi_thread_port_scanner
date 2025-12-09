import socket
import struct
import re

# Top 50 Router Credentials (User:Pass)
TOP_50_CREDS = [
    ("admin", "admin"), ("root", "root"), ("admin", "password"), ("root", "admin"),
    ("user", "user"), ("admin", "1234"), ("admin", "12345"), ("admin", "123456"),
    ("support", "support"), ("guest", "guest"), ("admin", "pass"), ("telecom", "telecom"),
    ("root", "12345"), ("admin", "operator"), ("operator", "operator"), ("root", "toor"),
    ("admin", "admin123"), ("service", "service"), ("supervisor", "supervisor"),
    ("Administrator", "admin"), ("admin", ""), ("root", ""), ("", "admin"),
    ("ubnt", "ubnt"), ("pi", "raspberry"), ("cisco", "cisco"), ("tmadmin", "tmadmin"),
    ("super", "super"), ("tech", "tech"), ("realtek", "realtek"), ("admin", "smcadmin"),
    ("admin", "micros"), ("admin", "sweex"), ("admin", "changeme"), ("r00t", "admin"),
    ("root", "vizxv"), ("admin", "century"), ("admin", "motorola"),
    ("admin", "fios"), ("admin", "router"), ("admin", "system"), ("sysadmin", "sysadmin"),
    ("admin", "meinsm"), ("admin", "pegasus"), ("sitecom", "123456"), ("claro", "claro")
]

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    993: "IMAPS", 995: "POP3S", 5432: "PostgreSQL"
}

# Basic Signature Database (Regex -> Description)
VULN_DB = {
    r"vsftpd 2\.3\.4": "Backdoor Command Execution (CVE-2011-2523)",
    r"ProFTPD 1\.3\.3c": "Backdoor Command Execution (CVE-2010-4227)",
    r"Apache/2\.4\.49": "Path Traversal (CVE-2021-41773)",
    r"nginx/1\.18\.0": "Refer to NVD (Multiple CVEs possible)", # Generic example
    r"OpenSSH 7\.2p2": "Username Enumeration (CVE-2018-15473)",
    r"Microsoft-IIS/6\.0": "Buffer Overflow (CVE-2003-0352)",
    r"Struts 2": "Remote Code Execution (Multiple)",
    r"Elasticsearch 1\.1": "RCE (CVE-2014-3120)"
}

def get_service_name(port):
    """
    Returns the common service name for a given port, or 'Unknown' if not found.
    """
    try:
        return socket.getservbyport(port)
    except OSError:
        return COMMON_PORTS.get(port, "Unknown")

def resolve_hostname(host):
    """
    Resolves a hostname or URL to an IP address. Returns None if resolution fails.
    """
    # Strip protocol
    if host.startswith("http://"):
        host = host[7:]
    elif host.startswith("https://"):
        host = host[8:]
    
    # Strip trailing path/slashes
    if "/" in host:
        host = host.split("/")[0]
        
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None

def check_vulnerability(banner):
    """
    Checks a banner string against known vulnerability signatures.
    Returns a list of potential vulnerabilities.
    """
    vulns = []
    if not banner or banner == "Unknown":
        return vulns
        
    for pattern, description in VULN_DB.items():
        if re.search(pattern, banner, re.IGNORECASE):
            vulns.append(description)
            
    return vulns
