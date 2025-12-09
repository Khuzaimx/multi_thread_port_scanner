import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTableWidget, QTableWidgetItem, QComboBox, QMessageBox,
                             QHeaderView, QCheckBox, QFileDialog, QSplitter, QTextEdit,
                             QTabWidget, QFormLayout)
import csv
from PyQt5.QtCore import QThread, Qt, QTime
from PyQt5.QtGui import QColor
import scanner
import utils

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Antigravity Port Scanner")
        self.setGeometry(100, 100, 800, 600)
        
        # Central Widget & Layout
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # --- TAB 1: Port Scanner ---
        self.scanner_tab = QWidget()
        layout = QVBoxLayout(self.scanner_tab)
        self.tabs.addTab(self.scanner_tab, "Port Scanner")
        
        # --- TAB 2: Router Fingerprint ---
        self.router_tab = QWidget()
        self.setup_router_tab()
        self.tabs.addTab(self.router_tab, "Router Fingerprint")
        
        # Input Section
        input_layout = QHBoxLayout()
        
        # Host Input
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Target IP / Hostname")
        input_layout.addWidget(QLabel("Target:"))
        input_layout.addWidget(self.host_input)
        
        # Ports Input
        self.start_port_input = QLineEdit()
        self.start_port_input.setPlaceholderText("Start")
        self.start_port_input.setFixedWidth(60)
        self.end_port_input = QLineEdit()
        self.end_port_input.setPlaceholderText("End")
        self.end_port_input.setFixedWidth(60)
        
        input_layout.addWidget(QLabel("Ports:"))
        input_layout.addWidget(self.start_port_input)
        input_layout.addWidget(QLabel("-"))
        input_layout.addWidget(self.end_port_input)

        # Scan Type
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["Connect Scan", "SYN Scan"])
        input_layout.addWidget(QLabel("Type:"))
        input_layout.addWidget(self.scan_type_combo)

        # Show Closed Checkbox
        self.show_closed_cb = QCheckBox("Show Closed")
        self.show_closed_cb.setChecked(True)
        input_layout.addWidget(self.show_closed_cb)
        
        # Active Penetration Checkbox
        self.active_probe_cb = QCheckBox("Active Penetration (Slow)")
        self.active_probe_cb.setStyleSheet("color: red; font-weight: bold")
        self.active_probe_cb.setToolTip("Sends payloads to test for misconfigurations")
        input_layout.addWidget(self.active_probe_cb)
        
        layout.addLayout(input_layout)
        
        # Control Buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        
        self.export_btn = QPushButton("Export CSV")
        self.export_btn.clicked.connect(self.export_csv)

        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.export_btn)
        layout.addLayout(btn_layout)
        
        
        # Results Table & Splitter
        splitter = QSplitter(Qt.Vertical)
        
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Port", "Status", "Service/Banner", "OS Guess", "Vulnerabilities"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        splitter.addWidget(self.table)
        
        # Log Console
        console_widget = QWidget()
        console_layout = QVBoxLayout(console_widget)
        console_layout.setContentsMargins(0, 5, 0, 0)
        console_layout.addWidget(QLabel("Penetration Log Console:"))
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setStyleSheet("background-color: #1e1e1e; color: #00ff00; font-family: Consolas, Monospace;")
        console_layout.addWidget(self.log_console)
        splitter.addWidget(console_widget)
        
        splitter.setStretchFactor(0, 3) # Table larger
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter)
        
        # Status Bar
        self.status_label = QLabel("Ready")
        self.statusBar().addWidget(self.status_label)
        
        # Scanning Thread Handling
        self.thread = None
        self.worker = None

    def start_scan(self):
        target = self.host_input.text().strip()
        
        # Validate Inputs
        ip = utils.resolve_hostname(target)
        if not ip:
            QMessageBox.critical(self, "Error", "Invalid Hostname or IP Address")
            return
            
        try:
            start_port = int(self.start_port_input.text())
            end_port = int(self.end_port_input.text())
            if start_port > end_port or start_port < 1 or end_port > 65535:
                raise ValueError
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid Port Range (1-65535)")
            return

        scan_type_text = self.scan_type_combo.currentText()
        scan_type = "SYN" if "SYN" in scan_type_text else "Connect"

        if scan_type == "SYN":
             # Basic check if user might not be admin (not foolproof, but a hint)
             pass 

        # Clear Table & Console
        self.table.setRowCount(0)
        self.log_console.clear()
        self.log_console.append(f"[*] Starting scan on {target} ({ip})...")
        self.status_label.setText(f"Scanning {target} ({ip}) from port {start_port} to {end_port}...")
        
        # Disable inputs
        self.toggle_inputs(False)

        # Setup Thread and Worker
        show_closed = self.show_closed_cb.isChecked()
        active_probe = self.active_probe_cb.isChecked()
        self.thread = QThread()
        self.worker = scanner.ScannerWorker(ip, start_port, end_port, scan_type=scan_type, show_closed=show_closed, active_probe=active_probe)
        self.worker.moveToThread(self.thread)
        
        # Connect Signals
        self.thread.started.connect(self.worker.run_scan)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.worker.result_ready.connect(self.add_result)
        self.worker.error.connect(self.handle_error)
        self.thread.finished.connect(self.scan_finished)
        
        self.thread.start()

    def stop_scan(self):
        if self.worker:
            self.worker.stop()
            self.status_label.setText("Stopping scan...")

    def scan_finished(self):
        open_count = 0
        closed_count = 0
        
        for row in range(self.table.rowCount()):
            status_item = self.table.item(row, 1)
            if status_item:
                if status_item.text() == "Open":
                    open_count += 1
                else:
                    closed_count += 1
                    
        self.status_label.setText(f"Scan Complete. Open: {open_count}, Closed: {closed_count}")
        self.toggle_inputs(True)

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Results", "", "CSV Files (*.csv)")
        if path:
            try:
                with open(path, 'w', newline='') as stream:
                    writer = csv.writer(stream)
                    writer.writerow(["Port", "Status", "Service/Banner", "OS Guess", "Vulnerabilities"])
                    for row in range(self.table.rowCount()):
                        row_data = []
                        for col in range(self.table.columnCount()):
                            item = self.table.item(row, col)
                            row_data.append(item.text() if item else "")
                        writer.writerow(row_data)
                QMessageBox.information(self, "Success", "Results exported successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {str(e)}")

    def add_result(self, result):
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        # Port
        self.table.setItem(row, 0, QTableWidgetItem(str(result['port'])))
        
        # Status
        status_item = QTableWidgetItem(result['status'])
        if result['status'] == "Open":
            status_item.setForeground(QColor("green"))
        else:
            status_item.setForeground(QColor("red"))
        self.table.setItem(row, 1, status_item)
        
        # Service
        self.table.setItem(row, 2, QTableWidgetItem(result['service']))
        
        # OS
        self.table.setItem(row, 3, QTableWidgetItem(result['os']))

        # Vulnerabilities
        vuln_item = QTableWidgetItem(result['vulns'])
        if result['vulns']:
            vuln_item.setForeground(QColor("red"))
        self.table.setItem(row, 4, vuln_item)
        
        # Append Logs
        if 'logs' in result and result['logs']:
             timestamp = QTime.currentTime().toString("HH:mm:ss")
             for log in result['logs']:
                 self.log_console.append(f"[{timestamp}] [Port {result['port']}] {log}")
             # If critical findings, maybe highlight?
             if "CRITICAL" in result['vulns']:
                 self.log_console.append(f"[{timestamp}] [!!!] CRITICAL VULNERABILITY FOUND ON PORT {result['port']}")

    # --- ROUTER FINGERPRINT LOGIC ---
    def start_fingerprint(self):
        target = self.router_ip_input.text()
        if not target:
             QMessageBox.warning(self, "Input Error", "Please enter a target IP.")
             return

        self.router_results.clear()
        self.router_results.append(f"[*] Starting Fingerprint on {target}...\n")
        self.fingerprint_btn.setEnabled(False)
        
        self.fp_thread = QThread()
        self.fp_worker = scanner.RouterFingerprinter(target)
        self.fp_worker.moveToThread(self.fp_thread)
        
        self.fp_thread.started.connect(self.fp_worker.run)
        self.fp_worker.log_msg.connect(self.update_router_log)
        self.fp_worker.finished.connect(self.display_fingerprint)
        self.fp_worker.finished.connect(self.fp_thread.quit)
        self.fp_worker.finished.connect(self.fp_worker.deleteLater)
        self.fp_thread.finished.connect(self.fp_thread.deleteLater)
        self.fp_thread.finished.connect(lambda: self.fingerprint_btn.setEnabled(True))
        
        self.fp_thread.start()
        
    def update_router_log(self, msg):
        self.router_results.append(f"[LOG] {msg}")

    def display_fingerprint(self, results):
        self.router_results.append("\n" + "="*40)
        self.router_results.append("       ROUTER FINGERPRINT RESULTS       ")
        self.router_results.append("="*40 + "\n")
        
        self.router_results.append(f"MANUFACTURER:  {results['Manufacturer']}")
        self.router_results.append(f"OS TYPE:       {results['OS']}")
        self.router_results.append(f"ADMIN PORT:    {results['Admin Port']}")
        self.router_results.append(f"TR-069 STATUS: {results['TR-069']}")
        self.router_results.append("-" * 30)
        self.router_results.append("DETAILS / HINTS:")
        for detail in results['Details']:
            self.router_results.append(f" - {detail}")

    def handle_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.stop_scan()

    def toggle_inputs(self, enable):
        self.start_btn.setEnabled(enable)
        self.export_btn.setEnabled(enable)
        self.stop_btn.setEnabled(not enable)
        self.host_input.setEnabled(enable)
        self.start_port_input.setEnabled(enable)
        self.end_port_input.setEnabled(enable)
        self.scan_type_combo.setEnabled(enable)
        self.show_closed_cb.setEnabled(enable)
        self.active_probe_cb.setEnabled(enable)

    # --- ROUTER FINGERPRINT LOGIC ---
    def setup_router_tab(self):
        layout = QVBoxLayout()
        
        # Input Area
        input_layout = QHBoxLayout()
        self.router_ip_input = QLineEdit()
        self.router_ip_input.setPlaceholderText("Target Router IP (e.g. 192.168.0.1)")
        input_layout.addWidget(QLabel("Target:"))
        input_layout.addWidget(self.router_ip_input)
        
        self.fingerprint_btn = QPushButton("Analyze Router")
        self.fingerprint_btn.clicked.connect(self.start_fingerprint)
        self.fingerprint_btn.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        input_layout.addWidget(self.fingerprint_btn)
        
        self.exploit_btn = QPushButton("Exploit UPnP ☠️")
        self.exploit_btn.setEnabled(False) # Enabled only if UPnP found
        self.exploit_btn.clicked.connect(self.start_upnp_exploit)
        self.exploit_btn.setStyleSheet("background-color: #aa0000; color: white; font-weight: bold;")
        input_layout.addWidget(self.exploit_btn)
        
        layout.addLayout(input_layout)
        
        # Results Display
        self.router_results = QTextEdit()
        self.router_results.setReadOnly(True)
        self.router_results.setStyleSheet("font-family: Consolas; font-size: 14px; background-color: #2b2b2b; color: #00ff00;")
        layout.addWidget(self.router_results)
        
        self.router_tab.setLayout(layout)

    def start_fingerprint(self):
        target = self.router_ip_input.text()
        if not target:
             QMessageBox.warning(self, "Input Error", "Please enter a target IP.")
             return

        self.router_results.clear()
        self.router_results.append(f"[*] Starting Advanced Router Recon on {target}...\n")
        self.fingerprint_btn.setEnabled(False)
        
        # Import new module here if needed or at top
        import router_recon
        
        self.fp_thread = QThread()
        self.fp_worker = router_recon.RouterRecon(target)
        self.fp_worker.moveToThread(self.fp_thread)
        
        self.fp_thread.started.connect(self.fp_worker.run_all)
        self.fp_worker.log_msg.connect(self.update_router_log)
        self.fp_worker.finished.connect(self.display_fingerprint)
        self.fp_worker.finished.connect(self.fp_thread.quit)
        self.fp_worker.finished.connect(self.fp_worker.deleteLater)
        self.fp_thread.finished.connect(self.fp_thread.deleteLater)
        self.fp_thread.finished.connect(lambda: self.fingerprint_btn.setEnabled(True))
        
        self.fp_thread.start()
        
    def update_router_log(self, msg):
        self.router_results.append(f"[LOG] {msg}")

    def display_fingerprint(self, results):
        self.router_results.append("\n" + "="*50)
        self.router_results.append("       🕵️  ROUTER RECON AUDIT REPORT  🕵️       ")
        self.router_results.append("="*50 + "\n")
        
        # Vendor & Model
        self.router_results.append(f"🎯 VENDOR:   {results.get('Vendor', 'Unknown').upper()}")
        self.router_results.append(f"📦 MODEL:    {results.get('Model', 'Unknown')}")
        self.router_results.append(f"💾 FIRMWARE: {results.get('Firmware', 'Unknown')}")
        self.router_results.append("-" * 40)
        
        # Critical Issues
        if results.get("Critical_Issues"):
             self.router_results.append("🚨 CRITICAL ISSUES DETECTED:")
             for issue in results["Critical_Issues"]:
                 self.router_results.append(f"   [!] {issue}")
        else:
             self.router_results.append("✅ No Critical Misconfigurations Detected (Basic Check).")
             
        self.router_results.append("-" * 40)
        
        # Open Ports / Protocols
        self.router_results.append(f"OPEN PORTS: {results.get('Open_Ports')}")
        self.router_results.append("PROTOCOLS IDENTIFIED:")
        for port, proto in results.get("Protocols", {}).items():
            self.router_results.append(f"   - Port {port}: {proto}")
            
        # HTTP Info
        if results.get("HTTP_Info"):
             self.router_results.append("\n🌍 HTTP INTELLIGENCE:")
             self.router_results.append(f"   Title: {results['HTTP_Info'].get('Title', 'N/A')}")
             if results['HTTP_Info'].get('Hidden_Fields'):
                 self.router_results.append(f"   Hidden Fields: {len(results['HTTP_Info']['Hidden_Fields'])} found")

        if results.get("Exploits"):
             self.router_results.append("\n💣 EXPLOIT SURFACE MAPPED:")
             for exp in results["Exploits"]:
                 self.router_results.append(f"   [X] {exp}")
        
        self.router_results.append("="*50)
        
        # Check if UPnP Open to enable Exploit
        if 1900 in results.get("Protocols", {}):
            self.exploit_btn.setEnabled(True)
            self.router_results.append("\n[!] UPnP Detected! Exploit Module Enabled.")

    def start_upnp_exploit(self):
        target = self.router_ip_input.text()
        self.router_results.append(f"\n[☠️] LAUNCHING UPnP EXPLOIT on {target}...")
        self.exploit_btn.setEnabled(False)
        
        import router_recon
        self.exp_thread = QThread()
        self.exp_worker = router_recon.UPnPExploiter(target)
        self.exp_worker.moveToThread(self.exp_thread)
        
        self.exp_thread.started.connect(self.exp_worker.run_exploit)
        self.exp_worker.log_msg.connect(self.update_router_log)
        self.exp_worker.finished.connect(self.exploit_finished)
        
        # We need to capture the control_url from the worker if we want to reuse it, 
        # or we just rely on PostExploit to re-discover or pass it via a property if we modified backend.
        # Ideally, update backend to signal control_url.
        # For now, let's just trigger PostExploit. It will likely need to scan again or we pass logic.
        # Actually simplest: PostExploiter has its own upnp logic or passed control_url.
        # Update: Let's chain them.
        
        self.exp_worker.finished.connect(self.exp_thread.quit)
        self.exp_worker.finished.connect(self.exp_worker.deleteLater)
        self.exp_thread.finished.connect(self.exp_thread.deleteLater)
        # self.exp_thread.finished.connect(lambda: self.exploit_btn.setEnabled(True)) # Don't enable yet, wait for PostExploit
        
        self.exp_thread.start()

    def exploit_finished(self, success, msg):
        self.router_results.append(f"\n[RESULT] {msg}")
        
        if success:
             self.router_results.append("\n[!] Ports Opened! AUTO-RUNNING POST-EXPLOITATION PAYLOADS... 🚀")
             self.start_post_exploitation()
        else:
             self.router_results.append("\n[FAILED] Stopping chain.")
             self.exploit_btn.setEnabled(True)
             QMessageBox.warning(self, "Exploit Failed", msg)

    def start_post_exploitation(self):
        target = self.router_ip_input.text()
        import router_recon
        
        self.post_thread = QThread()
        self.post_worker = router_recon.PostExploiter(target)
        self.post_worker.moveToThread(self.post_thread)
        
        self.post_thread.started.connect(self.post_worker.run_payloads)
        self.post_worker.log_msg.connect(self.update_router_log)
        self.post_worker.finished.connect(self.post_exploit_finished)
        self.post_worker.finished.connect(self.post_thread.quit)
        self.post_worker.finished.connect(self.post_worker.deleteLater)
        self.post_thread.finished.connect(self.post_thread.deleteLater)
        self.post_thread.finished.connect(lambda: self.exploit_btn.setEnabled(True))
        
        self.post_thread.start()

    def post_exploit_finished(self, success, msg):
        self.router_results.append(f"\n[POST-EXP] {msg}")
        QMessageBox.information(self, "Attack Chain Complete", "All modules finished.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
