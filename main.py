import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTableWidget, QTableWidgetItem, QComboBox, QMessageBox,
                             QHeaderView, QCheckBox, QFileDialog, QSplitter, QTextEdit)
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
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
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
        
        # Splitter Logic
        splitter = QSplitter(Qt.Vertical)
        
        # Results Table
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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
