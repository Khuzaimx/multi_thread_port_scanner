import sys
from PyQt5.QtCore import QCoreApplication
import scanner
import time

# Mock QApp for signals
app = QCoreApplication(sys.argv)

def test_scanner():
    print("Testing Scanner Backend...")
    target = "scanme.nmap.org" # Safe scanning target
    start_port = 80
    end_port = 80
    
    worker = scanner.ScannerWorker(target, start_port, end_port, scan_type="Connect")
    
    results = []
    
    def on_result(res):
        print(f"Result Received: {res}")
        results.append(res)
        
    worker.result_ready.connect(on_result)
    worker.finished.connect(app.quit)
    
    print(f"Scanning {target}:{start_port}-{end_port}...")
    worker.run_scan()
    
    # Simple event loop to wait for signal
    # In a real GUI this is app.exec_()
    # Here we just run worker.run_scan() which is synchronous in its thread-spawning but the pool waits.
    # Actually run_scan uses ThreadPoolExecutor but waits for it locally?
    # No, ThreadPoolExecutor block with 'as executor' context manager?
    # Wait, in scanner.py:
    # with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    #    ...
    #    for future in concurrent.futures.as_completed(futures):
    # This IS blocking until all futures complete. So run_scan is synchronous. 
    # That's slightly wrong for a GUI worker, it should probably not block the thread it runs on if that thread is the GUI thread.
    # But I moved the worker to a QThread in main.py, so blocking that QThread is fine!
    
    if len(results) > 0 and results[0]['port'] == 80 and results[0]['status'] == 'Open':
        print("SUCCESS: Port 80 found open.")
    else:
        print("FAILURE: Port 80 not found or closed.")

if __name__ == "__main__":
    try:
        test_scanner()
        print("Verification Complete.")
    except Exception as e:
        print(f"Verification Failed: {e}")
