import subprocess
import sys
import time

# --- UI Constants ---
NC = '\033[0m'
BOLD = '\033[1m'
GREEN = '\033[0;32m'
RED = '\033[0;31m'
CYAN = '\033[0;36m'

def log_header(message):
    print(f"\n{CYAN}{BOLD}{'='*60}")
    print(f" {message}")
    print(f"{'='*60}{NC}")

def run_step(command):
    """Executes a shell command and monitors for failure."""
    try:
        # We use shell=False for security, passing arguments as a list
        subprocess.run(command, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n{RED}{BOLD}[FATAL ERROR]{NC} Step failed: {' '.join(command)}")
        return False
    except FileNotFoundError:
        print(f"\n{RED}{BOLD}[FATAL ERROR]{NC} Script not found. Ensure all .py files are in this directory.")
        return False

def main():
    start_time = time.time()
    
    # 1. Pipeline Definition
    # Each tuple contains: (Display Name, Command List)
    pipeline = [
        ("Session Cleaning", ["python3", "pdf_erase.py", "erase"]),
        ("Payload Injection", ["python3", "pdf_hide.py", "hide"]),
        ("Metadata Alignment", ["python3", "pdf_sync.py", "sync"]),
        ("Extraction Verification", ["python3", "pdf_hide.py", "restore"]),
        ("Carrier Diff Audit", ["python3", "pdf_hide.py", "diff"]),
        ("Payload Hash Audit", ["python3", "pdf_hide.py", "hash"]),
        ("Timestamp Sync Audit", ["python3", "pdf_sync.py", "audit"]),
        ("Forensic Scan Audit", ["python3", "pdf_hide.py", "find"])
    ]

    log_header("PDF FORENSIC STEGANOGRAPHY SUITE: STARTING")

    # 2. Execution Loop
    for name, cmd in pipeline:
        if not run_step(cmd):
            sys.exit(1)

    # 3. Final Summary
    elapsed = time.time() - start_time
    log_header("SUITE EXECUTION COMPLETE")
    print(f"{GREEN}{BOLD}[SUCCESS]{NC} All forensic stages passed in {elapsed:.2f}s.")

if __name__ == "__main__":
    main()