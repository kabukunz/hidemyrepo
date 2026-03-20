import subprocess
import sys
import time

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; GREEN = '\033[0;32m'
RED = '\033[0;31m'; CYAN = '\033[0;36m'; YELLOW = '\033[1;33m'

def log_header(message):
    """Visual mission briefing header."""
    print(f"\n{CYAN}{BOLD}{'='*60}")
    print(f" {message}")
    print(f"{'='*60}{NC}")

def run_step(name, command):
    """Executes a forensic stage and monitors for mission-critical failure."""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {YELLOW}{BOLD}[STAGE]{NC} Initializing: {name}...")
    try:
        subprocess.run(command, check=True)
        return True
    except subprocess.CalledProcessError:
        print(f"\n{RED}{BOLD}[FATAL ERROR]{NC} {name} aborted. Check logs above.")
        return False
    except FileNotFoundError:
        print(f"\n{RED}{BOLD}[FATAL ERROR]{NC} Component missing: {command[1]}")
        return False

def start_pipeline(pipeline=None):
    """
    The Core Engine. 
    If pipeline is None, it uses the standard mission profile.
    """
    start_time = time.time()
    
    # 1. Pipeline Definition (Standard if not injected)
    active_pipeline = pipeline or [
        ("Session Cleaning",       ["python3", "pdf_erase.py", "erase"]),
        ("Payload Injection",      ["python3", "pdf_hide.py", "hide", "-xf", "-xc"]),
        ("Metadata Alignment",     ["python3", "pdf_sync.py", "sync"]),
        ("Payload Restore",        ["python3", "pdf_hide.py", "restore"]),
        ("Carrier Diff Audit",     ["python3", "pdf_hide.py", "diff"]),
        ("Payload Hash Audit",     ["python3", "pdf_hide.py", "hash"]),
        ("Timestamp Sync Audit",   ["python3", "pdf_sync.py", "audit"]),
        ("Forensic Scan Audit",    ["python3", "pdf_hide.py", "find"])
    ]

    log_header("PDF FORENSIC STEGANOGRAPHY SUITE: MISSION START")

    # 2. Execution Loop
    try:
        for name, cmd in active_pipeline:
            if not run_step(name, cmd):
                return False, name # Returns failure status and stage name
    except KeyboardInterrupt:
        print(f"\n{RED}{BOLD}[ABORTED]{NC} Mission terminated by operator.")
        sys.exit(1)

    # 3. Final Summary
    elapsed = time.time() - start_time
    log_header("SUCCESS: ALL STAGES VERIFIED")
    print(f"{GREEN}{BOLD}[DONE]{NC} Pipeline completed in {elapsed:.2f}s.\n")
    return True, "Success"

if __name__ == "__main__":
    # Standard standalone execution
    success, _ = start_pipeline()
    if not success:
        sys.exit(1)