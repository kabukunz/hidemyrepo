import subprocess
import sys
import time
import json
import argparse

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; GREEN = '\033[0;32m'
RED = '\033[0;31m'; CYAN = '\033[0;36m'; YELLOW = '\033[1;33m'

def log_header(message):
    print(f"\n{CYAN}{BOLD}{'='*60}\n {message}\n{'='*60}{NC}")

def run_step(name, command):
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {YELLOW}{BOLD}[STAGE]{NC} Initializing: {name}...")
    try:
        subprocess.run(command, check=True)
        return True
    except subprocess.CalledProcessError:
        print(f"\n{RED}{BOLD}[FATAL ERROR]{NC} {name} aborted.")
        return False
    except FileNotFoundError:
        print(f"\n{RED}{BOLD}[FATAL ERROR]{NC} Component missing: {command[1]}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Forensic Pipeline Engine")
    parser.add_argument("--pipeline", help="JSON string of custom pipeline steps")
    args = parser.parse_args()

    # 1. Pipeline Selection (Injected JSON vs. Standard Defaults)
    if args.pipeline:
        try:
            pipeline = json.loads(args.pipeline)
            log_header("INJECTED TEST PIPELINE START")
        except json.JSONDecodeError:
            print(f"{RED}Error: Invalid JSON pipeline string.{NC}")
            sys.exit(1)
    else:
        pipeline = [
            ("Session Cleaning",       ["python3", "pdf_erase.py", "erase"]),
            ("Payload Injection",      ["python3", "pdf_hide.py", "hide", "-xf", "-xc"]),
            ("Metadata Alignment",     ["python3", "pdf_sync.py", "sync"]),
            ("Payload Restore",        ["python3", "pdf_hide.py", "restore"]),
            ("Carrier Diff Audit",     ["python3", "pdf_hide.py", "diff"]),
            ("Payload Hash Audit",     ["python3", "pdf_hide.py", "hash"]),
            ("Timestamp Sync Audit",   ["python3", "pdf_sync.py", "audit"]),
            ("Forensic Scan Audit",    ["python3", "pdf_hide.py", "find"])
        ]
        log_header("STANDARD MISSION START")

    # 2. Execution Loop
    start_time = time.time()
    try:
        for name, cmd in pipeline:
            if not run_step(name, cmd):
                sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{RED}[ABORTED]{NC} Interrupted by operator.")
        sys.exit(1)

    elapsed = time.time() - start_time
    log_header("SUCCESS: PIPELINE VERIFIED")
    print(f"{GREEN}{BOLD}[DONE]{NC} Completed in {elapsed:.2f}s.\n")

if __name__ == "__main__":
    main()