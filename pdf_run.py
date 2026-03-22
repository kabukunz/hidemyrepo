import subprocess
import sys
import time
import json
import argparse
import logging

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; GREEN = '\033[0;32m'
RED = '\033[0;31m'; CYAN = '\033[0;36m'; YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)

def log_header(message):
    """Visual separator for pipeline stages."""
    header = f"\n{CYAN}{BOLD}{'='*60}\n {message}\n{'='*60}{NC}"
    logging.info(header)

def run_step(name, command):
    """Executes a pipeline stage and captures exit codes."""
    logging.info(f"{YELLOW}{BOLD}[STAGE]{NC} Initializing: {name}...")
    try:
        # We use check=True to ensure we catch failures immediately
        subprocess.run(command, check=True)
        return True
    except subprocess.CalledProcessError:
        logging.error(f"\n{RED}{BOLD}[FATAL ERROR]{NC} {name} aborted.")
        return False
    except FileNotFoundError:
        logging.error(f"\n{RED}{BOLD}[FATAL ERROR]{NC} Component missing: {command[1]}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Pipeline Engine{NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example JSON Pipeline:\n"
               '  --pipeline \'[["Clean", ["python3", "pdf_erase.py", "erase"]], '
               '["Hide", ["python3", "pdf_hide.py", "hide"]]]\''
    )
    parser.add_argument("-p", "--pipeline", help="JSON string of custom pipeline steps to override defaults.")
    args = parser.parse_args()

    # Determine which Python interpreter to use for sub-calls
    py_exec = sys.executable or "python3"

    if args.pipeline:
        try:
            pipeline = json.loads(args.pipeline)
            log_header("INJECTED TEST PIPELINE START")
        except json.JSONDecodeError:
            logging.error(f"{RED}Error: Invalid JSON pipeline string.{NC}")
            sys.exit(1)
    else:
        # Standard Mission Alignment: Mapping to our refactored scripts
        pipeline = [
            ("Session Cleaning",       [py_exec, "pdf_erase.py", "erase"]),
            ("Payload Injection",      [py_exec, "pdf_hide.py", "hide", "-xf", "-xc"]),
            ("Metadata Alignment",     [py_exec, "pdf_sync.py", "sync"]),
            ("Payload Restore",        [py_exec, "pdf_hide.py", "restore"]),
            ("Carrier Diff Audit",     [py_exec, "pdf_hide.py", "diff"]),
            ("Payload Hash Audit",     [py_exec, "pdf_hide.py", "hash"]),
            ("Timestamp Sync Audit",   [py_exec, "pdf_sync.py", "audit"]),
            ("Forensic Scan Audit",    [py_exec, "pdf_hide.py", "find"])
        ]
        log_header("STANDARD MISSION START")

    start_time = time.time()
    try:
        for name, cmd in pipeline:
            if not run_step(name, cmd):
                sys.exit(1)
    except KeyboardInterrupt:
        logging.warning(f"\n{RED}[ABORTED]{NC} Interrupted by operator.")
        sys.exit(1)

    elapsed = time.time() - start_time
    log_header("SUCCESS: PIPELINE VERIFIED")
    logging.info(f"{GREEN}{BOLD}[DONE]{NC} Completed in {elapsed:.2f}s.\n")

if __name__ == "__main__":
    main()