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

def log_header(message, color=CYAN):
    """Visual separator for pipeline stages."""
    header = f"\n{color}{BOLD}{'='*60}\n {message}\n{'='*60}{NC}"
    logging.info(header)

def run_step(name, command):
    """Executes a pipeline stage and captures exit codes."""
    logging.info(f"{YELLOW}{BOLD}[STAGE]{NC} Initializing: {name}...")
    try:
        # v2.2.0: check=True is vital because ghost.py returns sys.exit(1) on FAIL
        subprocess.run(command, check=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"\n{RED}{BOLD}[INTEGRITY BREACH]{NC} {name} failed with exit code {e.returncode}.")
        return False
    except Exception as e:
        logging.error(f"\n{RED}{BOLD}[RUNTIME ERROR]{NC} {name} crashed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}Ghost v2.2.0 Forensic Pipeline{NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-p", "--pipeline", help="JSON string to override defaults.")
    parser.add_argument("-k", "--key", help="Optional: Pass password to all steps.")
    args = parser.parse_args()

    # Unified Script Pointer
    hide_bin = "pdf_hide.py" 
    py_exec = sys.executable or "python3"

    # Default Standard Operating Procedure (SOP)
    # We now call ghost.py for every forensic layer
    default_pipeline = [
        # ("Clean State",        [py_exec, hide_bin, "erase"]),
        ("Payload Injection",  [py_exec, hide_bin, "hide", "-xf", "-xc", "-hb", "--crypto", "aes"]),
        ("Structural Audit",   [py_exec, hide_bin, "diff"]),
        ("Bit-Level Audit",    [py_exec, hide_bin, "hash"]),
        ("Timestamp Sync",     [py_exec, hide_bin, "sync"]),
        ("Forensic Audit",     [py_exec, hide_bin, "audit"]),
        ("Surface Audit",      [py_exec, hide_bin, "touch"]),
        # ("Payload Restore",        [py_exec, hide_bin, "restore"]),
    ]

    # Handle Password Injection if provided
    if args.key:
        for name, cmd in default_pipeline:
            if cmd[2] in ['hide', 'restore']:
                cmd.append(args.key)

    pipeline = default_pipeline
    if args.pipeline:
        try:
            pipeline = json.loads(args.pipeline)
        except json.JSONDecodeError:
            logging.error(f"{RED}Error: Invalid JSON string.{NC}")
            sys.exit(1)

    log_header("GHOST v2.2.0 PIPELINE START", BLUE)
    start_time = time.time()

    try:
        for name, cmd in pipeline:
            if not run_step(name, cmd):
                log_header("PIPELINE TERMINATED: FAILED", RED)
                sys.exit(1)
    except KeyboardInterrupt:
        logging.warning(f"\n{RED}[ABORTED]{NC} Operator manual override.")
        sys.exit(1)

    elapsed = time.time() - start_time
    log_header("SUCCESS: ALL FORENSIC CHECKS PASSED", GREEN)
    logging.info(f"{GREEN}{BOLD}[DONE]{NC} Full lifecycle verified in {elapsed:.2f}s.\n")

if __name__ == "__main__":
    main()