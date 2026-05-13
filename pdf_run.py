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

def run_step(name, command, use_shell=False):
    """
    Executes a pipeline stage with explicit shell control.
    v2.2.0: Captures exit codes to trigger the Integrity Breach signal.
    """
    
    # If using shell but command is a list, join it into a string
    if use_shell and isinstance(command, list):
        command = " ".join(command)

    logging.info(f"{YELLOW}{BOLD}[STAGE]{NC} [{name}] {command} (Shell: {use_shell})...")
    try:
        # Standardize command: Shell=True usually prefers a string, 
        # but modern subprocess.run handles lists on many systems.
        subprocess.run(command, check=True, shell=use_shell)
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
    # 3-Element Tuples: (Display Name, Command List/String, Shell Flag)
    default_pipeline = [
        ("LS",                  ["ls", "-lart"], True),
        ("RM hide carrier",     ["rm", "-rf", "hide_carrier"], True),
        ("COPY hide carrier",   ["cp", "-R", "hide_carrier_copy", "hide_carrier"], True),
        ("RM hide carrier",     ["rm", "-rf", "hide_payload"], True),
        ("COPY hide payload",   ["cp", "-R", "hide_payload_copy", "hide_payload"], True),
        ("Payload Injection",   [py_exec, hide_bin, "hide", "-xf", "-xc", "-hb", "--crypto", "aes"], False),
        ("Structural Audit",    [py_exec, hide_bin, "diff"], False),
        ("Bit-Level Audit",     [py_exec, hide_bin, "hash"], False),
        ("Timestamp Sync",      [py_exec, hide_bin, "sync"], False),
        ("Forensic Audit",      [py_exec, hide_bin, "audit"], False),
        ("Surface Audit",       [py_exec, hide_bin, "touch"], False),
        ("Payload Restore",     [py_exec, hide_bin, "restore"], False),
        ("DIFF payload",        ["diff", "-rq", "hide_payload", "hide_payload_copy"], True),
        ("Clean State",         [py_exec, hide_bin, "erase"], False),
    ]

    # Handle Password Injection if provided
    if args.key:
        for name, cmd, use_shell in default_pipeline:
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
        # Unpack the three parameters from the pipeline list
        for name, cmd, use_shell in pipeline:
            if not run_step(name, cmd, use_shell):
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