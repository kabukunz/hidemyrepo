import subprocess
import json
import sys
import time
import argparse
import logging
from datetime import datetime

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

PY_EXEC = sys.executable or "python3"
AUTOMATION_BIN = "pdf_run.py" 

def run_pipeline(pipeline_data=None, password=None):
    """Wraps the automation engine to execute a single lifecycle."""
    cmd = [PY_EXEC, AUTOMATION_BIN]
    if password: cmd.extend(["--key", password])
    if pipeline_data: cmd.extend(["--pipeline", json.dumps(pipeline_data)])
    
    try:
        subprocess.run(cmd, check=True)
        return True, "None"
    except subprocess.CalledProcessError as e:
        return False, f"Breach (Code {e.returncode})"
    except Exception as e:
        return False, str(e)

def main():
    parser = argparse.ArgumentParser(description=f"{BOLD}Ghost v2.2.0 Batch Iterator{NC}")
    parser.add_argument("-n", "--repeats", type=int, default=1, help="Iterations")
    parser.add_argument("-k", "--key", help="Forensic Key")
    parser.add_argument("-p", "--pipeline", help="JSON string for custom logic injection")
    args = parser.parse_args()

    audit_log = []
    suite_start = time.time()

    # --- Execution Loop ---
    for i in range(1, args.repeats + 1):
        logging.info(f"{YELLOW}{BOLD}[MISSION {i}/{args.repeats}]{NC} Initiating cycle...")
        
        m_start = time.time()
        
        # We pass the pipeline string (if any) directly through to the automation engine
        success, error_reason = run_pipeline(pipeline_data=args.pipeline, password=args.key)
        
        m_duration = time.time() - m_start
        audit_log.append({
            "iter": i, 
            "ts": datetime.now().strftime("%H:%M:%S"), 
            "res": success, 
            "err": error_reason, 
            "dur": m_duration
        })

        if not success:
            logging.error(f"{RED}Chain broken at mission {i}. Stopping for analysis.{NC}")
            break

    # --- FINAL FORENSIC REPORT ---
    total_elapsed = time.time() - suite_start
    print(f"\n{CYAN}{BOLD}{'='*85}{NC}")
    print(f" {BOLD}GHOST v2.2.0 BATCH REPORT{NC}")
    print(f"{CYAN}{'='*85}{NC}")
    print(f"{'ID':<4} | {'START':<9} | {'DURATION':<10} | {'RESULT':<10} | {'REASON'}")
    print(f"{'-'*85}")

    success_count = sum(1 for e in audit_log if e['res'])
    for entry in audit_log:
        status_color = GREEN if entry['res'] else RED
        status_text = "PASS" if entry['res'] else "FAIL"
        
        print(f"{entry['iter']:<4} | {entry['ts']:<9} | {entry['dur']:>7.2f}s  | "
              f"{status_color}{status_text:<10}{NC} | {entry['err']}")

    print(f"{'-'*85}")
    logging.info(f"{BOLD}Batch Complete:{NC} {success_count}/{len(audit_log)} successful.")
    logging.info(f"{BOLD}Total Duration:{NC} {total_elapsed:.2f}s")
    print(f"{CYAN}{BOLD}{'='*85}{NC}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)