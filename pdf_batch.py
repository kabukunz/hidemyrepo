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

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Cross-platform python executable resolution
PY_EXEC = sys.executable or "python3"

def run_pipeline(pipeline_data=None):
    """Executes a single steganography pipeline via pdf_run.py and returns success status."""
    cmd = [PY_EXEC, "pdf_run.py"]
    if pipeline_data:
        cmd.extend(["--pipeline", json.dumps(pipeline_data)])
    try:
        subprocess.run(cmd, check=True)
        return True, "None"
    except subprocess.CalledProcessError:
        return False, "Pipeline Breakdown"
    except Exception as e:
        return False, str(e)

def main():
    parser = argparse.ArgumentParser(description="pdf_batch.py v1.7.2 - Forensic Stress Tester")
    parser.add_argument("-m", "--mode", choices=['standard', 'custom'], default='standard')
    parser.add_argument("-n", "--repeats", type=int, default=1)
    parser.add_argument("-hp", "--payload", default="payload_small")
    args = parser.parse_args()

    audit_log = []
    suite_start = time.time()

    if args.mode == 'standard':
        for i in range(1, args.repeats + 1):
            logging.info(f"{YELLOW}{BOLD}[PIPELINE {i}/{args.repeats}] Starting standard pipeline...{NC}")
            
            m_start = time.time()
            success, error_stage = run_pipeline()
            m_duration = time.time() - m_start
            
            audit_log.append({
                "iter": i, "config": "Standard", "ts": datetime.now().strftime("%H:%M:%S"), 
                "res": success, "err": error_stage, "dur": m_duration
            })
            if not success:
                logging.error(f"{RED}Steganography Pipeline failed at iteration {i}.{NC}")
                break
    else:
        configs = [{"mc": 20, "sc": 0.15}, {"mc": 50, "sc": 0.30}]
        run_count = 0
        for cfg in configs:
            for i in range(1, args.repeats + 1):
                run_count += 1
                conf_label = f"MC:{cfg['mc']} SC:{cfg['sc']}"
                logging.info(f"{YELLOW}{BOLD}[CUSTOM {run_count}] Initializing {conf_label}...{NC}")
                
                test_pipeline = [
                    ("Clean", [PY_EXEC, "pdf_erase.py", "erase"]),
                    ("Hide",  [PY_EXEC, "pdf_hide.py", "hide", "-hp", args.payload, 
                               "-mc", str(cfg['mc']), "-sc", str(cfg['sc']), "-xf", "-xc"]),
                    ("Sync",  [PY_EXEC, "pdf_sync.py", "sync"]),
                    ("Hash",  [PY_EXEC, "pdf_hide.py", "hash"])
                ]
                
                m_start = time.time()
                success, error_stage = run_pipeline(test_pipeline)
                m_duration = time.time() - m_start
                
                audit_log.append({
                    "iter": run_count, "config": conf_label, "ts": datetime.now().strftime("%H:%M:%S"), 
                    "res": success, "err": error_stage, "dur": m_duration
                })
                if not success: break
            if not success: break

    # --- FINAL PIPELINE REPORT (v1.7.2) ---
    total_elapsed = time.time() - suite_start
    
    # We use a single print block for the final report to preserve table alignment
    print(f"\n{CYAN}{BOLD}{'='*85}{NC}")
    print(f"{BOLD} FINAL STRESS TEST REPORT - v1.7.2{NC}")
    print(f"{CYAN}{'='*85}{NC}")
    print(f"{'ID':<4} | {'START':<9} | {'CONFIG':<16} | {'TIME':<8} | {'RESULT':<10} | {'FAILURE STAGE'}")
    print(f"{'-'*85}")

    success_count = 0
    for entry in audit_log:
        status_text = "PASS" if entry['res'] else "FAIL"
        status_color = GREEN if entry['res'] else RED
        if entry['res']: success_count += 1
        
        colored_status = f"{status_color}{status_text}{NC}"
        duration_str = f"{entry['dur']:.2f}s"
        
        print(f"{entry['iter']:<4} | {entry['ts']:<9} | {entry['config']:<16} | {duration_str:<8} | {colored_status:<19} | {entry['err']}")

    print(f"{'-'*85}")
    logging.info(f"{BOLD}Total Missions:{NC}  {len(audit_log)}")
    logging.info(f"{BOLD}Success Rate:{NC}    {(success_count/len(audit_log))*100 if audit_log else 0:.1f}%")
    logging.info(f"{BOLD}Avg. Duration:{NC}   {sum(e['dur'] for e in audit_log)/len(audit_log):.2f}s" if audit_log else "0s")
    logging.info(f"{BOLD}Suite Total:{NC}     {total_elapsed:.2f}s")
    print(f"{CYAN}{BOLD}{'='*85}{NC}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning(f"\n{RED}Batch sequence aborted by operator.{NC}")
        sys.exit(1)