import subprocess
import json
import sys
import time
import argparse
from datetime import datetime

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; GREEN = '\033[0;32m'
RED = '\033[0;31m'; CYAN = '\033[0;36m'; YELLOW = '\033[1;33m'

def run_mission(pipeline_data=None):
    """Fires a mission at the v1.7 Engine and returns failure stage if any."""
    cmd = ["python3", "pdf_run.py"]
    if pipeline_data:
        cmd.extend(["--pipeline", json.dumps(pipeline_data)])
    
    try:
        # We allow output to flow to terminal for real-time monitoring
        subprocess.run(cmd, check=True)
        return True, "None"
    except subprocess.CalledProcessError:
        # In a real failure, pdf_run.py handles the specific error message
        return False, "Pipeline Breakdown"

def main():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}pdf_massive.py v1.7 - Stress Test Suite{NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    group_mode = parser.add_argument_group("Mission Mode")
    group_mode.add_argument("-m", "--mode", choices=['standard', 'custom'], default='standard',
                            help="Run internal defaults (standard) or matrix (custom).")
    group_mode.add_argument("-n", "--repeats", type=int, default=1, help="Repetitions per test.")
    
    group_custom = parser.add_argument_group("Custom Mode Configs")
    group_custom.add_argument("-hp", "--payload", default="payload_small", help="Payload directory for custom mode.")
    
    args = parser.parse_args()

    audit_log = []
    start_time = time.time()

    # --- Mode Selection & Execution ---
    if args.mode == 'standard':
        print(f"{CYAN}{BOLD}>>> MODE: STANDARD REPEAT ({args.repeats} iterations){NC}")
        for i in range(1, args.repeats + 1):
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n{YELLOW}{BOLD}[MISSION {i}/{args.repeats}] Started at {ts}{NC}")
            
            success, error_stage = run_mission()
            audit_log.append({"iter": i, "config": "Standard", "ts": ts, "res": success, "err": error_stage})
            
            if not success:
                print(f"{RED}[FAIL] Aborting suite at iteration {i}{NC}")
                break
    
    else:
        configs = [{"mc": 20, "sc": 0.15}, {"mc": 50, "sc": 0.30}]
        print(f"{CYAN}{BOLD}>>> MODE: CUSTOM MATRIX ({args.repeats} repeats each){NC}")
        
        run_count = 0
        for cfg in configs:
            for i in range(1, args.repeats + 1):
                run_count += 1
                ts = datetime.now().strftime("%H:%M:%S")
                conf_label = f"MC:{cfg['mc']} SC:{cfg['sc']}"
                
                test_pipeline = [
                    ("Clean", ["python3", "pdf_erase.py", "erase"]),
                    ("Hide",  ["python3", "pdf_hide.py", "hide", "-hp", args.payload, 
                               "-mc", str(cfg['mc']), "-sc", str(cfg['sc']), "-xf", "-xc"]),
                    ("Sync",  ["python3", "pdf_sync.py", "sync"]),
                    ("Hash",  ["python3", "pdf_hide.py", "hash"])
                ]
                
                print(f"\n{YELLOW}{BOLD}[CUSTOM {run_count}] {args.payload} | {conf_label} | {i}/{args.repeats}{NC}")
                
                success, error_stage = run_mission(test_pipeline)
                audit_log.append({"iter": run_count, "config": conf_label, "ts": ts, "res": success, "err": error_stage})
                
                if not success:
                    print(f"{RED}[FAIL] Aborting custom matrix at {conf_label}{NC}")
                    break
            if not success: break

    # --- FINAL MISSION REPORT ---
    elapsed = time.time() - start_time
    print(f"\n{CYAN}{BOLD}{'='*60}")
    print(f" FINAL STRESS TEST REPORT - v1.7")
    print(f"{'='*60}{NC}")
    print(f"{'ID':<4} | {'START':<10} | {'CONFIG':<15} | {'RESULT':<10} | {'FAILURE STAGE'}")
    print("-" * 60)

    success_count = 0
    for entry in audit_log:
        status = f"{GREEN}PASS{NC}" if entry['res'] else f"{RED}FAIL{NC}"
        if entry['res']: success_count += 1
        print(f"{entry['iter']:<4} | {entry['ts']:<10} | {entry['config']:<15} | {status:<10} | {entry['err']}")

    print(f"\n{BOLD}Total Missions:{NC}  {len(audit_log)}")
    print(f"{BOLD}Success Rate:{NC}    {(success_count/len(audit_log))*100 if audit_log else 0:.1f}%")
    print(f"{BOLD}Total Duration:{NC}  {elapsed:.2f}s")
    print(f"{CYAN}{BOLD}{'='*60}{NC}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Aborted.{NC}"); sys.exit(1)