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
    """Executes a single mission and returns success status."""
    cmd = ["python3", "pdf_run.py"]
    if pipeline_data:
        cmd.extend(["--pipeline", json.dumps(pipeline_data)])
    try:
        subprocess.run(cmd, check=True)
        return True, "None"
    except subprocess.CalledProcessError:
        return False, "Pipeline Breakdown"

def main():
    parser = argparse.ArgumentParser(description="pdf_massive.py v1.7.2")
    parser.add_argument("-m", "--mode", choices=['standard', 'custom'], default='standard')
    parser.add_argument("-n", "--repeats", type=int, default=1)
    parser.add_argument("-hp", "--payload", default="payload_small")
    args = parser.parse_args()

    audit_log = []
    suite_start = time.time()

    # --- Mode Execution ---
    if args.mode == 'standard':
        for i in range(1, args.repeats + 1):
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n{YELLOW}{BOLD}[MISSION {i}/{args.repeats}] Started at {ts}{NC}")
            
            m_start = time.time()
            success, error_stage = run_mission()
            m_duration = time.time() - m_start
            
            audit_log.append({
                "iter": i, "config": "Standard", "ts": ts, 
                "res": success, "err": error_stage, "dur": m_duration
            })
            if not success: break
    else:
        configs = [{"mc": 20, "sc": 0.15}, {"mc": 50, "sc": 0.30}]
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
                
                print(f"\n{YELLOW}{BOLD}[CUSTOM {run_count}] {conf_label} | {ts}{NC}")
                
                m_start = time.time()
                success, error_stage = run_mission(test_pipeline)
                m_duration = time.time() - m_start
                
                audit_log.append({
                    "iter": run_count, "config": conf_label, "ts": ts, 
                    "res": success, "err": error_stage, "dur": m_duration
                })
                if not success: break
            if not success: break

    # --- FINAL MISSION REPORT (v1.7.2) ---
    total_elapsed = time.time() - suite_start
    print(f"\n{CYAN}{BOLD}{'='*85}{NC}")
    print(f"{BOLD} FINAL STRESS TEST REPORT - v1.7.2{NC}")
    print(f"{CYAN}{'='*85}{NC}")
    
    # Header alignment
    print(f"{'ID':<4} | {'START':<9} | {'CONFIG':<16} | {'TIME':<8} | {'RESULT':<10} | {'FAILURE STAGE'}")
    print(f"{'-'*85}")

    success_count = 0
    for entry in audit_log:
        status_text = "PASS" if entry['res'] else "FAIL"
        status_color = GREEN if entry['res'] else RED
        if entry['res']: success_count += 1
        
        colored_status = f"{status_color}{status_text}{NC}"
        duration_str = f"{entry['dur']:.2f}s"
        
        # Table Row Output
        print(f"{entry['iter']:<4} | {entry['ts']:<9} | {entry['config']:<16} | {duration_str:<8} | {colored_status:<19} | {entry['err']}")

    print(f"{'-'*85}")
    print(f"{BOLD}Total Missions:{NC}  {len(audit_log)}")
    print(f"{BOLD}Success Rate:{NC}    {(success_count/len(audit_log))*100 if audit_log else 0:.1f}%")
    print(f"{BOLD}Avg. Duration:{NC}   {sum(e['dur'] for e in audit_log)/len(audit_log):.2f}s" if audit_log else "0s")
    print(f"{BOLD}Suite Total:{NC}     {total_elapsed:.2f}s")
    print(f"{CYAN}{BOLD}{'='*85}{NC}\n")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print(f"\n{RED}Aborted.{NC}"); sys.exit(1)