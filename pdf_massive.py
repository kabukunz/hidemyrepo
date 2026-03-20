import subprocess
import json
import sys
import time
import argparse

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; GREEN = '\033[0;32m'
RED = '\033[0;31m'; CYAN = '\033[0;36m'; YELLOW = '\033[1;33m'

def run_mission(pipeline_data=None):
    cmd = ["python3", "pdf_run.py"]
    if pipeline_data:
        cmd.extend(["--pipeline", json.dumps(pipeline_data)])
    try:
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}Massive PDF Stress Test Suite{NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    group_mode = parser.add_argument_group("Mission Mode")
    group_mode.add_argument("-m", "--mode", choices=['standard', 'custom'], default='standard',
                            help="Run internal defaults (standard) or matrix (custom).")
    group_mode.add_argument("-n", "--repeats", type=int, default=1, help="Repetitions per test (default: 1).")
    
    group_custom = parser.add_argument_group("Custom Mode Configs")
    group_custom.add_argument("-hp", "--payload", default="payload_small", help="Payload directory for custom mode.")
    
    args = parser.parse_args()

    start_time = time.time()

    if args.mode == 'standard':
        print(f"{CYAN}{BOLD}>>> MODE: STANDARD REPEAT ({args.repeats} iterations){NC}")
        for i in range(1, args.repeats + 1):
            if not run_mission():
                print(f"{RED}[FAIL] Standard pipeline failed at iteration {i}{NC}")
                sys.exit(1)
    else:
        configs = [{"mc": 20, "sc": 0.15}, {"mc": 50, "sc": 0.30}]
        print(f"{CYAN}{BOLD}>>> MODE: CUSTOM MATRIX ({args.repeats} repeats each){NC}")
        for cfg in configs:
            for i in range(1, args.repeats + 1):
                test_pipeline = [
                    ("Clean", ["python3", "pdf_erase.py", "erase"]),
                    ("Hide",  ["python3", "pdf_hide.py", "hide", "-hp", args.payload, 
                               "-mc", str(cfg['mc']), "-sc", str(cfg['sc']), "-xf", "-xc"]),
                    ("Hash",  ["python3", "pdf_hide.py", "hash"])
                ]
                if not run_mission(test_pipeline):
                    print(f"{RED}[FAIL] Custom configuration failed.{NC}")
                    sys.exit(1)

    print(f"\n{GREEN}{BOLD}>>> ALL CYCLES COMPLETE IN {time.time() - start_time:.2f}s.{NC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Aborted.{NC}"); sys.exit(1)