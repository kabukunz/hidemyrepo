import subprocess
import json
import sys
import time
import argparse

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; GREEN = '\033[0;32m'
RED = '\033[0;31m'; CYAN = '\033[0;36m'; YELLOW = '\033[1;33m'

def run_mission(pipeline_data=None):
    """Executes a single mission via pdf_run.py."""
    cmd = ["python3", "pdf_run.py"]
    if pipeline_data:
        cmd.extend(["--pipeline", json.dumps(pipeline_data)])
    
    try:
        # We allow the child process to print directly to the terminal
        subprocess.run(cmd, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    parser = argparse.ArgumentParser(description="Massive PDF Stress Tester")
    parser.add_argument("-n", "--repeats", type=int, default=1, help="Number of repetitions per test")
    parser.add_argument("-m", "--mode", choices=['standard', 'custom'], default='standard', 
                        help="Run pdf_run.py defaults or a custom test matrix")
    parser.add_argument("-hp", "--payload", default="payload_small", help="Payload folder for custom mode")
    args = parser.parse_args()

    start_time = time.time()

    if args.mode == 'standard':
        print(f"{CYAN}{BOLD}>>> STARTING STANDARD REPEAT TEST ({args.repeats} iterations){NC}")
        for i in range(1, args.repeats + 1):
            print(f"\n{YELLOW}{BOLD}[MISSION {i}/{args.repeats}]{NC}")
            if not run_mission():
                print(f"{RED}[FAIL] Standard pipeline failed at iteration {i}{NC}")
                sys.exit(1)
    
    else:
        # Custom Matrix Mode logic
        # You can expand this list to test multiple configurations in one go
        configs = [
            {"mc": 20, "sc": 0.15},
            {"mc": 50, "sc": 0.30}
        ]
        
        print(f"{CYAN}{BOLD}>>> STARTING CUSTOM MATRIX TEST ({args.repeats} repeats each){NC}")
        for cfg in configs:
            for i in range(1, args.repeats + 1):
                # Construct the injected pipeline
                test_pipeline = [
                    ("Clean", ["python3", "pdf_erase.py", "erase"]),
                    ("Hide",  ["python3", "pdf_hide.py", "hide", "-hp", args.payload, 
                               "-mc", str(cfg['mc']), "-sc", str(cfg['sc']), "-xf", "-xc"]),
                    ("Sync",  ["python3", "pdf_sync.py", "sync"]),
                    ("Hash",  ["python3", "pdf_hide.py", "hash"])
                ]
                
                print(f"\n{YELLOW}{BOLD}[CUSTOM] {args.payload} | MC:{cfg['mc']} | SC:{cfg['sc']} | {i}/{args.repeats}{NC}")
                if not run_mission(test_pipeline):
                    print(f"{RED}[FAIL] Custom configuration failed.{NC}")
                    sys.exit(1)

    elapsed = time.time() - start_time
    print(f"\n{GREEN}{BOLD}>>> ALL TEST CYCLES CONCLUDED SUCCESSFULLY IN {elapsed:.2f}s.{NC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Testing aborted by operator.{NC}")
        sys.exit(1)