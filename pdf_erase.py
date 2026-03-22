import os
import sys
import random
import string
import argparse
import time
import shutil
import logging

# --- UI Constants ---
NC = '\033[0m'       
BOLD = '\033[1m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
BLUE = '\033[0;34m'

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)

def secure_shred_file(path, dry_run=False):
    """Forensic-grade file wipe: Rename, random fill, unlink."""
    if dry_run:
        logging.warning(f"{YELLOW}{BOLD}[DRY-RUN]{NC} Would shred and unlink: {path}")
        return True
    try:
        file_size = os.path.getsize(path)
        dir_name = os.path.dirname(path)
        base_name = os.path.basename(path)

        # 1. Rename to random string to obfuscate filename history
        random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=max(5, len(base_name))))
        new_path = os.path.join(dir_name, random_name)
        os.rename(path, new_path)
        
        # 2. Overwrite with random numbers and sync to disk
        if file_size > 0:
            with open(new_path, "ba+", buffering=0) as f:
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())

        # 3. Unlink from filesystem
        os.remove(new_path)
        return True
    except Exception as e:
        logging.error(f"{RED}{BOLD}[ERROR]{NC} Could not shred {path}: {e}")
        return False

def handle_path(path, action, dry_run=False):
    """Dispatches file or directory to the appropriate erasure method."""
    if not os.path.exists(path):
        logging.warning(f"{YELLOW}{BOLD}[SKIP]{NC} Not found: {path}")
        return

    if os.path.isfile(path):
        if action == 'secure':
            if secure_shred_file(path, dry_run) and not dry_run:
                logging.info(f"{GREEN}{BOLD}[SECURE]{NC} Shredded file: {path}")
        else:
            if dry_run:
                logging.warning(f"{YELLOW}{BOLD}[DRY-RUN]{NC} Would remove file: {path}")
            else:
                os.remove(path)
                logging.info(f"{GREEN}{BOLD}[ERASE]{NC} Removed file: {path}")
            
    elif os.path.isdir(path):
        if action == 'secure':
            logging.info(f"{CYAN}{BOLD}[INFO]{NC} {'[DRY] ' if dry_run else ''}Recursively shredding: {path}")
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    secure_shred_file(os.path.join(root, name), dry_run)
                for name in dirs:
                    d_path = os.path.join(root, name)
                    if dry_run:
                        logging.warning(f"{YELLOW}{BOLD}[DRY-RUN]{NC} Would rmdir: {d_path}")
                    else:
                        os.rmdir(d_path)
            
            if dry_run:
                logging.warning(f"{YELLOW}{BOLD}[DRY-RUN]{NC} Would remove parent dir: {path}")
            else: 
                os.rmdir(path)
                logging.info(f"{GREEN}{BOLD}[SECURE]{NC} Directory wiped: {path}")
        else:
            if dry_run:
                logging.warning(f"{YELLOW}{BOLD}[DRY-RUN]{NC} Would rmtree: {path}")
            else:
                shutil.rmtree(path)
                logging.info(f"{GREEN}{BOLD}[ERASE]{NC} Directory removed: {path}")

def setup_args():
    """Configures CLI for standard or forensic disposal."""
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Suite Cleanup Tool (v1.6.1){NC}\n"
                    "Disposes of steganography pipeline artifacts using shared flag logic.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("action", choices=['erase', 'secure'], 
                        help="Action: 'erase' (standard) or 'secure' (forensic shred).")

    paths = parser.add_argument_group(f'{CYAN}Path Configuration{NC}')
    paths.add_argument("-rp", "--found_payload", default="found_payload", help="Extraction target.")
    paths.add_argument("-rd", "--found_carrier", default="found_carrier", help="Modified carriers.")

    sessions = parser.add_argument_group(f'{CYAN}Session Tracking{NC}')
    sessions.add_argument("-cf", "--carrier_file", default="carrier.txt", help="Manifest to shred.")
    sessions.add_argument("-pf", "--password_file", default="password.txt", help="Key file to shred.")
    
    parser.add_argument("-d", "--dry-run", action="store_true", help="Show actions without executing.")

    return parser.parse_args()

if __name__ == "__main__":
    args = setup_args()
    
    logging.info(f"\n{BLUE}{BOLD}--- [1] SESSION CLEANING ---{NC}")
    
    targets = [
        args.password_file,
        args.carrier_file,
        args.found_payload,
        args.found_carrier
    ]
    
    for target in targets:
        handle_path(target, args.action, args.dry_run)

    logging.info(f"{GREEN}{BOLD}[STATUS]{NC} Session cleanup complete.")