import os
import sys
import random
import string
import argparse
import time
import shutil
import logging

__version__ = "2.0.1"

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
    """Forensic-grade file wipe: Rename, random fill, sync, unlink."""
    if dry_run:
        logging.warning(f"{YELLOW}{BOLD}[DRY-RUN]{NC} Would shred: {path}")
        return True
    try:
        file_size = os.path.getsize(path)
        dir_name = os.path.dirname(path)
        base_name = os.path.basename(path)

        # 1. Rename to obscure metadata history
        random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=max(8, len(base_name))))
        new_path = os.path.join(dir_name, random_name)
        os.rename(path, new_path)
        
        # 2. Overwrite & Sync
        if file_size > 0:
            with open(new_path, "ba+", buffering=0) as f:
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno()) # Force write to physical media

        # 3. Final Deletion
        os.remove(new_path)
        return True
    except Exception as e:
        logging.error(f"{RED}{BOLD}[ERROR]{NC} Could not shred {path}: {e}")
        return False

def handle_path(path, action, dry_run=False):
    """Dispatches to shredder or standard remover."""
    if not os.path.exists(path):
        return # Quiet skip for missing targets

    if os.path.isfile(path):
        if action == 'secure':
            if secure_shred_file(path, dry_run) and not dry_run:
                logging.info(f"{GREEN}{BOLD}[SECURE]{NC} Shredded: {path}")
        else:
            if dry_run:
                logging.warning(f"{YELLOW}{BOLD}[DRY-RUN]{NC} Would remove: {path}")
            else:
                os.remove(path)
                logging.info(f"{GREEN}{BOLD}[ERASE]{NC} Removed: {path}")
            
    elif os.path.isdir(path):
        if action == 'secure':
            logging.info(f"{CYAN}{BOLD}[INFO]{NC} Shredding directory tree: {path}")
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    secure_shred_file(os.path.join(root, name), dry_run)
                for name in dirs:
                    if not dry_run: os.rmdir(os.path.join(root, name))
            if not dry_run: 
                os.rmdir(path)
                logging.info(f"{GREEN}{BOLD}[SECURE]{NC} Tree wiped: {path}")
        else:
            if not dry_run:
                shutil.rmtree(path)
                logging.info(f"{GREEN}{BOLD}[ERASE]{NC} Tree removed: {path}")

def setup_args():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Suite Cleanup Tool ({__version__}){NC}\n"
                    "Consolidated manifest & payload disposal.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("action", choices=['erase', 'secure'], 
                        help="'erase' (fast) or 'secure' (shred).")

    paths = parser.add_argument_group(f'{CYAN}Path Targets{NC}')
    paths.add_argument("-hp", "--hide_payload", default="hide_payload", help="Original payload dir.")
    paths.add_argument("-rp", "--found_payload", default="found_payload", help="Restored payload dir.")
    paths.add_argument("-rd", "--found_carrier", default="found_carrier", help="Legacy carrier copies.")

    sessions = parser.add_argument_group(f'{CYAN}Manifest{NC}')
    sessions.add_argument("-jf", "--json_file", default="carrier.json", help="The central session file.")
    
    parser.add_argument("-d", "--dry-run", action="store_true", help="Audit without execution.")

    return parser.parse_args()

if __name__ == "__main__":
    args = setup_args()
    
    logging.info(f"\n{BLUE}{BOLD}--- [1] SESSION CLEANING (v{__version__}) ---{NC}")
    
    # Consolidating targets: JSON is now the only sensitive file
    targets = [
        args.json_file,
        args.hide_payload,
        args.found_payload,
        args.found_carrier
    ]
    
    for target in targets:
        handle_path(target, args.action, args.dry_run)

    logging.info(f"{GREEN}{BOLD}[STATUS]{NC} Clean complete.")