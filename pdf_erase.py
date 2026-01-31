import os, sys, random, string, argparse, time, shutil

# --- UI Constants ---
NC = '\033[0m'       
BOLD = '\033[1m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'

def log(tag, message, color=NC):
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {color}{BOLD}[{tag}]{NC} {message}")

def secure_shred_file(path, dry_run=False):
    """Forensic-grade file wipe: Rename, random fill, unlink."""
    if dry_run:
        log("DRY-RUN", f"Would shred and unlink: {path}", YELLOW)
        return True
    try:
        file_size = os.path.getsize(path)
        dir_name = os.path.dirname(path)
        base_name = os.path.basename(path)

        # 1. Rename to random string
        random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=max(5, len(base_name))))
        new_path = os.path.join(dir_name, random_name)
        os.rename(path, new_path)
        
        # 2. Overwrite with random numbers
        if file_size > 0:
            with open(new_path, "ba+", buffering=0) as f:
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())

        # 3. Unlink
        os.remove(new_path)
        return True
    except Exception as e:
        log("ERROR", f"Could not shred {path}: {e}", RED)
        return False

def handle_path(path, action, dry_run=False):
    """Dispatches file or directory to the appropriate erasure method."""
    if not os.path.exists(path):
        log("SKIP", f"Not found: {path}", YELLOW)
        return

    if os.path.isfile(path):
        if action == 'secure':
            secure_shred_file(path, dry_run)
            if not dry_run: log("SECURE", f"Shredded file: {path}", GREEN)
        else:
            if dry_run:
                log("DRY-RUN", f"Would remove file: {path}", YELLOW)
            else:
                os.remove(path)
                log("ERASE", f"Removed file: {path}", GREEN)
            
    elif os.path.isdir(path):
        if action == 'secure':
            log("INFO", f"{'[DRY] ' if dry_run else ''}Recursively shredding: {path}", CYAN)
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    secure_shred_file(os.path.join(root, name), dry_run)
                for name in dirs:
                    if dry_run: log("DRY-RUN", f"Would rmdir: {os.path.join(root, name)}", YELLOW)
                    else: os.rmdir(os.path.join(root, name))
            
            if dry_run: log("DRY-RUN", f"Would remove parent dir: {path}", YELLOW)
            else: 
                os.rmdir(path)
                log("SECURE", f"Directory wiped: {path}", GREEN)
        else:
            if dry_run:
                log("DRY-RUN", f"Would rmtree: {path}", YELLOW)
            else:
                shutil.rmtree(path)
                log("ERASE", f"Directory removed: {path}", GREEN)

def setup_args():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Suite Cleanup Tool{NC}\n"
                    "Disposes of passwords, manifests, and restore directories.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("action", choices=['erase', 'secure'], 
                        help="Action: 'erase' (standard) or 'secure' (recursive forensic shred).")

    targets = parser.add_argument_group(f'{CYAN}Target Configuration{NC}')
    targets.add_argument("-f", "--files", nargs='+', 
                        default=["pdf_pwd.txt", "pdf_files.txt", "restore_dir", "restore_pdf_dir"],
                        help="Targets to remove. (Default: %(default)s)")
    
    parser.add_argument("-d", "--dry-run", action="store_true", help="Show actions without executing.")

    return parser.parse_args()

if __name__ == "__main__":
    args = setup_args()
    mode = "DRY-RUN MODE" if args.dry_run else args.action.upper()
    log("INFO", f"Starting {mode} routine...", CYAN)
    
    for target in args.files:
        handle_path(target, args.action, args.dry_run)

    log("STATUS", "Cleanup routine finished.", GREEN)