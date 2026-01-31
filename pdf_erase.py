import os, sys, random, string, argparse, time

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

def secure_shred(path):
    """Forensic-grade wipe: Rename to random, fill with random bits, unlink."""
    if not os.path.exists(path):
        log("SKIP", f"File not found: {path}", YELLOW)
        return False

    try:
        file_size = os.path.getsize(path)
        dir_name = os.path.dirname(path)
        base_name = os.path.basename(path)

        # 1. Rename to random string (Obscure metadata)
        random_name = ''.join(random.choices(string.ascii_letters + string.digits, k=len(base_name)))
        new_path = os.path.join(dir_name, random_name)
        os.rename(path, new_path)
        
        # 2. Overwrite with random numbers (No zero-markers)
        with open(new_path, "ba+", buffering=0) as f:
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno()) # Force write to physical media

        # 3. Unlink
        os.remove(new_path)
        log("SECURE", f"Shredded and unlinked: {base_name}", GREEN)
        return True
    except Exception as e:
        log("ERROR", f"Failed to shred {path}: {e}", RED)
        return False

def standard_erase(path):
    """Standard OS removal (fast but carvable)."""
    if not os.path.exists(path):
        log("SKIP", f"File not found: {path}", YELLOW)
        return False
    try:
        os.remove(path)
        log("ERASE", f"Removed: {os.path.basename(path)}", GREEN)
        return True
    except Exception as e:
        log("ERROR", f"Failed to remove {path}: {e}", RED)
        return False

def setup_args():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Suite Cleanup Tool{NC}\n"
                    "Securely disposes of passwords and manifests.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Positional Action
    parser.add_argument("action", choices=['erase', 'secure'], 
                        help="Action to perform: 'erase' (standard) or 'secure' (forensic shred).")

    # Target Configuration
    targets = parser.add_argument_group(f'{CYAN}Target Files{NC}')
    targets.add_argument("-f", "--files", nargs='+', default=["pdf_pwd.txt", "pdf_files.txt"],
                        help="List of files to target. (Default: pdf_pwd.txt pdf_files.txt)")

    return parser.parse_args()

if __name__ == "__main__":
    args = setup_args()
    
    log("INFO", f"Starting {args.action.upper()} routine...", CYAN)
    
    count = 0
    for target in args.files:
        if args.action == 'secure':
            if secure_shred(target): count += 1
        else:
            if standard_erase(target): count += 1

    log("STATUS", f"Cleanup finished. Files processed: {count}", GREEN)