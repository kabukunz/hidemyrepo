import os, sys, hashlib, argparse, zipfile, io, math, time, secrets, string, random

# --- UI Constants ---
# Color Constants for Terminal UI
NC = '\033[0m'       # No Color
BOLD = '\033[1m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
LIST_FILE = "pdf_files.txt"
PWD_FILE = "pdf_pwd.txt"

# --- Utility & Crypto Functions ---
def generate_robust_password(length=32):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def xor_crypt(data, password):
    if not password: return data
    key = password.encode()
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def get_file_hash(path):
    if not os.path.exists(path): return None
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""): sha.update(chunk)
    return sha.hexdigest()

def save_session(password, manifest, dry_run=False):
    """Saves the password and the list of used carriers."""
    # We always save these, even in dry run, so the user can audit the plan.
    try:
        # Save Password
        with open("pdf_pwd.txt", "w") as f:
            f.write(password)
        
        # Save Manifest (The list of carrier filenames)
        with open("pdf_files.txt", "w") as f:
            for item in manifest:
                # Ensure we only write the filename, not the full path
                f.write(f"{os.path.basename(item)}\n")
        
        prefix = f"{YELLOW}[DRY RUN]{NC} " if dry_run else ""
        print(f"{prefix}{GREEN}✓{NC} Mission manifest saved to pdf_files.txt")
        print(f"{prefix}{GREEN}✓{NC} Password saved to pdf_pwd.txt")
        
    except Exception as e:
        print(f"{RED}[!] Failed to save session files: {e}{NC}")
        
def load_session():
    pwd, manifest = None, []
    # Look in the current working directory for session files
    if os.path.exists(PWD_FILE):
        with open(PWD_FILE, "r") as f: pwd = f.read().strip()
    if os.path.exists(LIST_FILE):
        with open(LIST_FILE, "r") as f: manifest = [l.strip() for l in f if l.strip()]
    return pwd, manifest

def draw_progress(current, total, prefix=""):
    if total <= 0: return
    bar_len = 40
    filled = int(bar_len * current // total)
    bar = ('█' * filled).ljust(bar_len)
    sys.stdout.write(f"\r{prefix} |{bar}| {int(100*current/total)}% ({current}/{total})")
    sys.stdout.flush()

def get_zip_memory(source_dir):
    if not os.path.exists(source_dir): return None
    
    # Pre-scan for progress bar
    all_paths = []
    for root, dirs, files in os.walk(source_dir):
        for name in dirs + files:
            all_paths.append(os.path.join(root, name))
            
    if not all_paths: return None

    print(f"{BOLD}{BLUE}[ZIP]{NC} Compressing {len(all_paths)} items to memory...")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i, path in enumerate(all_paths, 1):
            rel_path = os.path.relpath(path, source_dir)
            
            if os.path.isdir(path):
                # Add directory entry (must end with /)
                zip_info = zipfile.ZipInfo(rel_path + '/')
                zf.writestr(zip_info, '')
            else:
                zf.write(path, rel_path)
            
            draw_progress(i, len(all_paths), prefix="  Zipping   ")
    
    print() 
    return buf.getvalue()

def get_sorted_files(directory, extension=None):
    if not os.path.exists(directory): return []
    flist = []
    for root, _, files in os.walk(directory):
        for f in files:
            if extension and not f.lower().endswith(extension): continue
            flist.append(os.path.join(root, f))
    flist.sort()
    return flist

def get_payload_files(source_dir):
    """Bridge for pdf_run: Gathers payload metadata."""
    if not os.path.exists(source_dir): return []
    files = []
    for root, _, filenames in os.walk(source_dir):
        for f in filenames:
            if f.startswith('.'): continue
            p = os.path.join(root, f)
            files.append({'path': p, 'size': os.path.getsize(p)})
    return files

def get_available_carriers(source_pdf_dir, exclude_chars=""):
    """Bridge for pdf_run: Gathers and filters PDFs."""
    all_pdfs = get_sorted_files(source_pdf_dir, ".pdf")
    available, _ = filter_carriers(all_pdfs, exclude_chars)
    return available

# --- Core Hide Procedural Steps ---

def filter_carriers(all_pdfs, exclude_chars):
    available_pool, char_excluded = [], []
    for f in all_pdfs:
        fname = os.path.basename(f)
        if any(char in fname for char in exclude_chars):
            char_excluded.append(fname)
            continue
        available_pool.append({'path': f, 'size': os.path.getsize(f)})
    return available_pool, char_excluded

def select_carrier_pool(files, payload_len, carrier_size_max_incr, max_count, password=None):
    """Deterministically shuffles based on password."""
    pool = sorted(files, key=lambda x: x['path'].lower())
    if password:
        random.Random(password).shuffle(pool)

    selected, current_cap, reserves = [], 0, []
    for f in pool:
        limit = int(f['size'] * carrier_size_max_incr)
        if len(selected) < max_count and current_cap < payload_len:
            selected.append(f)
            current_cap += limit
        else:
            reserves.append(f)
    return selected, current_cap, reserves

def check_capacity(current_cap, payload_len, available_files, carrier_size_max_incr):
    if current_cap < payload_len:
        missing_payload = payload_len - current_cap
        required_pdf_bytes = missing_payload / carrier_size_max_incr
        needed_mb = required_pdf_bytes / 1024 / 1024
        print(f"\n{RED}[!] FORENSIC CAPACITY FAILURE{NC}")
        print(f"To maintain stealth ({int(carrier_size_max_incr*100)}% increment), add {needed_mb:.2f} MB more PDFs.")
        sys.exit(1)

def run_dry_audit(selected_pool, payload_len, max_growth, char_excluded, reserve_carriers):
    print(f"\n{BOLD}{BLUE}[DRY RUN: FORENSIC AUDIT]{NC}")
    if char_excluded:
        print(f"\n{YELLOW}EXCLUDED:{NC}")
        for f in sorted(char_excluded): print(f"  [X] {f}")
    print(f"\n{GREEN}ACTION PLAN:{NC}")
    total_pool_bytes = sum(c['size'] for c in selected_pool)
    for i, c in enumerate(selected_pool, 1):
        shard = int((c['size'] / total_pool_bytes) * payload_len)
        growth = (shard / c['size']) * 100
        print(f" {i:2}. | {os.path.basename(c['path']):<45} | +{shard:<10,} B | {growth:>7.2f}%")

def perform_injection(selected_pool, encrypted, source_pdf_dir, restore_pdf_dir):
    total_pool_bytes = sum(c['size'] for c in selected_pool)
    payload_len = len(encrypted)
    cursor, manifest_entries = 0, []
    for i, c in enumerate(selected_pool, 1):
        rel = os.path.relpath(c['path'], source_pdf_dir)
        manifest_entries.append(rel)
        dst = os.path.join(restore_pdf_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shard_size = math.floor((c['size'] / total_pool_bytes) * payload_len)
        shard = encrypted[cursor:] if i == len(selected_pool) else encrypted[cursor:cursor + shard_size]
        cursor += len(shard)
        with open(c['path'], 'rb') as f: data = f.read()
        with open(dst, 'wb') as f:
            f.write(data); f.write(shard)
        draw_progress(i, len(selected_pool), prefix="  Injecting ")
    print()
    return manifest_entries

def hide(args):
    if not args.password:
        args.password = generate_robust_password()
        print(f"\n🔑 GENERATED PASSWORD: {BOLD}{args.password}{NC}")
    raw_payload = get_zip_memory(args.source_dir)
    if not raw_payload: return
    encrypted = xor_crypt(raw_payload, args.password)
    all_pdfs = get_sorted_files(args.source_pdf_dir, ".pdf")
    available, excluded = filter_carriers(all_pdfs, args.exclude_carrier_chars)
    selected, cap, reserves = select_carrier_pool(available, len(encrypted), args.max_carrier_size, args.max_carriers)
    check_capacity(cap, len(encrypted), available, args.max_carrier_size)
    if args.dry_run:
            run_dry_audit(selected, len(encrypted), args.carrier_size_max_incr, excluded, reserves)
            # NEW: Save manifest even in dry run
            manifest_pre = [os.path.relpath(c['path'], args.source_pdf_dir) for c in selected]
            save_session(args.password, manifest_pre, dry_run=True)
            return    
    print(f"\n{BOLD}{YELLOW}[HIDE]{NC} Injecting into {len(selected)} carriers...")
    selected.sort(key=lambda x: x['path'])
    manifest = perform_injection(selected, encrypted, args.source_pdf_dir, args.restore_pdf_dir)
    save_session(args.password, manifest)
    print(f"{GREEN}Success: {len(selected)} carriers utilized.{NC}")

def hide(args):
    # 1. Identity Setup
    if not args.password:
        args.password = generate_robust_password()
    
    # 2. Payload Preparation
    raw_payload = get_zip_memory(args.source_dir)
    if not raw_payload: 
        print(f"{RED}Error: No files found in {args.source_dir}{NC}")
        return
        
    encrypted = xor_crypt(raw_payload, args.password)
    
    # 3. Carrier Selection
    all_pdfs = get_sorted_files(args.source_pdf_dir, ".pdf")
    available, excluded = filter_carriers(all_pdfs, args.exclude_carrier_chars)
    
    # Use the correct argument name and pass the password for the shuffle
    selected, cap, reserves = select_carrier_pool(
        available, 
        len(encrypted), 
        args.carrier_size_max_incr, 
        args.max_carriers, 
        args.password
    )
    
    # 4. Capacity Guard
    check_capacity(cap, len(encrypted), available, args.carrier_size_max_incr)
    
    # 5. Execution or Audit
    if args.dry_run:
        run_dry_audit(selected, len(encrypted), args.carrier_size_max_incr, excluded, reserves)
        manifest_pre = [os.path.relpath(c['path'], args.source_pdf_dir) for c in selected]
        save_session(args.password, manifest_pre, dry_run=True)
        return    

    print(f"\n{BOLD}{YELLOW}[HIDE]{NC} Injecting into {len(selected)} carriers...")
    
    # Perform the actual binary injection
    manifest = perform_injection(selected, encrypted, args.source_pdf_dir, args.restore_pdf_dir)
    
    # 6. Session Persistence
    save_session(args.password, manifest)
    print(f"{GREEN}Success: {len(selected)} carriers utilized.{NC}")

def restore(args):
    # 1. Load saved session data (PWD_FILE and LIST_FILE)
    saved_pwd, manifest = load_session()
    
    # 2. Resolve Password: Priority (CLI Argument > Saved File)
    # We use 'args.password' if you typed it in the terminal, 
    # otherwise we use the password stored in pdf_pwd.txt.
    active_password = args.password or saved_pwd
    
    # 3. Defensive Check: If still no password, ask the user manually
    if not active_password:
        print(f"{YELLOW}[!] No password found in {PWD_FILE} or arguments.{NC}")
        active_password = input("🔑 Enter password to decrypt: ").strip()
    
    if not active_password:
        print(f"{RED}Error: Password is required for restoration. Aborting.{NC}")
        return

    if not manifest:
        print(f"{RED}Error: {LIST_FILE} not found. I don't know which PDFs to read.{NC}")
        return

    print(f"{BOLD}{YELLOW}[RESTORE]{NC} Reassembling data from {len(manifest)} carriers...")
    
    full_payload = b""
    try:
        # 4. Extract shards from PDF carriers
        for i, rel in enumerate(manifest, 1):
            path = os.path.join(args.restore_pdf_dir, rel)
            if not os.path.exists(path):
                print(f"\n{RED}[!] Missing carrier: {path}{NC}")
                continue
                
            with open(path, 'rb') as f:
                data = f.read()
                # Find the last standard PDF end-of-file marker
                pos = data.rfind(b'%%EOF')
                if pos != -1:
                    # Everything after %%EOF (plus the 5 bytes of the tag) is our payload
                    # We strip newlines to ensure clean binary concatenation
                    shard = data[pos+5:].lstrip(b'\r\n').lstrip(b'\n')
                    full_payload += shard
            
            draw_progress(i, len(manifest), prefix="  Reading   ")
        
        print("\n") # Break progress bar line

        # 5. Decrypt the full byte stream
        decrypted_zip = xor_crypt(full_payload, active_password)
        
        # 6. Decompress and restore files/folders
        with io.BytesIO(decrypted_zip) as mem_buf:
            with zipfile.ZipFile(mem_buf) as zf:
                os.makedirs(args.restore_dir, exist_ok=True)
                # namelist() includes both files and explicit directory entries
                items = zf.namelist()
                if not items:
                    print(f"{YELLOW}[!] ZIP archive appears to be empty.{NC}")
                    return

                for i, item in enumerate(items, 1):
                    # extract() automatically handles directory creation and file writing

                    # print(f"DEBUG: Extracting item -> '{item}'") # <--- Add this

                    zf.extract(item, args.restore_dir)
                    draw_progress(i, len(items), prefix="  Extracting")
        
        print(f"\n\n{BOLD}{GREEN}SUCCESS:{NC}")
        print(f" {BLUE}├─ Carriers:{NC} Read binary shards from '{args.restore_pdf_dir}'")
        print(f" {BLUE}└─ Payload:{NC}  Restored directory structure to '{args.restore_dir}'")

        # print(f"\n\n{BOLD}{GREEN}SUCCESS:{NC} Repository restored to '{args.restore_dir}'")

    except zipfile.BadZipFile:
        print(f"\n{RED}Error: Restoration failed.{NC}")
        print(f"{YELLOW}Reason: Decryption resulted in a corrupted ZIP. The password is likely incorrect.{NC}")
    except Exception as e:
        print(f"\n{RED}Error: An unexpected failure occurred: {e}{NC}")

def diff(args):
    _, manifest = load_session()
    
    # --- PART 1: CARRIER AUDIT ---
    print(f"\n{BOLD}{CYAN}[DIFF: CARRIER INTEGRITY]{NC}")
    if not manifest:
        print(f"  {YELLOW}No manifest found. Skipping carrier check.{NC}")
    else:
        for rel in manifest:
            src = os.path.join(args.source_pdf_dir, rel)
            dst = os.path.join(args.restore_pdf_dir, rel)
            if os.path.exists(dst) and os.path.exists(src):
                growth = os.stat(dst).st_size - os.stat(src).st_size
                print(f"  {rel:<45} | +{growth:<8} B | {GREEN}INJECTED{NC}")
            else:
                print(f"  {rel:<45} | {RED}MISSING FILE{NC}")

    # --- PART 2: PAYLOAD STRUCTURE AUDIT ---
    print(f"\n{BOLD}{YELLOW}[DIFF: PAYLOAD STRUCTURE]{NC}")
    
    def get_structure(base_path):
        struct = set()
        if not os.path.exists(base_path): return struct
        for root, dirs, files in os.walk(base_path):
            for name in dirs + files:
                rel_path = os.path.relpath(os.path.join(root, name), base_path)
                # Mark directories with a trailing slash to distinguish them
                if os.path.isdir(os.path.join(root, name)):
                    rel_path += "/"
                struct.add(rel_path)
        return struct

    source_set = get_structure(args.source_dir)
    restore_set = get_structure(args.restore_dir)
    
    all_paths = sorted(source_set | restore_set)
    if not all_paths:
        print(f"  {YELLOW}No payload data found to compare.{NC}")
        return

    for path in all_paths:
        is_dir = path.endswith("/")
        label = "[DIR] " if is_dir else "      "
        
        if path in source_set and path in restore_set:
            print(f"  {label}{path:<40} | {GREEN}MATCH{NC}")
        elif path in source_set:
            print(f"  {label}{path:<40} | {RED}MISSING IN RESTORE{NC}")
        else:
            print(f"  {label}{path:<40} | {YELLOW}EXTRA IN RESTORE{NC}")
            
def hash_check(args):
    print(f"\n{BOLD}{BLUE}[FILE & CARRIER INTEGRITY AUDIT]{NC}")
    
    # --- PART 1: PAYLOAD FILE HASHING ---
    print(f"\n{CYAN}Payload File Verification:{NC}")
    source_files = []
    for root, _, filenames in os.walk(args.source_dir):
        for f in filenames:
            source_files.append(os.path.join(root, f))
            
    if not source_files:
        print(f"  {YELLOW}No files found in {args.source_dir} to hash.{NC}")
    else:
        source_files.sort()
        matches, mismatches, missing = 0, 0, 0

        for p in source_files:
            rel = os.path.relpath(p, args.source_dir)
            dst = os.path.join(args.restore_dir, rel)
            
            h_o = get_file_hash(p)
            h_r = get_file_hash(dst)
            
            if not h_r:
                status = f"{RED}MISSING{NC}"
                missing += 1
                hash_display = "----------------"
            elif h_o == h_r:
                status = f"{GREEN}MATCH{NC}"
                matches += 1
                hash_display = h_r[:16]
            else:
                status = f"{RED}MISMATCH{NC}"
                mismatches += 1
                hash_display = h_r[:16]

            print(f"  [FILE] {hash_display}... | {rel:<45} | {status}")

        print(f"\n  {BOLD}Payload Summary:{NC} {GREEN}{matches} Matches{NC}, {RED}{mismatches} Mismatches{NC}, {RED}{missing} Missing{NC}")

    # --- PART 2: CARRIER INJECTION VERIFICATION ---
    _, manifest = load_session()
    if not manifest:
        print(f"\n{YELLOW}No manifest found. Skipping carrier check.{NC}")
    else:
        print(f"\n{CYAN}Carrier Injection Verification:{NC}")
        valid_carriers, empty_carriers = 0, 0
        
        for rel in manifest:
            src = os.path.join(args.source_pdf_dir, rel)
            dst = os.path.join(args.restore_pdf_dir, rel)
            
            if os.path.exists(src) and os.path.exists(dst):
                # Forensic check: Modified carrier must be larger than original
                orig_size = os.path.getsize(src)
                mod_size = os.path.getsize(dst)
                
                if mod_size > orig_size:
                    status = f"{GREEN}VALID (Injected){NC}"
                    valid_carriers += 1
                else:
                    status = f"{RED}EMPTY (Original){NC}"
                    empty_carriers += 1
                
                print(f"  [PDF]  {rel:<51} | {status}")
            else:
                print(f"  [PDF]  {rel:<51} | {RED}FILE MISSING{NC}")

        print(f"\n  {BOLD}Carrier Summary:{NC} {GREEN}{valid_carriers} Injected{NC}, {RED}{empty_carriers} Unmodified{NC}")

    if mismatches == 0 and missing == 0 and empty_carriers == 0:
        print(f"\n{BOLD}{GREEN}✓ ALL SYSTEMS NOMINAL: Forensic integrity confirmed.{NC}")

def main():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Steganography Suite{NC}\n"
                    "Securely shard, encrypt, and embed data payloads within PDF carriers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{YELLOW}Examples:{NC}
  python3 pdf_hide.py hide --max_carriers 5 -z 0.30
  python3 pdf_hide.py restore --password "MySecretKey"
        """
    )
    
    # 1. Payload & Identity
    p_group = parser.add_argument_group(f'{CYAN}Payload & Identity{NC}')
    p_group.add_argument("action", choices=['hide', 'restore', 'diff', 'hash'], 
                        help="Action to perform. (Choices: %(choices)s)")
    p_group.add_argument("password", nargs='?', default=None, 
                        help="Encryption key. Auto-generated if hiding and not provided.")
    p_group.add_argument("-s", "--source_dir", default="source_dir",
                        help="Directory containing sensitive files to hide. (Default: %(default)s)")
    p_group.add_argument("-r", "--restore_dir", default="restore_dir",
                        help="Directory to output restored files. (Default: %(default)s)")

    # 2. Carrier Configuration
    c_group = parser.add_argument_group(f'{CYAN}Carrier Configuration{NC}')
    c_group.add_argument("--source_pdf_dir", default="source_pdf_dir",
                        help="Directory containing legitimate cover PDFs. (Default: %(default)s)")
    c_group.add_argument("--restore_pdf_dir", default="restore_pdf_dir",
                        help="Directory to output modified PDFs. (Default: %(default)s)")
    c_group.add_argument("-m", "--max_carriers", type=int, default=1,
                        help="Max number of PDFs to use for sharding. (Default: %(default)s)")
    c_group.add_argument("-z", "--carrier_size_max_incr", type=float, default=0.30,
                        help="Max size increment per file (0.30 = 30%% growth). (Default: %(default)s)")
    c_group.add_argument("-x", "--exclude_carrier_chars", default="^+§",
                        help="Skip PDFs containing these characters. (Default: '%(default)s')")
    
    # 3. Operations
    o_group = parser.add_argument_group(f'{CYAN}Operations{NC}')
    o_group.add_argument("--dry_run", action="store_true",
                        help="Simulate the process without writing files. (Default: %(default)s)")

    args = parser.parse_args()
    
    # Mapping actions to their respective functions
    actions = {
        'hide': hide, 
        'restore': restore, 
        'diff': diff, 
        'hash': hash_check
    }
    
    # Execute selected action
    if args.action in actions:
        try:
            actions[args.action](args)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!] Operation cancelled by user.{NC}")
            sys.exit(1)
        except Exception as e:
            print(f"\n{RED}[!] Critical Error: {e}{NC}")
            sys.exit(1)

if __name__ == "__main__":
    main()