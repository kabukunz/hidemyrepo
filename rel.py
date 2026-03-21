import os, sys, random, string, argparse, time, shutil

# --- UI Constants ---
NC = '\033[0m'       
BOLD = '\033[1m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
BLUE = '\033[0;34m'

def log(tag, message, color=NC):
    """Standardized timestamped logging."""
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
                    d_path = os.path.join(root, name)
                    if dry_run: log("DRY-RUN", f"Would rmdir: {d_path}", YELLOW)
                    else: os.rmdir(d_path)
            
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
    """Configures CLI for standard or forensic disposal with dynamic flags."""
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Suite Cleanup Tool (v1.6.1){NC}\n"
                    "Disposes of mission artifacts using shared flag logic.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("action", choices=['erase', 'secure'], 
                        help="Action: 'erase' (standard) or 'secure' (forensic shred).")

    # Path Configuration aligned with v1.6.1 Baselines
    paths = parser.add_argument_group(f'{CYAN}Path Configuration{NC}')
    paths.add_argument("-rp", "--found_payload", default="found_payload", help="Extraction target.")
    paths.add_argument("-rd", "--found_carrier", default="found_carrier", help="Modified carriers.")

    # Session Tracking aligned with v1.6.1 Baselines
    sessions = parser.add_argument_group(f'{CYAN}Session Tracking{NC}')
    sessions.add_argument("-cf", "--carrier_file", default="carrier.txt", help="Manifest to shred.")
    sessions.add_argument("-pf", "--password_file", default="password.txt", help="Key file to shred.")
    
    parser.add_argument("-d", "--dry-run", action="store_true", help="Show actions without executing.")

    return parser.parse_args()

if __name__ == "__main__":
    args = setup_args()
    
    print(f"\n{BLUE}{BOLD}--- [1] SESSION CLEANING ---{NC}")
    
    # Define the list of targets based on provided or default flags
    targets = [
        args.password_file,
        args.carrier_file,
        args.found_payload,
        args.found_carrier
    ]
    
    for target in targets:
        handle_path(target, args.action, args.dry_run)

    log("STATUS", "Session cleanup complete.", GREEN)import os, sys, hashlib, argparse, zipfile, io, math, time, secrets, string, random, glob

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; RED = '\033[0;31m'; GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'; BLUE = '\033[0;34m'; CYAN = '\033[0;36m'

def log(tag, message, color=NC):
    """Standardized timestamped logging for forensic audit trail."""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {color}{BOLD}[{tag}]{NC} {message}")

# --- Utility & Crypto Functions ---
def generate_robust_password(length=32):
    """Generates a high-entropy string for XOR key material."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def xor_crypt(data, password):
    """Symmetric XOR cipher; used for both encryption and decryption."""
    if not password: return data
    key = password.encode()
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def get_file_hash(path):
    """Calculates SHA-256 hash for forensic integrity verification."""
    if not os.path.exists(path): return None
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""): sha.update(chunk)
    return sha.hexdigest()

def save_session(args, password, manifest):
    """Persists mission-critical keys and marked carrier lists."""
    try:
        with open(args.password_file, "w") as f: f.write(password)
        with open(args.carrier_file, "w") as f:
            for item in manifest: f.write(f"{item}\n")
        log("SAVED", f"Mission manifest -> {args.carrier_file}", GREEN)
        log("SAVED", f"Security key -> {args.password_file}", GREEN)
    except Exception as e:
        log("ERROR", f"Failed to save session files: {e}", RED)
        
def load_session(args):
    """Retrieves password and carrier list for reassembly/restoration."""
    pwd, manifest = None, []
    if os.path.exists(args.password_file):
        with open(args.password_file, "r") as f: pwd = f.read().strip()
    if os.path.exists(args.carrier_file):
        with open(args.carrier_file, "r") as f: manifest = [l.strip() for l in f if l.strip()]
    return pwd, manifest

def draw_progress(current, total, prefix=""):
    """Renders a terminal progress bar for long-running binary operations."""
    if total <= 0: return
    bar_len = 40
    filled = int(bar_len * current // total)
    bar = ('█' * filled).ljust(bar_len)
    sys.stdout.write(f"\r{prefix} |{bar}| {int(100*current/total)}% ({current}/{total})")
    sys.stdout.flush()

# --- Binary Processing ---
def get_zip_memory(hide_payload):
    """Compresses a directory into a memory-buffered ZIP."""
    if not os.path.exists(hide_payload): return None
    all_paths = []
    for root, dirs, files in os.walk(hide_payload):
        for d in dirs: all_paths.append(os.path.join(root, d))
        for f in files: all_paths.append(os.path.join(root, f))
    if not all_paths: return None

    log("ZIP", f"Compressing {len(all_paths)} items to memory...", BLUE)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i, path in enumerate(all_paths, 1):
            rel_path = os.path.relpath(path, hide_payload)
            if os.path.isdir(path):
                zf.writestr(zipfile.ZipInfo(rel_path + '/'), b'')
            else:
                zf.write(path, rel_path)
            draw_progress(i, len(all_paths), prefix="  Zipping   ")
    print(); return buf.getvalue()

def get_sorted_files(directory, extension=None):
    """Gathers all files in a directory, optionally filtered by extension."""
    if not os.path.exists(directory): return []
    flist = []
    for root, _, files in os.walk(directory):
        for f in files:
            if extension and not f.lower().endswith(extension): continue
            flist.append(os.path.join(root, f))
    flist.sort(); return flist

def filter_carriers(all_pdfs, exclude_chars):
    """Filters carrier PDFs based on presence of forbidden characters."""
    available_pool, char_excluded = [], []
    for f in all_pdfs:
        fname = os.path.basename(f)
        if any(char in fname for char in exclude_chars):
            char_excluded.append(fname); continue
        available_pool.append({'path': f, 'size': os.path.getsize(f)})
    return available_pool, char_excluded

def select_carrier_pool(files, payload_len, max_carriers_size_incr, max_count, password=None):
    """Shuffles and selects a subset of PDFs for shards."""
    pool = sorted(files, key=lambda x: x['path'].lower())
    if password: random.Random(password).shuffle(pool)
    selected, current_cap = [], 0
    for f in pool:
        limit = int(f['size'] * max_carriers_size_incr)
        if len(selected) < max_count and current_cap < payload_len:
            selected.append(f); current_cap += limit
    return selected, current_cap

# --- Core Actions ---
def perform_injection(selected_pool, encrypted, hide_carrier, found_carrier, mark_chars):
    """Splits binary payload and appends shards after %%EOF marker."""
    total_pool_bytes = sum(c['size'] for c in selected_pool)
    payload_len = len(encrypted)
    cursor, manifest_entries = 0, []
    for i, c in enumerate(selected_pool, 1):
        rel_path = os.path.relpath(c['path'], hide_carrier)
        
        # Apply markers if provided
        if mark_chars:
            base, ext = os.path.splitext(rel_path)
            rel_path = f"{base}{mark_chars}{ext}"
            
        manifest_entries.append(rel_path)
        dst = os.path.join(found_carrier, rel_path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        
        shard_size = math.floor((c['size'] / total_pool_bytes) * payload_len)
        shard = encrypted[cursor:] if i == len(selected_pool) else encrypted[cursor:cursor + shard_size]
        cursor += len(shard)
        
        with open(c['path'], 'rb') as f: data = f.read()
        with open(dst, 'wb') as f:
            f.write(data); f.write(shard)
        draw_progress(i, len(selected_pool), prefix="  Injecting ")
    print(); return manifest_entries

def hide(args):
    """Main workflow for encrypting and embedding data."""
    print(f"\n{BLUE}{BOLD}--- [2] PAYLOAD HIDING ---{NC}")
    if not args.password: args.password = generate_robust_password()
    
    raw_payload = get_zip_memory(args.hide_payload)
    if not raw_payload: 
        log("ERROR", f"No files found in {args.hide_payload}", RED); return
        
    encrypted = xor_crypt(raw_payload, args.password)
    payload_size = len(encrypted)
    payload_mb = payload_size / (1024 * 1024) # Conversion for display
    
    # Load file-based blacklist only if requested
    exclude_carrier = set()
    exclude_log = []
    
    if args.exclude_carrier_file:
        if os.path.exists(args.exclude_carrier_file):
            with open(args.exclude_carrier_file, 'r') as f:
                exclude_carrier = {os.path.basename(l.strip()) for l in f if l.strip()}

    all_pdfs = [os.path.join(r, f) for r, _, fs in os.walk(args.hide_carrier) for f in fs if f.lower().endswith(".pdf")]
    available = []

    for f in sorted(all_pdfs):
        fname = os.path.basename(f)
        
        char_match = any(char in fname for char in args.exclude_carrier_chars) if args.exclude_carrier_chars else False
        file_match = fname in exclude_carrier
        
        if char_match or file_match:
            reasons = []
            if char_match or file_match:
                reasons.append("[")
            if file_match: reasons.append("exclude carrier")
            if char_match and file_match:
                reasons.append(" + ")
            if char_match: reasons.append(f"exclude char:({args.exclude_carrier_chars})")
            if char_match or file_match:
                reasons.append("]")
            exclude_log.append((fname, "".join(reasons)))
        else:
            available.append({'path': f, 'size': os.path.getsize(f)})

    if exclude_log:
        log("EXCLUDE", "Exclude carriers:", BLUE)
        for fname, reason in exclude_log:
            log("SKIP", f"{fname} {reason}", YELLOW)
        
        log("STATUS", f"Filtered {len(exclude_log)} carriers.", CYAN)
        print() # Visual spacer

    selected, current_cap = [], 0
    for f in available:
        if len(selected) < args.max_carriers_number and current_cap < payload_size:
            selected.append(f)
            current_cap += int(f['size'] * args.max_carriers_size_incr)

    if current_cap < payload_size:
        log("ERROR", f"Insufficient capacity. Need {payload_mb:.2f} MB, only have {current_cap/(1024*1024):.2f} MB.", RED)
        sys.exit(1)

    status_msg = f"Injecting into {len(selected)} carriers..."
    if args.mark_carrier_chars:
        status_msg = f"Injecting and marking with '{args.mark_carrier_chars}'..."
    log("HIDE", status_msg, YELLOW)

    manifest = perform_injection(selected, encrypted, args.hide_carrier, args.found_carrier, args.mark_carrier_chars)
    
    # Calculate Final Figures
    total_carrier_size = sum(c['size'] for c in selected)
    total_storage_mb = (total_carrier_size + payload_size) / (1024 * 1024)
    avg_growth = (payload_size / total_carrier_size) * 100 if total_carrier_size > 0 else 0
    
    save_session(args, args.password, manifest)

    # Detailed Status Output
    print(f"\n{GREEN}{BOLD}[STATS]{NC}")
    print(f"  {CYAN}Payload Size:{NC}   {payload_mb:.2f} MB")
    print(f"  {CYAN}Carriers Used:{NC}  {len(selected)} files")
    print(f"  {CYAN}Total Storage:{NC}  {total_storage_mb:.2f} MB")
    print(f"  {CYAN}Avg. Growth:{NC}    {avg_growth:.2f}%")

def restore(args):
    """Reassembles shards and decrypts the hidden payload."""
    print(f"\n{BLUE}{BOLD}--- [4] RESTORE PAYLOAD ---{NC}")
    saved_pwd, manifest = load_session(args)
    active_password = args.password or saved_pwd
    if not active_password or not manifest:
        log("ERROR", "Missing password or manifest.", RED); return

    log("RESTORE", f"Reassembling from {len(manifest)} carriers...", YELLOW)
    full_payload = b""
    try:
        for i, rel in enumerate(manifest, 1):
            path = os.path.join(args.found_carrier, rel)
            if not os.path.exists(path):
                log("MISSING", path, RED); continue
            with open(path, 'rb') as f:
                data = f.read(); pos = data.rfind(b'%%EOF')
                if pos != -1:
                    full_payload += data[pos+5:].lstrip(b'\r\n').lstrip(b'\n')
            draw_progress(i, len(manifest), prefix="  Reading   ")
        print("\n")
        decrypted_zip = xor_crypt(full_payload, active_password)
        with io.BytesIO(decrypted_zip) as mem_buf:
            with zipfile.ZipFile(mem_buf) as zf:
                os.makedirs(args.found_payload, exist_ok=True)
                items = zf.namelist()
                for i, item in enumerate(items, 1):
                    zf.extract(item, args.found_payload)
                    draw_progress(i, len(items), prefix="  Extracting")
        print("\n"); log("SUCCESS", f"Restored to '{args.found_payload}'", GREEN)
    except Exception as e:
        log("ERROR", f"Restoration failed: {e}", RED)

def diff(args):
    """Compares file sizes across original and modified PDFs."""
    print(f"\n{BLUE}{BOLD}--- [5] CARRIER DIFF ---{NC}")
    _, manifest = load_session(args)
    print(f"\n{BOLD}{CYAN}[DIFF: CARRIER INTEGRITY]{NC}")
    if not manifest:
        log("SKIP", "No manifest found.", YELLOW)
        return
    for rel in manifest:
        dst = os.path.join(args.found_carrier, rel)
        # Attempt to find source by removing mark_chars if necessary
        base, ext = os.path.splitext(rel)
        src_rel = rel
        if args.mark_carrier_chars and base.endswith(args.mark_carrier_chars):
             src_rel = f"{base[:-len(args.mark_carrier_chars)]}{ext}"
        
        src = os.path.join(args.hide_carrier, src_rel)
        status = f"{GREEN}INJECTED{NC}" if os.path.exists(dst) else f"{RED}MISSING{NC}"
        growth = os.path.getsize(dst) - os.path.getsize(src) if os.path.exists(dst) and os.path.exists(src) else 0
        print(f"  {rel:<45} | +{growth:<8} B | {status}")

def hash(args):
    """Compares SHA-256 hashes of all payload files."""
    print(f"\n{BLUE}{BOLD}--- [6] PAYLOAD HASH ---{NC}")
    log("AUDIT", "Starting Integrity Audit...", BLUE)
    source_files = sorted([os.path.join(r, f) for r, _, fs in os.walk(args.hide_payload) for f in fs])
    matches, mismatches, missing = 0, 0, 0
    for p in source_files:
        rel = os.path.relpath(p, args.hide_payload)
        h_o, h_r = get_file_hash(p), get_file_hash(os.path.join(args.found_payload, rel))
        if not h_r: status, missing = f"{RED}MISSING{NC}", missing + 1
        elif h_o == h_r: status, matches = f"{GREEN}MATCH{NC}", matches + 1
        else: status, mismatches = f"{RED}MISMATCH{NC}", mismatches + 1
        print(f"  [FILE] {rel:<45} | {status}")
    log("STATUS", f"Matches: {matches}, Mismatches: {mismatches}, Missing: {missing}", CYAN)

def find(args):
    """Scans for steganographic content marked by the carrier chars."""
    print(f"\n{BLUE}{BOLD}--- [7] PAYLOAD FIND ---{NC}")
    target_dir = args.found_carrier
    _, manifest = load_session(args)
    manifest_set = set(manifest) if manifest else set()
    
    files = glob.glob(os.path.join(target_dir, "*.pdf"))
    stats = {"carriers": 0, "clean": 0}
    
    print(f"\n{BOLD}{'FILENAME':<70} | {'STATUS':<20} | {'PAYLOAD'}{NC}")
    print("-" * 110)
    for f_path in sorted(files):
        payload_size, fname = 0, os.path.basename(f_path)
        try:
            with open(f_path, 'rb') as f:
                data = f.read(); pos = data.rfind(b'%%EOF')
                if pos != -1: payload_size = len(data[pos+5:].strip())
        except: continue

        # Identifies as carrier if in manifest OR if ends with mark_carrier_chars
        is_marked = args.mark_carrier_chars and os.path.splitext(fname)[0].endswith(args.mark_carrier_chars)
        if payload_size > 0 and (fname in manifest_set or is_marked):
            status = f"{GREEN}STEGO CARRIER{NC}"; stats["carriers"] += 1
        else:
            status = f"{BLUE}CLEAN PDF{NC}"; stats["clean"] += 1
            
        size_str = f"{payload_size:,} bytes" if payload_size > 0 else "---"
        print(f"{fname[:70]:<70} | {status:<20} | {size_str}")

def main():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Steganography Suite{NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Actions
    parser.add_argument("action", choices=['hide', 'restore', 'diff', 'hash', 'find'], 
                        help="Action to perform: hide payload, restore it, or run forensic audits.")
    parser.add_argument("password", nargs='?', help="Manual password for XOR encryption/decryption (optional).")
    
    # Path Configuration
    paths = parser.add_argument_group(f'{CYAN}Path Configuration{NC}')
    paths.add_argument("-hp", "--hide_payload", default="hide_payload", 
                       help="Directory containing payload to hide (Default: hide_payload).")
    paths.add_argument("-hc", "--hide_carrier", default="hide_carrier", 
                       help="Directory containing carriers for hiding payload (Default: hide_carrier).")
    paths.add_argument("-fp", "--found_payload", default="found_payload", 
                       help="Directory where hidden payload will be extracted (Default: found_payload).")
    paths.add_argument("-fc", "--found_carrier", default="found_carrier", 
                       help="Directory to save carriers with hidden payload (Default: found_carrier).")
    
    # Session Tracking
    sessions = parser.add_argument_group(f'{CYAN}Session Tracking{NC}')
    sessions.add_argument("-cf", "--carrier_file", default="carrier.txt", help="Carriers file (Default: carrier.txt).")
    sessions.add_argument("-pf", "--password_file", default="password.txt", help="Password file (Default: password.txt).")    

    # Carrier Management
    carriers = parser.add_argument_group(f'{CYAN}Carrier Management{NC}')
    carriers.add_argument("-mc", "--max_carriers_number", type=int, default=50, 
                          help="Maximum number of carriers to utilize (Default: 50).")
    carriers.add_argument("-sc", "--max_carriers_size_incr", type=float, default=0.30, 
                          help="Allowed growth ratio per carrier (e.g., 0.15 for 15%%). (Default: 30%%)")
    carriers.add_argument("-xc", "--exclude_carrier_chars", nargs='?', const="^+§", default=None,
                          help="Skip carriers with these characters (Usage: -xc [chars], Default: ^+§).")
    carriers.add_argument("-xf", "--exclude_carrier_file", nargs='?', const="exclude_carrier.txt", default=None,
                          help="Enable blacklist file. (Usage: -xf [filename], Default: exclude_carrier.txt).")
    carriers.add_argument("-kc", "--mark_carrier_chars", default="", 
                          help="Character(s) to append to the end of carrier filenames (Default: None).")

    args = parser.parse_args()
    actions = {'hide': hide, 'restore': restore, 'diff': diff, 'hash': hash, 'find': find}
    
    if args.action in actions:
        try: actions[args.action](args)
        except Exception as e: log("CRITICAL", str(e), RED); sys.exit(1)

if __name__ == "__main__":
    main()import os, sys, ctypes, struct, glob, subprocess, time, re, argparse

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; RED = '\033[0;31m'; GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'; BLUE = '\033[0;34m'; CYAN = '\033[0;36m'

def log(tag, message, color=NC):
    """Standardized timestamped logging."""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {color}{BOLD}[{tag}]{NC} {message}")

def get_meta(path):
    """Deep metadata extraction using macOS stat and xattr."""
    meta = {'added_raw': "", 'birth_raw': 0, 'mod_raw': 0, 'acc_raw': 0, 'size': 0}
    if not os.path.exists(path): return meta
    try:
        meta['birth_raw'] = int(subprocess.check_output(['stat', '-f', '%B', path]).decode().strip())
        meta['mod_raw'] = int(subprocess.check_output(['stat', '-f', '%m', path]).decode().strip())
        meta['acc_raw'] = int(subprocess.check_output(['stat', '-f', '%a', path]).decode().strip())
        meta['size'] = os.stat(path).st_size
        
        res_x = subprocess.run(['xattr', '-px', 'com.apple.metadata:kMDItemDateAdded', path], 
                               capture_output=True, text=True)
        if res_x.returncode == 0:
            meta['added_raw'] = res_x.stdout.strip().replace("\n", "").replace(" ", "")
    except: pass
    return meta

def sync(hide_carrier, found_carrier, file_list):
    """Safe-Sync: Forges timestamps and birth dates to match source carriers."""
    try:
        libc = ctypes.CDLL("/usr/lib/libc.dylib", use_errno=True)
    except OSError:
        log("ERROR", "libc.dylib not found. Creation date sync will fail.", RED)
        return

    print(f"\n{BLUE}{BOLD}--- [3] METADATA ALIGNMENT ---{NC}")
    log("INFO", f"Synchronizing timestamps and birth dates...", CYAN)

    for fname in file_list:
        dst = os.path.join(found_carrier, fname)
        src = os.path.join(hide_carrier, fname)
        
        if not os.path.exists(src) or not os.path.exists(dst): continue
        
        m_orig = get_meta(src)

        # STEP A: Native Python Timestamp Sync
        try:
            os.utime(dst, (m_orig['acc_raw'], m_orig['mod_raw']))
        except Exception as e:
            log("WARN", f"utime failed for {fname}: {e}", YELLOW)

        # STEP B: Kernel-Level Birth Date
        try:
            attr_list = struct.pack("HHHHH", 5, 0, 0x00000200, 0, 0)
            time_buf = struct.pack("qq", m_orig['birth_raw'], 0)
            libc.setattrlist(dst.encode(), attr_list, time_buf, len(time_buf), 0)
        except Exception as e:
            log("WARN", f"setattrlist failed for {fname}: {e}", YELLOW)
        
        log("SYNC", f"Timestamp alignment: {fname}", GREEN)

def audit(hide_carrier, found_carrier, file_list):
    """Forensic comparison report."""
    print(f"\n{BLUE}{BOLD}--- [7] TIMESTAMP SYNC ---{NC}")
    print(f"\n{BOLD}Forensic 4-Point Audit Report{NC}")
    print("-" * 90)
    for fname in sorted(file_list):
        s_path = os.path.join(found_carrier, fname)
        o_path = os.path.join(hide_carrier, fname)
        if not os.path.exists(o_path) or not os.path.exists(s_path): continue
        m_o, m_s = get_meta(o_path), get_meta(s_path)
        print(f"\n📄 {BOLD}{fname}{NC}")
        print(f"{'ATTRIBUTE':<12} | {'ORIGINAL':<22} | {'STEGO':<22} | STATUS")
        print("-" * 90)
        diff = m_s['size'] - m_o['size']
        print(f"{'SIZE':<12} | {str(m_o['size']):<22} | {str(m_s['size']):<22} | {GREEN}VALID (+{diff}B){NC}")
        for label, key in [('BIRTH', 'birth_raw'), ('MOD', 'mod_raw'), ('ACCESS', 'acc_raw')]:
            status = f"{GREEN}MATCH{NC}" if m_o[key] == m_s[key] else f"{RED}FAIL{NC}"
            print(f"{label:<12} | {str(m_o[key]):<22} | {str(m_s[key]):<22} | {status}")
        status_a = f"{GREEN}MATCH{NC}" if m_o['added_raw'] == m_s['added_raw'] else f"{RED}FAIL{NC}"
        print(f"{'ADDED':<12} | {'Present' if m_o['added_raw'] else 'Empty':<22} | {'Present' if m_s['added_raw'] else 'Empty':<22} | {status_a}")

def setup_args():
    """Configures the CLI with the final found_carrier=found_carrier defaults."""
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Metadata Sync Tool (macOS Edition){NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("action", choices=['sync', 'audit'], 
                        help="Action to perform: 'sync' or 'audit'.")

    paths = parser.add_argument_group(f'{CYAN}Path Configuration{NC}')
    paths.add_argument("-hc", "--hide_carrier", default="hide_carrier", 
                       help="Directory containing carriers for hiding payload (Default: hide_carrier).")
    paths.add_argument("-fc", "--found_carrier", default="found_carrier", 
                       help="Directory to save carriers with hidden payload (Default: found_carrier).")
    paths.add_argument("-cf", "--carrier_file", default="carrier.txt", help="Carriers file (Default: carrier.txt).")

    return parser.parse_args()

if __name__ == "__main__":
    args = setup_args()
    
    target_files = []
    mode_label = ""

    # Manifest Resolution
    if os.path.exists(args.carrier_file):
        with open(args.carrier_file, 'r') as f:
            target_files = [os.path.basename(l.strip()) for l in f if l.strip() and not l.startswith('#')]
        if target_files:
            mode_label = f"{CYAN}MANIFEST{NC} ({args.carrier_file})"
    
    # Directory Scan Fallback
    if not target_files:
        target_files = [os.path.basename(f) for f in glob.glob(os.path.join(args.found_carrier, "*.pdf"))]
        mode_label = f"{YELLOW}DIRECTORY SCAN{NC} ({args.found_carrier})"

    if not target_files:
        log("ERROR", f"No target files found in {args.found_carrier}.", RED)
        sys.exit(1)

    print(f"{BOLD}Selection Mode:{NC} {mode_label}")
    print(f"{BOLD}Files Found:{NC}    {len(target_files)}")
    print(f"{BOLD}Action:{NC}         {args.action.upper()}\n")

    if args.action == 'audit':
        audit(args.hide_carrier, args.found_carrier, target_files)
    else:
        sync(args.hide_carrier, args.found_carrier, target_files)