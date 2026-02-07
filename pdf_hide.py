import os, sys, hashlib, argparse, zipfile, io, math, time, secrets, string, random, glob

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; RED = '\033[0;31m'; GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'; BLUE = '\033[0;34m'; CYAN = '\033[0;36m'
LIST_FILE = "pdf_files.txt"; PWD_FILE = "pdf_pwd.txt"

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

def save_session(password, manifest, dry_run=False):
    """Persists mission-critical keys and marked carrier lists."""
    try:
        with open(PWD_FILE, "w") as f: f.write(password)
        with open(LIST_FILE, "w") as f:
            for item in manifest: f.write(f"{item}\n")
        prefix = f"{YELLOW}[DRY RUN]{NC} " if dry_run else ""
        log("SAVED", f"{prefix}Mission manifest -> {LIST_FILE}", GREEN)
        log("SAVED", f"{prefix}Security key -> {PWD_FILE}", GREEN)
    except Exception as e:
        log("ERROR", f"Failed to save session files: {e}", RED)
        
def load_session():
    """Retrieves password and carrier list for reassembly/restoration."""
    pwd, manifest = None, []
    if os.path.exists(PWD_FILE):
        with open(PWD_FILE, "r") as f: pwd = f.read().strip()
    if os.path.exists(LIST_FILE):
        with open(LIST_FILE, "r") as f: manifest = [l.strip() for l in f if l.strip()]
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
def get_zip_memory(source_payload_dir):
    """Compresses a directory into a memory-buffered ZIP."""
    if not os.path.exists(source_payload_dir): return None
    all_paths = []
    for root, dirs, files in os.walk(source_payload_dir):
        for d in dirs: all_paths.append(os.path.join(root, d))
        for f in files: all_paths.append(os.path.join(root, f))
    if not all_paths: return None

    log("ZIP", f"Compressing {len(all_paths)} items to memory...", BLUE)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i, path in enumerate(all_paths, 1):
            rel_path = os.path.relpath(path, source_payload_dir)
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

def select_carrier_pool(files, payload_len, carrier_size_max_incr, max_count, password=None):
    """Shuffles and selects a subset of PDFs for shards."""
    pool = sorted(files, key=lambda x: x['path'].lower())
    if password: random.Random(password).shuffle(pool)
    selected, current_cap = [], 0
    for f in pool:
        limit = int(f['size'] * carrier_size_max_incr)
        if len(selected) < max_count and current_cap < payload_len:
            selected.append(f); current_cap += limit
    return selected, current_cap

# --- Core Actions ---
def perform_injection(selected_pool, encrypted, source_pdf_dir, restore_pdf_dir, mark_chars):
    """Splits binary payload and appends shards after %%EOF marker."""
    total_pool_bytes = sum(c['size'] for c in selected_pool)
    payload_len = len(encrypted)
    cursor, manifest_entries = 0, []
    for i, c in enumerate(selected_pool, 1):
        rel_path = os.path.relpath(c['path'], source_pdf_dir)
        
        # Apply markers if provided
        if mark_chars:
            base, ext = os.path.splitext(rel_path)
            rel_path = f"{base}{mark_chars}{ext}"
            
        manifest_entries.append(rel_path)
        dst = os.path.join(restore_pdf_dir, rel_path)
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
    
    raw_payload = get_zip_memory(args.source_payload_dir)
    if not raw_payload: 
        log("ERROR", f"No files found in {args.source_payload_dir}", RED); return
        
    encrypted = xor_crypt(raw_payload, args.password)
    payload_size = len(encrypted)
    payload_mb = payload_size / (1024 * 1024) # Conversion for display
    
    all_pdfs = [os.path.join(r, f) for r, _, fs in os.walk(args.source_pdf_dir) for f in fs if f.lower().endswith(".pdf")]
    available = []
    for f in sorted(all_pdfs):
        if not any(char in os.path.basename(f) for char in args.exclude_carrier_chars):
            available.append({'path': f, 'size': os.path.getsize(f)})

    selected, current_cap = [], 0
    for f in available:
        if len(selected) < args.max_carriers and current_cap < payload_size:
            selected.append(f)
            current_cap += int(f['size'] * args.carrier_size_max_incr)

    if current_cap < payload_size:
        log("ERROR", f"Insufficient capacity. Need {payload_mb:.2f} MB, only have {current_cap/(1024*1024):.2f} MB.", RED)
        sys.exit(1)

    status_msg = f"Injecting into {len(selected)} carriers..."
    if args.mark_carrier_chars:
        status_msg = f"Injecting and marking with '{args.mark_carrier_chars}'..."
    log("HIDE", status_msg, YELLOW)

    manifest = perform_injection(selected, encrypted, args.source_pdf_dir, args.restore_pdf_dir, args.mark_carrier_chars)
    
    # Calculate Final Figures
    total_carrier_size = sum(c['size'] for c in selected)
    total_storage_mb = (total_carrier_size + payload_size) / (1024 * 1024)
    avg_growth = (payload_size / total_carrier_size) * 100 if total_carrier_size > 0 else 0
    
    save_session(args.password, manifest)

    # Detailed Status Output
    print(f"\n{GREEN}{BOLD}[MISSION COMPLETE]{NC}")
    print(f"  {CYAN}Payload Size:{NC}   {payload_mb:.2f} MB")
    print(f"  {CYAN}Carriers Used:{NC}  {len(selected)} files")
    print(f"  {CYAN}Total Storage:{NC}  {total_storage_mb:.2f} MB")
    print(f"  {CYAN}Avg. Growth:{NC}    {avg_growth:.2f}%")

def restore(args):
    """Reassembles shards and decrypts the hidden payload."""
    print(f"\n{BLUE}{BOLD}--- [4] RESTORE PAYLOAD ---{NC}")
    saved_pwd, manifest = load_session()
    active_password = args.password or saved_pwd
    if not active_password or not manifest:
        log("ERROR", "Missing password or manifest.", RED); return

    log("RESTORE", f"Reassembling from {len(manifest)} carriers...", YELLOW)
    full_payload = b""
    try:
        for i, rel in enumerate(manifest, 1):
            path = os.path.join(args.restore_pdf_dir, rel)
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
                os.makedirs(args.restore_payload_dir, exist_ok=True)
                items = zf.namelist()
                for i, item in enumerate(items, 1):
                    zf.extract(item, args.restore_payload_dir)
                    draw_progress(i, len(items), prefix="  Extracting")
        print("\n"); log("SUCCESS", f"Restored to '{args.restore_payload_dir}'", GREEN)
    except Exception as e:
        log("ERROR", f"Restoration failed: {e}", RED)

def diff(args):
    """Compares file sizes across original and modified PDFs."""
    print(f"\n{BLUE}{BOLD}--- [5] CARRIER DIFF ---{NC}")
    _, manifest = load_session()
    print(f"\n{BOLD}{CYAN}[DIFF: CARRIER INTEGRITY]{NC}")
    if not manifest:
        log("SKIP", "No manifest found.", YELLOW)
        return
    for rel in manifest:
        dst = os.path.join(args.restore_pdf_dir, rel)
        # Attempt to find source by removing mark_chars if necessary
        base, ext = os.path.splitext(rel)
        src_rel = rel
        if args.mark_carrier_chars and base.endswith(args.mark_carrier_chars):
             src_rel = f"{base[:-len(args.mark_carrier_chars)]}{ext}"
        
        src = os.path.join(args.source_pdf_dir, src_rel)
        status = f"{GREEN}INJECTED{NC}" if os.path.exists(dst) else f"{RED}MISSING{NC}"
        growth = os.path.getsize(dst) - os.path.getsize(src) if os.path.exists(dst) and os.path.exists(src) else 0
        print(f"  {rel:<45} | +{growth:<8} B | {status}")

def hash(args):
    """Compares SHA-256 hashes of all payload files."""
    print(f"\n{BLUE}{BOLD}--- [6] PAYLOAD HASH ---{NC}")
    log("AUDIT", "Starting Integrity Audit...", BLUE)
    source_files = sorted([os.path.join(r, f) for r, _, fs in os.walk(args.source_payload_dir) for f in fs])
    matches, mismatches, missing = 0, 0, 0
    for p in source_files:
        rel = os.path.relpath(p, args.source_payload_dir)
        h_o, h_r = get_file_hash(p), get_file_hash(os.path.join(args.restore_payload_dir, rel))
        if not h_r: status, missing = f"{RED}MISSING{NC}", missing + 1
        elif h_o == h_r: status, matches = f"{GREEN}MATCH{NC}", matches + 1
        else: status, mismatches = f"{RED}MISMATCH{NC}", mismatches + 1
        print(f"  [FILE] {rel:<45} | {status}")
    log("STATUS", f"Matches: {matches}, Mismatches: {mismatches}, Missing: {missing}", CYAN)

def find(args):
    """Scans for steganographic content marked by the carrier chars."""
    print(f"\n{BLUE}{BOLD}--- [7] PAYLOAD FIND ---{NC}")
    target_dir = args.restore_pdf_dir
    _, manifest = load_session()
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
    paths.add_argument("-sp", "--source_payload_dir", default="source_payload_dir", 
                       help="Directory containing files to hide (Default: source_payload_dir).")
    paths.add_argument("-rp", "--restore_payload_dir", default="restore_payload_dir", 
                       help="Directory where files will be extracted (Default: restore_payload_dir).")
    paths.add_argument("-sd", "--source_pdf_dir", default="source_pdf_dir", 
                       help="Directory containing clean carrier PDFs (Default: source_pdf_dir).")
    paths.add_argument("-rd", "--restore_pdf_dir", default="restore_pdf_dir", 
                       help="Directory to save modified carrier PDFs (Default: restore_pdf_dir).")

    # Carrier Management
    carriers = parser.add_argument_group(f'{CYAN}Carrier Management{NC}')
    carriers.add_argument("-mc", "--max_carriers", type=int, default=50, 
                          help="Maximum number of carriers to utilize (Default: 50).")
    carriers.add_argument("-sc", "--carrier_size_max_incr", type=float, default=0.30, 
                          help="Allowed growth ratio per carrier (e.g., 0.15 for 15%%). (Default: 30%%)")
    carriers.add_argument("-xc", "--exclude_carrier_chars", default="^+§", 
                          help="Skip carriers with these characters in their filename (Default: ^+§).")
    carriers.add_argument("-kc", "--mark_carrier_chars", default="", 
                          help="Character(s) to append to the end of carrier filenames (Default: None).")

    args = parser.parse_args()
    actions = {'hide': hide, 'restore': restore, 'diff': diff, 'hash': hash, 'find': find}
    
    if args.action in actions:
        try: actions[args.action](args)
        except Exception as e: log("CRITICAL", str(e), RED); sys.exit(1)

if __name__ == "__main__":
    main()