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
    """Persists mission-critical keys and carrier lists to local text files."""
    try:
        with open(PWD_FILE, "w") as f: f.write(password)
        with open(LIST_FILE, "w") as f:
            for item in manifest: f.write(f"{os.path.basename(item)}\n")
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

def get_zip_memory(source_dir):
    """Compresses a directory into a memory-buffered ZIP with full skeleton preservation."""
    if not os.path.exists(source_dir): return None
    all_paths = []
    for root, dirs, files in os.walk(source_dir):
        for d in dirs: all_paths.append(os.path.join(root, d))
        for f in files: all_paths.append(os.path.join(root, f))
    if not all_paths: return None

    log("ZIP", f"Compressing {len(all_paths)} items to memory...", BLUE)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i, path in enumerate(all_paths, 1):
            rel_path = os.path.relpath(path, source_dir)
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
    """Filters carrier PDFs based on presence of forbidden characters in filename."""
    available_pool, char_excluded = [], []
    for f in all_pdfs:
        fname = os.path.basename(f)
        if any(char in fname for char in exclude_chars):
            char_excluded.append(fname); continue
        available_pool.append({'path': f, 'size': os.path.getsize(f)})
    return available_pool, char_excluded

def select_carrier_pool(files, payload_len, carrier_size_max_incr, max_count, password=None):
    """Shuffles and selects a subset of PDFs capable of holding the payload shards."""
    pool = sorted(files, key=lambda x: x['path'].lower())
    if password: random.Random(password).shuffle(pool)
    selected, current_cap, reserves = [], 0, []
    for f in pool:
        limit = int(f['size'] * carrier_size_max_incr)
        if len(selected) < max_count and current_cap < payload_len:
            selected.append(f); current_cap += limit
        else:
            reserves.append(f)
    return selected, current_cap, reserves

def check_capacity(current_cap, payload_len, carrier_size_max_incr):
    """Ensures the selected PDF pool can accommodate the payload without excessive growth."""
    if current_cap < payload_len:
        needed_mb = ((payload_len - current_cap) / carrier_size_max_incr) / 1024 / 1024
        log("CAPACITY", f"Forensic failure. Add {needed_mb:.2f} MB more PDFs.", RED)
        sys.exit(1)

def run_dry_audit(selected_pool, payload_len, char_excluded):
    """Prints the projected steganographic growth for a proposed injection plan."""
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
    """Splits binary payload and appends shards after the %%EOF marker of each PDF."""
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
    print(); return manifest_entries

def hide(args):
    """Main workflow for encrypting and embedding data."""
    print(f"\n{BLUE}{BOLD}--- [2] PAYLOAD HIDING ---{NC}")
    if not args.password: args.password = generate_robust_password()
    raw_payload = get_zip_memory(args.source_dir)
    if not raw_payload: 
        log("ERROR", f"No files in {args.source_dir}", RED); return
    encrypted = xor_crypt(raw_payload, args.password)
    all_pdfs = get_sorted_files(args.source_pdf_dir, ".pdf")
    available, excluded = filter_carriers(all_pdfs, args.exclude_carrier_chars)
    selected, cap, reserves = select_carrier_pool(available, len(encrypted), args.carrier_size_max_incr, args.max_carriers, args.password)
    check_capacity(cap, len(encrypted), args.carrier_size_max_incr)
    
    if args.dry_run:
        run_dry_audit(selected, len(encrypted), excluded)
        save_session(args.password, [os.path.relpath(c['path'], args.source_pdf_dir) for c in selected], dry_run=True)
        return    

    log("HIDE", f"Injecting into {len(selected)} carriers...", YELLOW)
    manifest = perform_injection(selected, encrypted, args.source_pdf_dir, args.restore_pdf_dir)
    
    save_session(args.password, manifest)
    log("STATUS", f"Success: {len(selected)} carriers utilized.", GREEN)

def restore(args):
    """Main workflow for reassembling shards and decrypting the hidden payload."""
    print(f"\n{BLUE}{BOLD}--- [4] RESTORE PAYLOAD ---{NC}")
    saved_pwd, manifest = load_session()
    active_password = args.password or saved_pwd
    if not active_password: active_password = input("🔑 Enter password: ").strip()
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
                os.makedirs(args.restore_dir, exist_ok=True)
                items = zf.namelist()
                for i, item in enumerate(items, 1):
                    zf.extract(item, args.restore_dir)
                    draw_progress(i, len(items), prefix="  Extracting")
        print("\n"); log("SUCCESS", f"Restored structure to '{args.restore_dir}'", GREEN)
    except Exception as e:
        log("ERROR", f"Restoration failed: {e}", RED)

def diff(args):
    """Compares file existence and size growth across original and modified PDFs."""
    print(f"\n{BLUE}{BOLD}--- [5] CARRIER DIFF ---{NC}")
    _, manifest = load_session()
    print(f"\n{BOLD}{CYAN}[DIFF: CARRIER INTEGRITY]{NC}")
    if not manifest:
        log("SKIP", "No manifest found.", YELLOW)
    else:
        for rel in manifest:
            src, dst = os.path.join(args.source_pdf_dir, rel), os.path.join(args.restore_pdf_dir, rel)
            status = f"{GREEN}INJECTED{NC}" if os.path.exists(dst) else f"{RED}MISSING{NC}"
            growth = os.stat(dst).st_size - os.stat(src).st_size if os.path.exists(dst) else 0
            print(f"  {rel:<45} | +{growth:<8} B | {status}")

def hash(args):
    """Performs deep forensic audit by comparing SHA-256 hashes of all payload files."""
    print(f"\n{BLUE}{BOLD}--- [6] PAYLOAD HASH ---{NC}")
    log("AUDIT", "Starting Integrity Audit...", BLUE)
    source_files = sorted([os.path.join(r, f) for r, _, fs in os.walk(args.source_dir) for f in fs])
    matches, mismatches, missing = 0, 0, 0
    for p in source_files:
        rel = os.path.relpath(p, args.source_dir)
        h_o, h_r = get_file_hash(p), get_file_hash(os.path.join(args.restore_dir, rel))
        if not h_r: status, missing = f"{RED}MISSING{NC}", missing + 1
        elif h_o == h_r: status, matches = f"{GREEN}MATCH{NC}", matches + 1
        else: status, mismatches = f"{RED}MISMATCH{NC}", mismatches + 1
        print(f"  [FILE] {rel:<45} | {status}")
    log("STATUS", f"Matches: {matches}, Mismatches: {mismatches}, Missing: {missing}", CYAN)

def find(args):
    """Scans for steganographic content appended after %%EOF."""
    print(f"\n{BLUE}{BOLD}--- [7] PAYLOAD FIND ---{NC}")
    target_dir = args.restore_pdf_dir
    _, manifest = load_session()
    manifest_set = set(manifest) if manifest else set()
    
    log("SCAN", f"Scanning directory: {target_dir}", CYAN)
    files = glob.glob(os.path.join(target_dir, "*.pdf"))
    
    # Counters for summary
    stats = {"carriers": 0, "clean": 0}
    
    print(f"\n{BOLD}{'FILENAME':<70} | {'STATUS':<20} | {'PAYLOAD'}{NC}")
    print("-" * 110)
    
    for f_path in sorted(files):
        if os.path.isdir(f_path): continue
        payload_size = 0
        fname = os.path.basename(f_path)
        
        try:
            with open(f_path, 'rb') as f:
                data = f.read()
                pos = data.rfind(b'%%EOF')
                if pos != -1:
                    payload_size = len(data[pos+5:].strip())
        except: continue

        if payload_size > 0:
            if fname in manifest_set:
                status = f"{GREEN}STEGO CARRIER{NC}"
                stats["carriers"] += 1
        else:
            status = f"{BLUE}CLEAN PDF{NC}"
            stats["clean"] += 1
            
        display_name = (fname[:67] + '..') if len(fname) > 70 else fname
        size_str = f"{payload_size:,} bytes" if payload_size > 0 else "---"
        print(f"{display_name:<70} | {status:<20} | {size_str}")

    # Summary Audit
    print("-" * 110)
    log("SUMMARY", f"Total Files Scanned: {len(files)}", CYAN)
    print(f"  > {GREEN}Stego Carriers{NC}: {stats['carriers']}")
    print(f"  > {BLUE}Clean PDFs    {NC}: {stats['clean']}")
    print("-" * 110)

    print(f"\n{CYAN}Scan complete.{NC}")

def main():
    """CLI configuration and action dispatcher."""
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Steganography Suite{NC}", 
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='Show this help message and exit.')

    p_group = parser.add_argument_group(f'{CYAN}Payload & Identity{NC}')
    p_group.add_argument("action", nargs='?', choices=['hide', 'restore', 'diff', 'hash', 'find'])
    p_group.add_argument("password", nargs='?', default=None)
    p_group.add_argument("-s", "--source_dir", default="source_dir")
    p_group.add_argument("-r", "--restore_dir", default="restore_dir")

    c_group = parser.add_argument_group(f'{CYAN}Carrier Configuration{NC}')
    c_group.add_argument("--source_pdf_dir", default="source_pdf_dir")
    c_group.add_argument("--restore_pdf_dir", default="restore_pdf_dir")
    c_group.add_argument("-m", "--max_carriers", type=int, default=50)
    c_group.add_argument("-z", "--carrier_size_max_incr", type=float, default=0.30)
    c_group.add_argument("-x", "--exclude_carrier_chars", default="^+§")
    
    parser.add_argument("--dry_run", action="store_true")
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr); sys.exit(1)

    args = parser.parse_args()
    actions = {'hide': hide, 'restore': restore, 'diff': diff, 'hash': hash, 'find': find}
    
    if args.action in actions:
        try: actions[args.action](args)
        except KeyboardInterrupt: sys.exit(1)
        except Exception as e: log("CRITICAL", str(e), RED); sys.exit(1)

if __name__ == "__main__":
    main()