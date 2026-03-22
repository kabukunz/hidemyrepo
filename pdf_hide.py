import os
import sys
import hashlib
import argparse
import zipfile
import io
import math
import time
import secrets
import string
import random
import glob
import logging

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; RED = '\033[0;31m'; GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'; BLUE = '\033[0;34m'; CYAN = '\033[0;36m'

# --- Logging Configuration ---
# Standardizes output formatting to match your forensic audit trail look
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)

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
        logging.info(f"{GREEN}{BOLD}[SAVED]{NC} Mission manifest -> {args.carrier_file}")
        logging.info(f"{GREEN}{BOLD}[SAVED]{NC} Security key -> {args.password_file}")
    except Exception as e:
        logging.error(f"{RED}{BOLD}[ERROR]{NC} Failed to save session files: {e}")
        
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
    # Kept as sys.stdout to prevent logging module from breaking the carriage return (\r)
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

    logging.info(f"{BLUE}{BOLD}[ZIP]{NC} Compressing {len(all_paths)} items to memory...")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for i, path in enumerate(all_paths, 1):
            rel_path = os.path.relpath(path, hide_payload)
            if os.path.isdir(path):
                zf.writestr(zipfile.ZipInfo(rel_path + '/'), b'')
            else:
                zf.write(path, rel_path)
            draw_progress(i, len(all_paths), prefix="  Zipping   ")
    
    sys.stdout.write("\n") # Visual spacer after progress bar
    return buf.getvalue()

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
    
    sys.stdout.write("\n")
    return manifest_entries

def hide(args):
    """Main workflow for encrypting and embedding data."""
    logging.info(f"\n{BLUE}{BOLD}--- [2] PAYLOAD HIDING ---{NC}")
    if not args.password: args.password = generate_robust_password()
    
    raw_payload = get_zip_memory(args.hide_payload)
    if not raw_payload: 
        logging.error(f"{RED}{BOLD}[ERROR]{NC} No files found in {args.hide_payload}")
        return
        
    encrypted = xor_crypt(raw_payload, args.password)
    payload_size = len(encrypted)
    payload_mb = payload_size / (1024 * 1024)
    
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
        logging.info(f"{BLUE}{BOLD}[EXCLUDE]{NC} Exclude carriers:")
        for fname, reason in exclude_log:
            logging.warning(f"{YELLOW}{BOLD}[SKIP]{NC} {fname} {reason}")
        
        logging.info(f"{CYAN}{BOLD}[STATUS]{NC} Filtered {len(exclude_log)} carriers.\n")

    selected, current_cap = [], 0
    for f in available:
        if len(selected) < args.max_carriers_number and current_cap < payload_size:
            selected.append(f)
            current_cap += int(f['size'] * args.max_carriers_size_incr)

    if current_cap < payload_size:
        logging.error(f"{RED}{BOLD}[ERROR]{NC} Insufficient capacity. Need {payload_mb:.2f} MB, only have {current_cap/(1024*1024):.2f} MB.")
        sys.exit(1)

    status_msg = f"Injecting into {len(selected)} carriers..."
    if args.mark_carrier_chars:
        status_msg = f"Injecting and marking with '{args.mark_carrier_chars}'..."
    logging.info(f"{YELLOW}{BOLD}[HIDE]{NC} {status_msg}")

    manifest = perform_injection(selected, encrypted, args.hide_carrier, args.found_carrier, args.mark_carrier_chars)
    
    # Calculate Final Figures
    total_carrier_size = sum(c['size'] for c in selected)
    total_storage_mb = (total_carrier_size + payload_size) / (1024 * 1024)
    avg_growth = (payload_size / total_carrier_size) * 100 if total_carrier_size > 0 else 0
    
    save_session(args, args.password, manifest)

    # Detailed Status Output
    logging.info(f"\n{GREEN}{BOLD}[STATS]{NC}")
    logging.info(f"  {CYAN}Payload Size:{NC}   {payload_mb:.2f} MB")
    logging.info(f"  {CYAN}Carriers Used:{NC}  {len(selected)} files")
    logging.info(f"  {CYAN}Total Storage:{NC}  {total_storage_mb:.2f} MB")
    logging.info(f"  {CYAN}Avg. Growth:{NC}    {avg_growth:.2f}%")

def restore(args):
    """Reassembles shards and decrypts the hidden payload."""
    logging.info(f"\n{BLUE}{BOLD}--- [4] RESTORE PAYLOAD ---{NC}")
    saved_pwd, manifest = load_session(args)
    active_password = args.password or saved_pwd
    if not active_password or not manifest:
        logging.error(f"{RED}{BOLD}[ERROR]{NC} Missing password or manifest.")
        return

    logging.info(f"{YELLOW}{BOLD}[RESTORE]{NC} Reassembling from {len(manifest)} carriers...")
    full_payload = b""
    try:
        for i, rel in enumerate(manifest, 1):
            path = os.path.join(args.found_carrier, rel)
            if not os.path.exists(path):
                logging.error(f"{RED}{BOLD}[MISSING]{NC} {path}")
                continue
            with open(path, 'rb') as f:
                data = f.read(); pos = data.rfind(b'%%EOF')
                if pos != -1:
                    full_payload += data[pos+5:].lstrip(b'\r\n').lstrip(b'\n')
            draw_progress(i, len(manifest), prefix="  Reading   ")
        
        sys.stdout.write("\n\n")
        decrypted_zip = xor_crypt(full_payload, active_password)
        with io.BytesIO(decrypted_zip) as mem_buf:
            with zipfile.ZipFile(mem_buf) as zf:
                os.makedirs(args.found_payload, exist_ok=True)
                items = zf.namelist()
                for i, item in enumerate(items, 1):
                    zf.extract(item, args.found_payload)
                    draw_progress(i, len(items), prefix="  Extracting")
        
        sys.stdout.write("\n\n")
        logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} Restored to '{args.found_payload}'")
    except Exception as e:
        logging.error(f"{RED}{BOLD}[ERROR]{NC} Restoration failed: {e}")

def diff(args):
    """Compares file sizes across original and modified PDFs."""
    logging.info(f"\n{BLUE}{BOLD}--- [5] CARRIER DIFF ---{NC}")
    _, manifest = load_session(args)
    logging.info(f"\n{BOLD}{CYAN}[DIFF: CARRIER INTEGRITY]{NC}")
    if not manifest:
        logging.warning(f"{YELLOW}{BOLD}[SKIP]{NC} No manifest found.")
        return
    for rel in manifest:
        dst = os.path.join(args.found_carrier, rel)
        base, ext = os.path.splitext(rel)
        src_rel = rel
        if args.mark_carrier_chars and base.endswith(args.mark_carrier_chars):
             src_rel = f"{base[:-len(args.mark_carrier_chars)]}{ext}"
        
        src = os.path.join(args.hide_carrier, src_rel)
        status = f"{GREEN}INJECTED{NC}" if os.path.exists(dst) else f"{RED}MISSING{NC}"
        growth = os.path.getsize(dst) - os.path.getsize(src) if os.path.exists(dst) and os.path.exists(src) else 0
        logging.info(f"  {rel:<45} | +{growth:<8} B | {status}")

def hash(args):
    """Compares SHA-256 hashes of all payload files."""
    logging.info(f"\n{BLUE}{BOLD}--- [6] PAYLOAD HASH ---{NC}")
    logging.info(f"{BLUE}{BOLD}[AUDIT]{NC} Starting Integrity Audit...")
    source_files = sorted([os.path.join(r, f) for r, _, fs in os.walk(args.hide_payload) for f in fs])
    matches, mismatches, missing = 0, 0, 0
    for p in source_files:
        rel = os.path.relpath(p, args.hide_payload)
        h_o, h_r = get_file_hash(p), get_file_hash(os.path.join(args.found_payload, rel))
        if not h_r: status, missing = f"{RED}MISSING{NC}", missing + 1
        elif h_o == h_r: status, matches = f"{GREEN}MATCH{NC}", matches + 1
        else: status, mismatches = f"{RED}MISMATCH{NC}", mismatches + 1
        logging.info(f"  [FILE] {rel:<45} | {status}")
    logging.info(f"{CYAN}{BOLD}[STATUS]{NC} Matches: {matches}, Mismatches: {mismatches}, Missing: {missing}")

def find(args):
    """Scans for steganographic content marked by the carrier chars."""
    logging.info(f"\n{BLUE}{BOLD}--- [7] PAYLOAD FIND ---{NC}")
    target_dir = args.found_carrier
    _, manifest = load_session(args)
    manifest_set = set(manifest) if manifest else set()
    
    files = glob.glob(os.path.join(target_dir, "*.pdf"))
    stats = {"carriers": 0, "clean": 0}
    
    logging.info(f"\n{BOLD}{'FILENAME':<70} | {'STATUS':<20} | {'PAYLOAD'}{NC}")
    logging.info("-" * 110)
    for f_path in sorted(files):
        payload_size, fname = 0, os.path.basename(f_path)
        try:
            with open(f_path, 'rb') as f:
                data = f.read(); pos = data.rfind(b'%%EOF')
                if pos != -1: payload_size = len(data[pos+5:].strip())
        except: continue

        is_marked = args.mark_carrier_chars and os.path.splitext(fname)[0].endswith(args.mark_carrier_chars)
        if payload_size > 0 and (fname in manifest_set or is_marked):
            status = f"{GREEN}STEGO CARRIER{NC}"; stats["carriers"] += 1
        else:
            status = f"{BLUE}CLEAN PDF{NC}"; stats["clean"] += 1
            
        size_str = f"{payload_size:,} bytes" if payload_size > 0 else "---"
        logging.info(f"{fname[:70]:<70} | {status:<20} | {size_str}")

def main():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Steganography Suite{NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("action", choices=['hide', 'restore', 'diff', 'hash', 'find'], 
                        help="Action to perform: hide payload, restore it, or run forensic audits.")
    parser.add_argument("password", nargs='?', help="Manual password for XOR encryption/decryption (optional).")
    
    paths = parser.add_argument_group(f'{CYAN}Path Configuration{NC}')
    paths.add_argument("-hp", "--hide_payload", default="hide_payload", 
                       help="Directory containing payload to hide (Default: hide_payload).")
    paths.add_argument("-hc", "--hide_carrier", default="hide_carrier", 
                       help="Directory containing carriers for hiding payload (Default: hide_carrier).")
    paths.add_argument("-fp", "--found_payload", default="found_payload", 
                       help="Directory where hidden payload will be extracted (Default: found_payload).")
    paths.add_argument("-fc", "--found_carrier", default="found_carrier", 
                       help="Directory to save carriers with hidden payload (Default: found_carrier).")
    
    sessions = parser.add_argument_group(f'{CYAN}Session Tracking{NC}')
    sessions.add_argument("-cf", "--carrier_file", default="carrier.txt", help="Carriers file (Default: carrier.txt).")
    sessions.add_argument("-pf", "--password_file", default="password.txt", help="Password file (Default: password.txt).")    

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
        except Exception as e: 
            logging.critical(f"{RED}{BOLD}[CRITICAL]{NC} {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main()