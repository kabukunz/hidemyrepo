import os
import sys
import hashlib
import argparse
import zipfile
import io
import math
import secrets
import string
import random
import glob
import logging
import json
from datetime import datetime
from itertools import cycle
import subprocess

# --- UI & Logging (Matches your baseline) ---
NC = '\033[0m'; BOLD = '\033[1m'; RED = '\033[0;31m'; GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'; BLUE = '\033[0;34m'; CYAN = '\033[0;36m'

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
    """Fast XOR implementation using bytearray and itertools."""
    if not password: 
        return data
    key = password.encode()
    # Using bytearray + zip is roughly 20x faster than a list comprehension
    return bytes(b ^ k for b, k in zip(data, cycle(key)))

def get_file_hash(path):
    """Calculates SHA-256 hash for forensic integrity verification."""
    if not os.path.exists(path): return None
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""): sha.update(chunk)
    return sha.hexdigest()

def save_session(args, password, manifest):
    """Persists steganography pipeline-critical keys and marked carrier lists."""
    try:
        with open(args.password_file, "w") as f: f.write(password)
        with open(args.carrier_file, "w") as f:
            for item in manifest: f.write(f"{item}\n")
        logging.info(f"{GREEN}{BOLD}[SAVED]{NC} Steganography pipeline manifest -> {args.carrier_file}")
        logging.info(f"{GREEN}{BOLD}[SAVED]{NC} Security key -> {args.password_file}")
    except Exception as e:
        logging.error(f"{RED}{BOLD}[ERROR]{NC} Failed to save session files: {e}")
        
def load_session(args):
    manifest = []
    password = None

    if os.path.exists("carrier.json"):
        try:
            with open("carrier.json", "r") as f:
                data = json.load(f)
                manifest = data.get("carriers", [])
                password = data.get("password") # Pull password from JSON
            logging.info(f"{GREEN}[LOAD]{NC} Session data retrieved from carrier.json")
        except Exception as e:
            logging.error(f"Failed to parse carrier.json: {e}")
    
    # Priority: Command line arg > JSON stored password
    active_pwd = args.password if args.password else password
    
    return active_pwd, manifest

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

def inject_copy_replace(src_path, dst_path, shard):
    """
    [Copy and Replace Hide Mode]
    Creates a new file entry in the destination directory to keep the source clean.
    """
    try:
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        with open(src_path, 'rb') as f:
            data = f.read()
        with open(dst_path, 'wb') as f:
            f.write(data)
            f.write(shard)
        return True
    except Exception as e:
        logging.error(f"Copy-Replace injection failed for {dst_path}: {e}")
        return False

def inject_in_place(target_path, shard):
    """Appends shard data to the end of a file without creating a copy."""
    try:
        with open(target_path, 'ab') as f:
            f.write(shard)
        return True
    except Exception as e:
        logging.error(f"In-place write failed for {target_path}: {e}")
        return False

def inject_to_carriers(shards, carrier_paths, output_json="carrier.json"):
    """
    Appends shards to PDFs in-place and maps exact byte offsets to a JSON manifest.
    """
    manifest = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "carriers": []
    }

    logging.info(f"\n{BOLD}--- [1] SURGICAL INJECTION ---{NC}")

    for i, shard_data in enumerate(shards):
        if i >= len(carrier_paths):
            break
            
        carrier_path = carrier_paths[i]
        file_name = os.path.basename(carrier_path)
        
        try:
            # 1. Get exact start position before writing (The end of original PDF)
            start_offset = os.path.getsize(carrier_path)
            
            # 2. Append shard to the carrier in binary mode
            with open(carrier_path, 'ab') as f:
                f.write(shard_data)
            
            # 3. Verify the payload size actually written
            end_offset = os.path.getsize(carrier_path)
            payload_size = end_offset - start_offset
            
            # 4. Record to manifest using relative name for portability
            manifest["carriers"].append({
                "file_name": file_name,
                "start_offset": start_offset,
                "payload_size": payload_size
            })
            
            logging.info(f"{GREEN}[+] Injected {payload_size} bytes -> {file_name}{NC}")

        except Exception as e:
            logging.error(f"{RED}[!] Failed to inject into {file_name}: {e}{NC}")

    # 5. Save the Master Map (carrier.json)
    with open(output_json, "w") as f:
        json.dump(manifest, f, indent=4)
    
    logging.info(f"\n{BOLD}SUCCESS:{NC} '{output_json}' generated with precision offsets.")

def get_macos_date_added(path):
    """Retrieves the macOS-specific Spotlight 'Date Added' metadata."""
    try:
        # Use mdls to get the kMDItemDateAdded
        cmd = ["mdls", "-name", "kMDItemDateAdded", "-raw", path]
        result = subprocess.check_output(cmd).decode().strip()
        return result if result != "(null)" else None
    except:
        return None    

def perform_injection(selected_pool, encrypted, active_password, args):
    """
    Orchestrates shard distribution and dispatches to the chosen mode.
    Now generates a surgical carrier.json manifest containing offsets and the password.
    """
    total_pool_bytes = sum(c['size'] for c in selected_pool)
    payload_len = len(encrypted)
    cursor, manifest_entries = 0, []
    
    # Capture the password being used for this session
    # Priority: Command line argument > saved password file
    active_password = args.password
    if not active_password and os.path.exists("pdf_pwd.txt"):
        with open("pdf_pwd.txt", "r") as f:
            active_password = f.read().strip()

    logging.info(f"\n{BOLD}--- [3] PERFORMING INJECTION ---{NC}")

    for i, c in enumerate(selected_pool, 1):
        # Determine the relative path for the manifest
        rel_path = os.path.relpath(c['path'], args.hide_carrier)
        
        if args.mark_carrier_chars:
            base, ext = os.path.splitext(rel_path)
            rel_path = f"{base}{args.mark_carrier_chars}{ext}"
            
        # Calculate shard size proportionally based on carrier capacity
        shard_size = math.floor((c['size'] / total_pool_bytes) * payload_len)
        shard = encrypted[cursor:] if i == len(selected_pool) else encrypted[cursor:cursor + shard_size]
        
        # 1. Capture the exact start position (Current end of file)
        # This is the "Surgical Address" for extraction
        start_offset = os.path.getsize(c['path'])

        # 1. Capture original forensic dates BEFORE modification
        st = os.stat(c['path'])

        # Capture macOS-specific Birthtime (Creation Date)
        # Default to mtime if birthtime isn't available (e.g., on some Linux systems)
        original_birth = getattr(st, 'st_birthtime', st.st_mtime)
        
        # 2. Mode Dispatcher
        if args.in_place:
            success = inject_in_place(c['path'], shard)
        else:
            dst = os.path.join(args.found_carrier, rel_path)
            success = inject_copy_replace(c['path'], dst, shard)
            
        if not success:
            logging.error(f"Pipeline failure at carrier: {c['path']}")
            sys.exit(1)

        # 3. Log the surgical metadata with all 4 dates
        manifest_entries.append({
            "file_name": rel_path,
            "start_offset": start_offset,
            "payload_size": len(shard),
            "meta": {
                "st_mtime": st.st_mtime,
                "st_atime": st.st_atime,
                "st_ctime": st.st_ctime,
                "st_birthtime": original_birth,
                # We save this to check for 'Sync' drift later
                "macos_added": get_macos_date_added(c['path']), 
                "injected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        })

        # Advance the byte cursor
        cursor += len(shard)
        draw_progress(i, len(selected_pool), prefix="  Injecting ")
    
    sys.stdout.write("\n")

    # 4. Finalize the Master Manifest (The Session Map)
    session_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "password": active_password,
        "mode": "in-place" if args.in_place else "copy-replace",
        "carriers": manifest_entries
    }

    with open("carrier.json", "w") as f:
        json.dump(session_data, f, indent=4)

    logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} carrier.json generated with offsets and password.")
    
    return manifest_entries

def hide(args):
    """Main workflow for carrier selection and binary embedding."""
    logging.info(f"\n{BLUE}{BOLD}--- [2] PAYLOAD HIDING ---{NC}")
    if not args.password: 
        args.password = generate_robust_password()
    
    raw_payload = get_zip_memory(args.hide_payload)
    if not raw_payload: return
        
    encrypted = xor_crypt(raw_payload, args.password)
    payload_size = len(encrypted)
    payload_mb = payload_size / (1024 * 1024)
    
    # --- Carrier Selection Logic ---
    exclude_carrier = set()
    exclude_log = []
    
    if args.exclude_carrier_file and os.path.exists(args.exclude_carrier_file):
        with open(args.exclude_carrier_file, 'r') as f:
            exclude_carrier = {os.path.basename(l.strip()) for l in f if l.strip()}

    all_pdfs = [os.path.join(r, f) for r, _, fs in os.walk(args.hide_carrier) for f in fs if f.lower().endswith(".pdf")]
    available = []

    for f in sorted(all_pdfs):
        fname = os.path.basename(f)
        char_match = any(c in fname for c in args.exclude_carrier_chars) if args.exclude_carrier_chars else False
        file_match = fname in exclude_carrier
        
        if char_match or file_match:
            exclude_log.append((fname, f"[{'exclude file' if file_match else ''}{' + ' if file_match and char_match else ''}{'exclude char' if char_match else ''}]"))
        else:
            available.append({'path': f, 'size': os.path.getsize(f)})

    if exclude_log:
        logging.info(f"{BLUE}{BOLD}[EXCLUDE]{NC} Skip list:")
        for fname, reason in exclude_log:
            logging.warning(f"  {YELLOW}[SKIP]{NC} {fname} {reason}")

    # Selection based on capacity
    selected, current_cap = [], 0
    for f in available:
        if len(selected) < args.max_carriers_number and current_cap < payload_size:
            selected.append(f)
            current_cap += int(f['size'] * args.max_carriers_size_incr)

    if current_cap < payload_size:
        logging.error(f"{RED}[ERROR]{NC} Insufficient capacity. Need {payload_mb:.2f} MB, have {current_cap/(1024*1024):.2f} MB.")
        sys.exit(1)

    # --- Renamed Mode Announcements ---
    if args.in_place:
        logging.warning(f"{YELLOW}{BOLD}[MODE]{NC} Running IN-PLACE hide.")
    else:
        logging.info(f"{CYAN}[MODE]{NC} Running COPY AND REPLACE hide.")

    # perform_injection handles the encryption storage and carrier.json creation
    perform_injection(selected, encrypted, args.password, args)

    # Stats...
    total_carrier_size = sum(c['size'] for c in selected)
    total_storage_mb = (total_carrier_size + len(encrypted)) / (1024 * 1024)
    avg_growth = (len(encrypted) / total_carrier_size) * 100 if total_carrier_size > 0 else 0
    
    logging.info(f"\n{GREEN}{BOLD}[STATS]{NC}")
    logging.info(f"  Payload Size:   {len(encrypted)/(1024*1024):.2f} MB")
    logging.info(f"  Carriers Used:  {len(selected)} files")
    logging.info(f"  Total Storage:  {total_storage_mb:.2f} MB")
    logging.info(f"  Avg. Growth:    {avg_growth:.2f}%")

def restore(args):
    """Reassembles shards and extracts content directly back to the source directory."""
    logging.info(f"\n{BLUE}{BOLD}--- [4] RESTORE PAYLOAD (IN-PLACE) ---{NC}")
    
    # 1. Load the session data
    _, manifest_data = load_session(args) 
    
    try:
        with open("carrier.json", "r") as f:
            session_json = json.load(f)
            active_password = session_json.get("password")
            mode = session_json.get("mode", "copy-replace")
            manifest = session_json.get("carriers", [])
    except FileNotFoundError:
        logging.error(f"{RED}[ERROR]{NC} carrier.json not found. Cannot restore.")
        return

    # Determine Destination: hide_payload instead of found_payload
    dest_dir = args.hide_payload
    
    # Safety Check: If the directory exists and has files, warn the user
    if os.path.exists(dest_dir) and os.listdir(dest_dir):
        logging.warning(f"{YELLOW}[WARN]{NC} Destination '{dest_dir}' is not empty.")
        confirm = input(f"{BOLD}Overwrite existing files in '{dest_dir}'? (y/n): {NC}")
        if confirm.lower() != 'y':
            logging.info("Restore cancelled.")
            return

    logging.info(f"{YELLOW}[RESTORE]{NC} Reassembling from {len(manifest)} carriers...")
    
    chunks = []
    try:
        for i, entry in enumerate(manifest, 1):
            rel_path = entry['file_name']
            
            # Use the mode from JSON to find where the carriers are
            if mode == "in-place":
                target_path = os.path.join(args.hide_carrier, rel_path)
            else:
                target_path = os.path.join(args.found_carrier, rel_path)
                
            with open(target_path, 'rb') as f:
                f.seek(entry['start_offset'])
                shard_data = f.read(entry['payload_size'])
                chunks.append(shard_data)
                
            draw_progress(i, len(manifest), prefix="  Reading   ")
        
        full_payload = b"".join(chunks)
        sys.stdout.write("\n\n")

        # 2. Decrypt
        decrypted_zip = xor_crypt(full_payload, active_password)
        
        # 3. Header Validation
        if not decrypted_zip.startswith(b'PK'):
            logging.error(f"{RED}[ERROR]{NC} Decryption failed. Invalid ZIP header.")
            return

        # 4. Extract IN-PLACE (to hide_payload)
        with io.BytesIO(decrypted_zip) as mem_buf:
            with zipfile.ZipFile(mem_buf) as zf:
                os.makedirs(dest_dir, exist_ok=True)
                items = zf.namelist()
                for i, item in enumerate(items, 1):
                    # Extract to the hide_payload directory
                    zf.extract(item, dest_dir)
                    draw_progress(i, len(items), prefix="  Extracting")
        
        sys.stdout.write("\n\n")
        logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} Data restored in-place to '{dest_dir}'")
        
    except Exception as e:
        logging.error(f"\n{RED}{BOLD}[ERROR]{NC} Restoration failed: {e}")

def diff(args):
    """Compares actual disk size against expected manifest size."""
    logging.info(f"\n{BLUE}{BOLD}--- [5] CARRIER DIFF ---{NC}")
    
    if not os.path.exists("carrier.json"):
        logging.warning(f"{YELLOW}[SKIP]{NC} No carrier.json found.")
        return

    with open("carrier.json", "r") as f:
        session_json = json.load(f)
        mode = session_json.get("mode", "copy-replace")
        manifest = session_json.get("carriers", [])

    header = f"{'CARRIER':<45} | {'GROWTH':<10} | {'STATUS'}"
    logging.info(f"\n{BOLD}{CYAN}{header}{NC}")
    logging.info("-" * len(header))
    
    for entry in manifest:
        rel = entry['file_name']
        target_dir = args.hide_carrier if mode == "in-place" else args.found_carrier
        path = os.path.join(target_dir, rel)

        if os.path.exists(path):
            current_size = os.path.getsize(path)
            # 'start_offset' is the size of the original file
            expected_size = entry['start_offset'] + entry['payload_size']
            
            if current_size == expected_size:
                status = f"{GREEN}INTEGRITY OK{NC}"
                growth = entry['payload_size']
            else:
                # This catches if the file was tampered with or corrupted
                diff_val = current_size - entry['start_offset']
                status = f"{RED}SIZE MISMATCH{NC} (Actual: +{diff_val}B)"
                growth = diff_val
        else:
            status = f"{RED}MISSING{NC}"
            growth = 0
            
        logging.info(f"  {rel:<45} | +{str(growth) + ' B':<10} | {status}")

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
    carriers.add_argument("--in-place", action="store_true", 
                          help="Modify carriers directly (Preserves Inode/File ID).")    

    args = parser.parse_args()
    actions = {'hide': hide, 'restore': restore, 'diff': diff, 'hash': hash, 'find': find}
    
    if args.action in actions:
        try: actions[args.action](args)
        except Exception as e: 
            logging.critical(f"{RED}{BOLD}[CRITICAL]{NC} {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main()