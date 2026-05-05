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
import logging
import json
from datetime import datetime
from itertools import cycle
import subprocess
import ctypes
import struct
import shutil

__version__ = "2.0.1"

# 1. Get the current terminal width
# fallback=(80, 24) ensures it works even if redirected to a pipe
term_width, _ = shutil.get_terminal_size(fallback=(80, 24))

# 2. Subtract the "Fixed" costs
# Logging prefix "[HH:MM:SS] [INFO] " is ~20 chars
# Separators and Status columns take ~30 chars
fixed_overhead = 50 

# 3. Calculate dynamic max
LOG_MAX_FNAME = max(20, term_width - fixed_overhead)

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

def get_current_meta(path):
    """Retrieves current on-disk metadata for auditing."""
    # We initialize with 0/False so the Audit table has values to compare even on failure
    meta = {'birth': 0, 'mod': 0, 'acc': 0, 'size': 0, 'added': None}
    if not os.path.exists(path): 
        return meta
        
    try:
        st = os.stat(path)
        # Using int() to match your Audit table logic
        meta['birth'] = int(getattr(st, 'st_birthtime', st.st_mtime))
        meta['mod'] = int(st.st_mtime)
        meta['acc'] = int(st.st_atime)
        meta['size'] = st.st_size
        
        # Pull the actual date string/timestamp instead of just a True/False
        meta['added'] = get_macos_date_added(path)
    except Exception:
        pass
    return meta    

def get_macos_date_added(path):
    """Retrieves the macOS-specific Spotlight 'Date Added' metadata."""
    try:
        # mdls is more reliable than xattr for Spotlight metadata
        cmd = ["mdls", "-name", "kMDItemDateAdded", "-raw", path]
        result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
        return result if result and result != "(null)" else None
    except Exception:
        return None

def perform_injection(selected_pool, encrypted, active_password, args):
    """
    Orchestrates shard distribution and dispatches to the chosen mode.
    Updated to include forensic shard hashing for integrity audits.
    """
    total_pool_bytes = sum(c['size'] for c in selected_pool)
    payload_len = len(encrypted)
    cursor, manifest_entries = 0, []
    
    # Capture the password being used for this session
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
            
        # Calculate shard size proportionally
        shard_size = math.floor((c['size'] / total_pool_bytes) * payload_len)
        shard = encrypted[cursor:] if i == len(selected_pool) else encrypted[cursor:cursor + shard_size]
        
        # --- NEW: Forensic Shard Hash ---
        # Generate hash of the shard BEFORE injection for future audits
        shard_hash = hashlib.sha256(shard).hexdigest()[:16] # 16-char fingerprint

        # 1. Capture the exact start position (Current end of file)
        start_offset = os.path.getsize(c['path'])

        # 1. Capture original forensic dates BEFORE modification
        st = os.stat(c['path'])
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

        # 3. Log metadata including the shard_hash
        manifest_entries.append({
            "file_name": rel_path,
            "start_offset": start_offset,
            "payload_size": len(shard),
            "shard_hash": shard_hash,  # <--- Added for [6] PAYLOAD HASH
            "meta": {
                "st_mtime": st.st_mtime,
                "st_atime": st.st_atime,
                "st_ctime": st.st_ctime,
                "st_birthtime": original_birth,
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

    logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} carrier.json generated with offsets, hashes, and password.")
    
    return manifest_entries

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

def erase_path(path, action):
    """Dispatches to shredder or standard remover without dry-run overhead."""
    if not os.path.exists(path):
        return 

    if os.path.isfile(path):
        if action == 'secure':
            if secure_shred_file(path):
                logging.info(f"{GREEN}{BOLD}[SECURE]{NC} Shredded: {path}")
        else:
            os.remove(path)
            logging.info(f"{GREEN}{BOLD}[ERASE]{NC} Removed: {path}")
            
    elif os.path.isdir(path):
        if action == 'secure':
            logging.info(f"{CYAN}{BOLD}[INFO]{NC} Shredding directory tree: {path}")
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    secure_shred_file(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            
            os.rmdir(path)
            logging.info(f"{GREEN}{BOLD}[SECURE]{NC} Tree shredded: {path}")
        else:
            shutil.rmtree(path)
            logging.info(f"{GREEN}{BOLD}[ERASE]{NC} Tree removed: {path}")

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
            # CAPTURE METADATA BEFORE INJECTION
            available.append({
                'path': f, 
                'size': os.path.getsize(f),
                'pre_meta': get_current_meta(f) # Store forensic dates now
            })

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

    # --- Mode Announcements ---
    if args.in_place:
        logging.warning(f"{YELLOW}{BOLD}[MODE]{NC} Running IN-PLACE hide.")
    else:
        logging.info(f"{CYAN}[MODE]{NC} Running COPY AND REPLACE hide.")

    # perform_injection now needs the 'pre_meta' to save to carrier.json
    perform_injection(selected, encrypted, args.password, args)

    # 3. Stats and Final Reporting
    total_carrier_size = sum(c['size'] for c in selected)
    total_storage_mb = (total_carrier_size + len(encrypted)) / (1024 * 1024)
    avg_growth = (len(encrypted) / total_carrier_size) * 100 if total_carrier_size > 0 else 0
    
    logging.info(f"\n{GREEN}{BOLD}[STATS]{NC}")
    logging.info(f"  Payload Size:   {len(encrypted)/(1024*1024):.2f} MB")
    logging.info(f"  Carriers Used:  {len(selected)} files")
    logging.info(f"  Total Storage:  {total_storage_mb:.2f} MB")
    logging.info(f"  Avg. Growth:    {avg_growth:.2f}%")
    logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} Hide applied successfully.")
    logging.info(f"{CYAN}[INFO]{NC} Run 'sync' to apply forensic timestamps.")

def restore(args):
    """Reassembles shards and extracts content directly back to the source directory."""
    logging.info(f"\n{BLUE}{BOLD}--- [4] RESTORE PAYLOAD (IN-PLACE) ---{NC}")
    
    # 1. Load the session data
    try:
        with open(args.json_file, "r") as f: # Use args.json_file instead of hardcoded string
            session_json = json.load(f)
            active_password = session_json.get("password")
            mode = session_json.get("mode", "in-place")
            manifest = session_json.get("carriers", [])
    except FileNotFoundError:
        logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found. Cannot restore.")
        return

    # Determine Destination: hide_payload (Source of Truth)
    dest_dir = args.hide_payload
    
    # --- v2.0.0 OVERWRITE LOGIC ---
    # We default to overwriting. We only prompt if --no-overwrite is True.
    if os.path.exists(dest_dir) and os.listdir(dest_dir):
        if getattr(args, 'no_overwrite', False): # Check for the safety flag
            logging.warning(f"{YELLOW}[WARN]{NC} Destination '{dest_dir}' is not empty.")
            confirm = input(f"{BOLD}Overwrite existing files in '{dest_dir}'? (y/n): {NC}")
            if confirm.lower() != 'y':
                logging.info("Restore cancelled by user.")
                return
        else:
            # Default behavior: Quietly proceed
            logging.debug(f"Overwriting content in {dest_dir} (v2.0.0 Default)")

    logging.info(f"{YELLOW}[RESTORE]{NC} Reassembling from {len(manifest)} carriers...")
    
    chunks = []
    try:
        for i, entry in enumerate(manifest, 1):
            rel_path = entry['file_name']
            
            # Find carriers based on session mode
            target_dir = args.hide_carrier if mode == "in-place" else args.found_carrier
            target_path = os.path.join(target_dir, rel_path)
                
            if not os.path.exists(target_path):
                raise FileNotFoundError(f"Carrier missing: {rel_path}")

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
            logging.error(f"{RED}[ERROR]{NC} Decryption failed. Invalid ZIP header (check password).")
            return

        # 4. Extract IN-PLACE
        with io.BytesIO(decrypted_zip) as mem_buf:
            with zipfile.ZipFile(mem_buf) as zf:
                os.makedirs(dest_dir, exist_ok=True)
                items = zf.namelist()
                for i, item in enumerate(items, 1):
                    # zf.extract handles overwriting existing files by default
                    zf.extract(item, dest_dir)
                    draw_progress(i, len(items), prefix="  Extracting")
        
        sys.stdout.write("\n\n")
        logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} Data restored in-place to '{dest_dir}'")
        
    except Exception as e:
        logging.error(f"\n{RED}{BOLD}[ERROR]{NC} Restoration failed: {e}")

def sync(args):
    """Aligns disk timestamps with JSON-stored forensic dates."""
    logging.info(f"\n{BLUE}{BOLD}--- [3] DATES ALIGNMENT ---{NC}")
    
    if not os.path.exists(args.json_file):
        logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found.")
        return

    with open(args.json_file, "r") as f:
        data = json.load(f)
        manifest = data.get("carriers", [])
        mode = data.get("mode", "in-place")

    # Define target_dir early to avoid unbound errors
    target_dir = args.hide_carrier if mode == "in-place" else args.found_carrier
    
    if not os.path.exists(target_dir):
        logging.error(f"{RED}[ERROR]{NC} Target directory {target_dir} does not exist.")
        return

    # Load libc for macOS birthtime (creation date) support
    try:
        libc = ctypes.CDLL("/usr/lib/libc.dylib", use_errno=True)
    except OSError:
        logging.error(f"{RED}[CRITICAL]{NC} libc.dylib missing. Birth date sync unavailable.")
        return

    with open(args.json_file, "r") as f:
        data = json.load(f)
        manifest = data.get("carriers", [])
        mode = data.get("mode", "in-place")
        # Grab the session timestamp to back-date the folder later
        session_ts = data.get("timestamp") 

    logging.info(f"{CYAN}[INFO]{NC} Processing {len(manifest)} carriers from session ({mode})...")

    for entry in manifest:
        fname = entry['file_name']
        meta = entry.get('meta', {})
        
        target_dir = args.hide_carrier if mode == "in-place" else args.found_carrier
        path = os.path.join(target_dir, fname)

        if not os.path.exists(path):
            logging.warning(f"  {YELLOW}[SKIP]{NC} Missing: {fname}")
            continue

        # 1. Standard utime (Modification/Access)
        # Check both naming conventions for safety
        m_time = int(meta.get('st_mtime') or meta.get('mod', 0))
        a_time = int(meta.get('st_atime') or meta.get('acc', 0))
        
        if m_time > 0:
            os.utime(path, (a_time, m_time))

        # 2. Kernel-Level Birth Date (Creation)
        # Check both naming conventions
        b_time = int(meta.get('st_birthtime') or meta.get('birth', 0))
        if b_time > 0:
            try:
                # ATTR_CMN_CRTIME = 0x00000200
                attr_list = struct.pack("HHHHH", 5, 0, 0x00000200, 0, 0)
                time_buf = struct.pack("qq", b_time, 0)
                libc.setattrlist(path.encode(), attr_list, time_buf, len(time_buf), 0)
            except Exception as e:
                logging.debug(f"Birthdate fail for {fname}: {e}")

        # 3. Wipe macOS Extended Attributes (Clears 'Date Added' and 'Where From')
        if sys.platform == "darwin":
            # -c clears all xattrs, which is the most forensic approach
            subprocess.run(['xattr', '-c', path], capture_output=True)

        logging.info(f"  {GREEN}[SYNCED]{NC} {fname}")

    # 4. Final Touch: Back-date the parent directory
    try:
        # Pull mtimes from manifest to find the "oldest" relevant date
        all_mtimes = [int(e['meta'].get('st_mtime') or e['meta'].get('mod', 0)) 
                      for e in manifest if e.get('meta')]
        
        if all_mtimes:
            # Using the minimum (oldest) mtime to ensure the folder looks 'untouched'
            back_date = min(all_mtimes)
            os.utime(target_dir, (back_date, back_date))
            logging.info(f"{CYAN}[INFO]{NC} Parent directory timestamps reset.")
    except Exception as e:
        logging.debug(f"Parent directory sync failed: {e}")

def audit(args):
    """Forensic comparison report between JSON manifest and current disk state."""
    logging.info(f"\n{BLUE}{BOLD}--- [7] DATES AUDIT ---{NC}")
    
    if not os.path.exists(args.json_file):
        logging.error(f"{RED}[ERROR]{NC} {args.json_file} missing.")
        return
    
    try:
        with open(args.json_file, "r") as f:
            data = json.load(f)
            manifest = data.get("carriers", [])
            mode = data.get("mode", "in-place")
            target_dir = args.hide_carrier if mode == "in-place" else args.found_carrier
    except Exception as e:
        logging.error(f"{RED}[ERROR]{NC} Failed to parse manifest: {e}")
        return

    if not manifest: 
        logging.warning(f"{YELLOW}[SKIP]{NC} Manifest is empty.")
        return

    # v2.0.0 Constraints: Standardize table width for logging clarity
    max_found_len = max(len(entry['file_name']) for entry in manifest)
    col_w = min(max_found_len, LOG_MAX_FNAME)

    logging.info(f"{CYAN}[INFO]{NC} Auditing {len(manifest)} carriers ({mode})...")

    # --- Header Formatting ---
    # Spaces added to MOD/ACC to center headers over 5-char MATCH/FAIL results
    header = f"{'CARRIER FILE':<{col_w}} | {'BIRTH':^5} | {' MOD ':^5} | {' ACC ':^5} | {'ADDED':^5}"
    separator = "-" * len(header)
    
    logging.info(f"{BOLD}{header}{NC}")
    logging.info(separator)

    for entry in manifest:
        raw_fname = entry['file_name']
        meta_j = entry.get('meta', {})
        
        # Display Truncation: "very_long_filename_from_2022.pdf" -> "very_long_filename_from_20... "
        if len(raw_fname) > LOG_MAX_FNAME:
            display_name = raw_fname[:LOG_MAX_FNAME-3] + "..."
        else:
            display_name = raw_fname

        # Perform the actual disk check using the full path
        path = os.path.join(target_dir, raw_fname)
        if not os.path.exists(path):
            row = f"{display_name:<{col_w}} | {RED}MISSING FROM DISK{'':<{len(header)-col_w-21}}{NC}"
            logging.info(row)
            continue

        meta_d = get_current_meta(path)

        # Comparison Logic: int() handles float precision drift in filesystems
        def get_stat(json_val, disk_val):
            if int(json_val or 0) == int(disk_val or 0):
                return f"{GREEN}MATCH{NC}"
            return f"{RED}FAIL {NC}"

        # Support both legacy and v2.0.0 meta keys
        b_stat = get_stat(meta_j.get('st_birthtime') or meta_j.get('birth'), meta_d['birth'])
        m_stat = get_stat(meta_j.get('st_mtime') or meta_j.get('mod'), meta_d['mod'])
        a_stat = get_stat(meta_j.get('st_atime') or meta_j.get('acc'), meta_d['acc'])
        
        # 'ADDED' is special: manifests clean state vs current disk attributes
        added_stat = f"{GREEN}CLEAN{NC}" if meta_d['added'] is None else f"{RED}DIRTY{NC}"

        # Construct and log the row
        row = f"{display_name:<{col_w}} | {b_stat} | {m_stat} | {a_stat} | {added_stat}"
        logging.info(row)

    logging.info(separator)

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
    """Verifies hidden shards against the forensic hashes in carrier.json."""
    logging.info(f"\n{BLUE}{BOLD}--- [6] PAYLOAD INTEGRITY HASH ---{NC}")
    
    if not os.path.exists(args.json_file):
        logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found.")
        return

    try:
        with open(args.json_file, "r") as f:
            data = json.load(f)
            manifest = data.get("carriers", [])
            mode = data.get("mode", "in-place")
            # Determine where to look based on the session mode
            target_dir = args.hide_carrier if mode == "in-place" else args.found_carrier
    except Exception as e:
        logging.error(f"{RED}[ERROR]{NC} Failed to parse manifest: {e}")
        return

    if not manifest:
        logging.warning(f"{YELLOW}[SKIP]{NC} No carriers found in manifest.")
        return

    # v2.0.0 Constraints: Cap filename column to maintain table alignment
    max_found_len = max(len(e['file_name']) for e in manifest)
    col_w = min(max_found_len, LOG_MAX_FNAME)

    logging.info(f"{CYAN}[INFO]{NC} Verifying {len(manifest)} shards ({mode})...")

    # --- Header Formatting ---
    # Expected hash is truncated to 16 chars for the UI
    header = f"{'CARRIER':<{col_w}} | {'EXPECTED (SHA256)':<16} | {'STATUS'}"
    separator = "-" * len(header)
    
    logging.info(f"{BOLD}{header}{NC}")
    logging.info(separator)

    for entry in manifest:
        raw_fname = entry['file_name']
        expected = entry.get('shard_hash', 'N/A')
        
        # Display Truncation
        if len(raw_fname) > LOG_MAX_FNAME:
            display_name = raw_fname[:LOG_MAX_FNAME-3] + "..."
        else:
            display_name = raw_fname

        path = os.path.join(target_dir, raw_fname)
        
        if not os.path.exists(path):
            status = f"{RED}MISSING{NC}"
            current_hex = " " * 16
        else:
            try:
                with open(path, "rb") as f:
                    # Forensic Seek: Read only the hidden shard data
                    f.seek(entry['start_offset'])
                    actual_data = f.read(entry['payload_size'])
                    current_hex = hashlib.sha256(actual_data).hexdigest()[:16]
                    
                    if expected == 'N/A':
                        status = f"{YELLOW}UNTRACKED{NC}"
                    else:
                        status = f"{GREEN}MATCH{NC}" if current_hex == expected else f"{RED}CORRUPT{NC}"
            except Exception as e:
                status = f"{RED}READ ERR{NC}"
                current_hex = " " * 16

        # Final Row Log
        row = f"{display_name :<{col_w}} | {expected:<16} | {status}"
        logging.info(row)

    logging.info(separator)

def erase(args):
    """
    Forensic Command: Wipes the session manifest and associated payloads.
    Integrated from pdf_erase.py logic.
    """
    logging.info(f"\n{RED}{BOLD}--- [8] ERASE ---{NC}")
    
    # Define our targets based on the manifest and defaults
    targets = [
        args.json_file,
        "hide_payload",   # Original source
        "found_payload",  # Restored output
        "found_carrier"   # Legacy copies
    ]

    # We check if the user wants standard or forensic wipe
    method = 'erase' if args.fast_erase else 'secure'
    
    logging.info(f"{CYAN}[INFO]{NC} Initiating {method} wipe of session artifacts...")

    for target in targets:
        if not os.path.exists(target):
            continue
            
        # Recursive shredder/remover
        erase_path(target, method)

    logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} All forensic traces of this session removed.")    

def main():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Steganography Suite v{__version__}{NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"{CYAN}v2.0.1: Integrated Forensic Erasure & Responsive Auditing{NC}"
    )
    
    # 1. Commands
    parser.add_argument("action", choices=['hide', 'restore', 'diff', 'hash', 'sync', 'audit', 'erase'], 
                        help="Action to perform: hide, restore, audit, or erase.")
    parser.add_argument("password", nargs='?', help="Manual password for XOR encryption (optional).")
    
    paths = parser.add_argument_group(f'{CYAN}Path Configuration{NC}')
    paths.add_argument("-hp", "--hide_payload", default="hide_payload", 
                       help="Directory containing payload to hide (Default: hide_payload).")
    paths.add_argument("-hc", "--hide_carrier", default="hide_carrier", 
                       help="Directory containing carriers for hiding (Default: hide_carrier).")
    paths.add_argument("-fp", "--found_payload", default="found_payload", 
                       help="Directory where hidden payload will be extracted (Default: found_payload).")
    paths.add_argument("-fc", "--found_carrier", default="found_carrier", 
                       help="Directory for carrier copies if not in-place (Default: found_carrier).")
    paths.add_argument("--no-overwrite", action="store_true", 
                       help="Request confirmation before overwriting files.")
    
    sessions = parser.add_argument_group(f'{CYAN}Session Tracking{NC}')
    sessions.add_argument("-jf", "--json_file", default="carrier.json", 
                          help="Master manifest file (Default: carrier.json).")
    
    carriers = parser.add_argument_group(f'{CYAN}Carrier Management{NC}')
    carriers.add_argument("-mc", "--max_carriers_number", type=int, default=50, 
                          help="Max carriers to utilize (Default: 50).")
    carriers.add_argument("-sc", "--max_carriers_size_incr", type=float, default=0.30, 
                          help="Allowed growth ratio per carrier (Default: 30%%).")
    carriers.add_argument("-xc", "--exclude_carrier_chars", nargs='?', const="^+§", default=None,
                          help="Skip carriers with these characters (Default: ^+§).")
    carriers.add_argument("-xf", "--exclude_carrier_file", nargs='?', const="exclude_carrier.txt", default=None,
                          help="Enable blacklist file (Default: exclude_carrier.txt).")
    carriers.add_argument("-kc", "--mark_carrier_chars", default="", 
                          help="Character(s) to append to filenames (Default: None).")
    carriers.add_argument("--no-in-place", action="store_false", dest="in_place",
                          help="Disable in-place modification.")
    parser.set_defaults(in_place=True)

    erasure = parser.add_argument_group(f'{CYAN}Erase Management{NC}')
    erasure.add_argument("--fast_erase", action="store_true", 
                         help="Use standard OS removal instead of forensic shredding.")
    erasure.add_argument("-y", "--yes", action="store_true", 
                         help="Skip confirmation prompt for erase action.")

    # Global Flags
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()
    
    # 2. Actions dictionary
    actions = {
        'hide': hide, 
        'restore': restore, 
        'diff': diff, 
        'hash': hash, 
        'sync': sync,
        'audit': audit,
        'erase': erase
    }

    if args.action in actions:
        try: 
            actions[args.action](args)
        except KeyboardInterrupt:
            logging.info(f"\n{YELLOW}[SHUTDOWN]{NC} Interrupted by user.")
            sys.exit(0)
        except Exception as e: 
            logging.critical(f"{RED}{BOLD}[CRITICAL]{NC} {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main()