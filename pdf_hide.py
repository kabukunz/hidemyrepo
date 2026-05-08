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

# --- Setup Functions ---
__version__ = "2.0.2"

json_file_name = "pdf_map.json"

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

def print_table_row(cols, widths, colors=None):
    """
    Standardized row printer for forensic tables.
    Truncates long strings and maintains vertical alignment.
    """
    formatted_parts = []
    for i, (val, width) in enumerate(zip(cols, widths)):
        color = colors[i] if colors and i < len(colors) else ""
        reset = NC if color else ""
        
        # Convert to string and truncate if value exceeds width
        val_str = str(val)
        if len(val_str) > width:
            val_str = val_str[:width-3] + "..."
            
        formatted_parts.append(f"{color}{val_str:<{width}}{reset}")
    
    logging.info(" | ".join(formatted_parts))

def draw_progress(current, total, prefix=""):
    """Renders a progress bar that looks like a log entry but updates in-place."""
    if total <= 0: return
    
    bar_len = 40
    filled = int(bar_len * current // total)
    bar = ('█' * filled).ljust(bar_len)
    percent = int(100 * current / total)
    
    # 1. Generate a timestamp to match your logging format
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # 2. Construct the full line
    # The \r at the start keeps it on the same line
    # The prefix can be [INFO], [ZIP], or [INJECT]
    output = f"\r[{timestamp}] {prefix} |{bar}| {percent}% ({current}/{total})"
    
    sys.stdout.write(output)
    sys.stdout.flush()

    # 3. When finished, move to the next line so the next log doesn't overwrite it
    if current == total:
        sys.stdout.write("\n")
        sys.stdout.flush()    

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

def get_crypto_primitives():
    """Lazy-load cryptography requirements."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        return AESGCM, PBKDF2HMAC, hashes, default_backend
    except ImportError:
        print(f"\n{RED}[!] Error: 'cryptography' package is missing.{NC}")
        print(f"{YELLOW}To use AES mode, install it with: pip install cryptography{NC}\n")
        sys.exit(1)

def encrypt_data_aes(data, password, iterations):
    """
    Encrypts a byte blob using AES-256-GCM.
    Returns: (ciphertext, crypto_meta_dict)
    """
    # 1. Load primitives (ensures cryptography is installed)
    AESGCM, PBKDF2HMAC, hashes, default_backend = get_crypto_primitives()

    # 2. Generate random anchors
    # Salt: Makes the key derivation unique even if passwords match
    # Nonce: Ensures the same payload results in different ciphertext every time
    salt = os.urandom(16)
    nonce = os.urandom(12)

    # 3. Derive Key (PBKDF2)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # 4. Perform Encryption
    aesgcm = AESGCM(key)
    # The result includes the 16-byte authentication tag appended automatically
    ciphertext = aesgcm.encrypt(nonce, data, None)

    # 5. Build the meta block for the JSON manifest
    crypto_meta = {
        "algo": "aes-256-gcm",
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "iterations": iterations
    }

    return ciphertext, crypto_meta

def decrypt_payload_aes(ciphertext, password, salt, nonce, iterations):
    """
    Derives the AES-256 key and decrypts the payload.
    Returns: Raw bytes if successful, None if authentication fails.
    """
    # 1. Load primitives (Lazy import check)
    AESGCM, PBKDF2HMAC, hashes, default_backend = get_crypto_primitives()

    try:
        # 2. Re-derive the key using the Salt and Iterations from the manifest
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        # 3. Attempt to decrypt
        aesgcm = AESGCM(key)
        
        # AES-GCM verifies the integrity tag automatically. 
        # If the password is wrong or a single bit was changed, this raises InvalidTag.
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        
        return decrypted_data

    except Exception as e:
        # We catch all crypto-related failures (InvalidTag, etc.) 
        # and return None to signal a 'Lock Failure'.
        logging.debug(f"AES Decryption Internal Error: {e}")
        return None
        
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

def inject(target_path, shard):
    """Appends shard data to the end of a file without creating a copy."""
    try:
        with open(target_path, 'ab') as f:
            f.write(shard)
        return True
    except Exception as e:
        logging.error(f"In-place write failed for {target_path}: {e}")
        return False

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

def perform_injection(selected_pool, encrypted, args, crypto_meta):
    """
    Orchestrates shard distribution and generates the master manifest.
    Updated to support dual-mode crypto (XOR/AES) and forensic integrity.
    """
    total_pool_bytes = sum(c['size'] for c in selected_pool)
    payload_len = len(encrypted)
    cursor, manifest_entries = 0, []
    
    # Capture the password being used for this session
    active_password = args.password

    logging.info(f"{BOLD}--- PERFORMING INJECTION ---{NC}")

    for i, c in enumerate(selected_pool, 1):
        # Determine the relative path for the manifest
        rel_path = os.path.relpath(c['path'], args.hide_carrier)
        
        # Apply character masking if requested
        if args.mark_carrier_chars:
            base, ext = os.path.splitext(rel_path)
            rel_path = f"{base}{args.mark_carrier_chars}{ext}"
            
        # Calculate shard size proportionally based on carrier capacity
        shard_size = math.floor((c['size'] / total_pool_bytes) * payload_len)
        
        # Ensure the last carrier takes the remainder of the buffer
        if i == len(selected_pool):
            shard = encrypted[cursor:]
        else:
            shard = encrypted[cursor:cursor + shard_size]
        
        # --- Forensic Shard Hash ---
        # 16-char fingerprint for future integrity audits
        shard_hash = hashlib.sha256(shard).hexdigest()[:16]

        # 1. Capture exact start position and original metadata
        start_offset = os.path.getsize(c['path'])
        st = os.stat(c['path'])
        original_birth = getattr(st, 'st_birthtime', st.st_mtime)
        
        # 2. Execute the physical append to the PDF
        success = inject(c['path'], shard)
            
        if not success:
            logging.error(f"Pipeline failure at carrier: {c['path']}")
            sys.exit(1)

        # 3. Catalog metadata for the manifest
        manifest_entries.append({
            "carrier_index": i,
            "file_name": rel_path,
            "start_offset": start_offset,
            "payload_size": len(shard),
            "shard_hash": shard_hash,
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

    # 4. Finalize the Master Manifest (v2.1.0 Session Map)
    # Includes the 'crypto' block required for AES decryption
    session_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "crypto": crypto_meta, # Contains algo, salt, nonce, and iterations
        "hide_payload": args.hide_payload,
        "hide_carrier_backup": args.hide_carrier_backup,
        "carriers_total": len(manifest_entries),
        "carriers": manifest_entries
    }

    # Only add the password if the user didn't request silence
    if not args.no_log_passwd:
        session_data["password"] = active_password
    else:
        logging.info(f"{YELLOW}[OPSEC]{NC} Password omitted from manifest as requested.")

    with open(args.json_file, "w") as f:
        json.dump(session_data, f, indent=4)

    logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} " + args.json_file + " generated with " + crypto_meta.get('algo', 'xor').upper() + " metadata.")
    
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
                logging.info(f"{GREEN}{BOLD}[SECURE]{NC} shredded file: {path}")
        else:
            os.remove(path)
            logging.info(f"{GREEN}{BOLD}[ERASE]{NC} removed file: {path}")
            
    elif os.path.isdir(path):
        if action == 'secure':
            # logging.info(f"{CYAN}{BOLD}[INFO]{NC} shredding dir: {path}")
            for root, dirs, files in os.walk(path, topdown=False):
                for name in files:
                    secure_shred_file(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            
            os.rmdir(path)
            logging.info(f"{GREEN}{BOLD}[SECURE]{NC} shredded dir: {path}")
        else:
            shutil.rmtree(path)
            logging.info(f"{GREEN}{BOLD}[ERASE]{NC} removed dir: {path}")

def hide(args):
    """Main workflow for carrier selection and binary embedding with backup."""
    logging.info(f"\n{BLUE}{BOLD}--- [2] PAYLOAD HIDING ---{NC}")
    
    if not args.password: 
        args.password = generate_robust_password()

    raw_payload = get_zip_memory(args.hide_payload)
    if not raw_payload: return
        
    # --- Unified Crypto Dispatcher ---
    crypto_meta = {}
    if args.crypto == "aes":
        logging.info(f"{CYAN}[CRYPTO]{NC} Mode: AES-256-GCM | Iterations: {args.iterations:,}")
        # This returns (ciphertext, meta_dict)
        encrypted, crypto_meta = encrypt_data_aes(raw_payload, args.password, args.iterations)
    else:
        logging.info(f"{CYAN}[CRYPTO]{NC} Mode: XOR (Standard)")
        encrypted = xor_crypt(raw_payload, args.password)
        crypto_meta = {"algo": "xor"}

    payload_size = len(encrypted)
    
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
            reason = f"{'exclude file' if file_match else ''}{' + ' if file_match and char_match else ''}{'exclude char' if char_match else ''}"
            exclude_log.append((f"  [SKIP] {fname}", reason))
        else:
            available.append({
                'path': f, 
                'size': os.path.getsize(f),
                'pre_meta': get_current_meta(f) 
            })

    # --- Structured Skip List Display ---
    if exclude_log:
        logging.info(f"{CYAN}[EXCLUDE]{NC} Skip list:")
        widths = [65, 35]
        headers = ["SKIPPED CARRIER", "REASON"]
        sep = "-" * (sum(widths) + 3)
        
        logging.info(sep)
        print_table_row(headers, widths, [YELLOW + BOLD, YELLOW + BOLD])
        logging.info(sep)
        for fname_formatted, reason in exclude_log:
            clean_name = fname_formatted.lstrip() 
            print_table_row([clean_name, reason], widths, ["", YELLOW])
        logging.info(sep)

    # --- Selection based on capacity ---
    selected, current_cap = [], 0
    for f in available:
        if len(selected) < args.max_carriers_number and current_cap < payload_size:
            selected.append(f)
            # Use the actual encrypted size for capacity calculations
            current_cap += int(f['size'] * args.max_carriers_size_incr)

    if current_cap < payload_size:
        logging.error(f"{RED}[ERROR]{NC} Insufficient capacity.")
        sys.exit(1)

    # Backup Logic
    if args.hide_carrier_backup:
        backup_dir = args.hide_carrier_backup
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
            logging.info(f"{CYAN}[BACKUP]{NC} Created: {backup_dir}")
        
        logging.info(f"{CYAN}[BACKUP]{NC} Archiving {len(selected)} carriers...")
        for f in selected:
            shutil.copy2(f['path'], os.path.join(backup_dir, os.path.basename(f['path'])))
        logging.info(f"{GREEN}[SUCCESS]{NC} Backup complete.")

    # # Crypto Type
    # if args.crypto == "aes":
    #     logging.info(f"{CYAN}[CRYPTO]{NC} Mode: AES-256-GCM | Iterations: {args.iterations:,}")
    # else:
    #     logging.info(f"{CYAN}[CRYPTO]{NC} Mode: XOR (Standard)")

    # --- Execute Injection ---
    # We pass crypto_meta so perform_injection can save it to the JSON
    perform_injection(selected, encrypted, args, crypto_meta)

    # --- Unified Stats Reporting ---
    total_carrier_size = sum(c['size'] for c in selected)
    total_storage_mb = (total_carrier_size + len(encrypted)) / (1024 * 1024)
    avg_growth = (len(encrypted) / total_carrier_size) * 100 if total_carrier_size > 0 else 0
    
    logging.info(f"{GREEN}{BOLD}--- INJECTION STATS ---{NC}")
    stat_widths = [20, 30]
    print_table_row(["Payload Size", f"{len(encrypted)/(1024*1024):.2f} MB"], stat_widths)
    print_table_row(["Carriers Used", f"{len(selected)} files"], stat_widths)
    print_table_row(["Total Storage", f"{total_storage_mb:.2f} MB"], stat_widths)
    print_table_row(["Avg. Growth", f"{avg_growth:.2f}%"], stat_widths)
    
    logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} Hide applied successfully.")
    logging.info(f"{CYAN}[INFO]{NC} Run 'sync' to apply forensic timestamps.")

def restore(args):
    """Reassembles shards and extracts content directly back to the source directory."""
    logging.info(f"\n{BLUE}{BOLD}--- [4] RESTORE PAYLOAD ---{NC}")
    
    # 1. Load the session data
    try:
        with open(args.json_file, "r") as f:
            session_json = json.load(f)
            
            # OPSEC Priority: Manual CLI Password > Manifest Stored Password
            active_password = args.password or session_json.get("password")
            
            # Detect Crypto Method (Default to XOR for legacy support)
            crypto_info = session_json.get("crypto", {"algo": "xor"})
            manifest = session_json.get("carriers", [])
            
    except FileNotFoundError:
        logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found. Cannot restore.")
        return

    if not active_password:
        logging.error(f"{RED}[ERROR]{NC} No password found in manifest and none provided via CLI.")
        logging.info(f"{YELLOW}[TIP]{NC} Use: python ghost.py restore [JSON] [PASS]")
        return

    # --- Reassembly Phase ---
    logging.info(f"{YELLOW}[RESTORE]{NC} Reassembling from {len(manifest)} carriers...")
    chunks = []
    
    try:
        for i, entry in enumerate(manifest, 1):
            # Resolve the path (assuming carriers are in the specified hide_carrier dir)
            target_path = os.path.join(args.hide_carrier, entry['file_name'])
                
            if not os.path.exists(target_path):
                raise FileNotFoundError(f"Carrier missing: {entry['file_name']}")

            with open(target_path, 'rb') as f:
                f.seek(entry['start_offset'])
                shard_data = f.read(entry['payload_size'])
                
                # Forensic Check: Verify shard hash before merging
                current_hash = hashlib.sha256(shard_data).hexdigest()[:16]
                if current_hash != entry['shard_hash']:
                    logging.warning(f"{RED}[TAMPERED]{NC} Shard {i} hash mismatch!")
                
                chunks.append(shard_data)
                
            draw_progress(i, len(manifest), prefix="  Reading   ")
        
        full_payload = b"".join(chunks)
        sys.stdout.write("\n\n")

        # --- 2. Decryption Dispatcher ---
        algo = crypto_info.get("algo", "xor").lower()
        
        if algo == "aes-256-gcm":
            logging.info(f"{CYAN}[CRYPTO]{NC} Method: AES-256-GCM | Verifying Integrity...")
            # Extract anchors from manifest
            salt = bytes.fromhex(crypto_info["salt"])
            nonce = bytes.fromhex(crypto_info["nonce"])
            iters = crypto_info.get("iterations", 100000)
            
            # Decrypt (returns None if Tag/Password fails)
            decrypted_zip = decrypt_payload_aes(full_payload, active_password, salt, nonce, iters)
        else:
            logging.info(f"{CYAN}[CRYPTO]{NC} Method: XOR | Decrypting...")
            decrypted_zip = xor_crypt(full_payload, active_password)
        
        if not decrypted_zip:
            logging.error(f"{RED}[ERROR]{NC} Decryption failed. Wrong password or data corruption.")
            return

        # 3. Final extraction to memory then disk
        if not decrypted_zip.startswith(b'PK'):
            logging.error(f"{RED}[ERROR]{NC} Validated data but found no ZIP header. Extraction aborted.")
            return

        with io.BytesIO(decrypted_zip) as mem_buf:
            with zipfile.ZipFile(mem_buf) as zf:
                os.makedirs(args.hide_payload, exist_ok=True)
                items = zf.namelist()
                for i, item in enumerate(items, 1):
                    zf.extract(item, args.hide_payload)
                    draw_progress(i, len(items), prefix="  Unpacking ")
        
        sys.stdout.write("\n\n")
        logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} Data restored to '{args.hide_payload}'")
        
    except Exception as e:
        logging.error(f"\n{RED}{BOLD}[ERROR]{NC} Restoration failed: {e}")

def sync(args):
    """Aligns disk timestamps with JSON-stored forensic dates."""
    logging.info(f"\n{BLUE}{BOLD}--- [3] DATES ALIGNMENT ---{NC}")
    
    if not os.path.exists(args.json_file):
        logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found.")
        return

    try:
        with open(args.json_file, "r") as f:
            data = json.load(f)
            manifest = data.get("carriers", [])
            # Grab oldest mtime to reset the folder later
            all_mtimes = [int(e.get('meta', {}).get('st_mtime') or e.get('meta', {}).get('mod', 0)) 
                          for e in manifest if e.get('meta')]
    except Exception as e:
        logging.error(f"{RED}[ERROR]{NC} Failed to parse manifest: {e}")
        return

    if not os.path.exists(args.hide_carrier):
        logging.error(f"{RED}[ERROR]{NC} Target directory {args.hide_carrier} missing.")
        return

    # Load libc for macOS birthtime support
    libc = None
    if sys.platform == "darwin":
        try:
            libc = ctypes.CDLL("/usr/lib/libc.dylib", use_errno=True)
        except OSError:
            logging.warning(f"{YELLOW}[WARN]{NC} libc.dylib missing. Birth date sync unavailable.")

    logging.info(f"{CYAN}[INFO]{NC} Synchronizing {len(manifest)} carriers...")

    for i, entry in enumerate(manifest, 1):
        fname = entry['file_name']
        meta = entry.get('meta', {})
        path = os.path.join(args.hide_carrier, fname)

        # Update progress bar (The "Log-Style" version)
        draw_progress(i, len(manifest), prefix=f"{CYAN}Syncing{NC} ")

        if not os.path.exists(path):
            continue

        # 1. Standard utime (Modification/Access)
        m_time = int(meta.get('st_mtime') or meta.get('mod', 0))
        a_time = int(meta.get('st_atime') or meta.get('acc', 0))
        
        if m_time > 0:
            os.utime(path, (a_time, m_time))

        # 2. Kernel-Level Birth Date (Creation) - macOS Only
        b_time = int(meta.get('st_birthtime') or meta.get('birth', 0))
        if b_time > 0 and libc:
            try:
                # ATTR_CMN_CRTIME = 0x00000200
                attr_list = struct.pack("HHHHH", 5, 0, 0x00000200, 0, 0)
                time_buf = struct.pack("qq", b_time, 0)
                libc.setattrlist(path.encode(), attr_list, time_buf, len(time_buf), 0)
            except:
                pass # Silently fail on permission/kernel locks

        # 3. Wipe macOS Extended Attributes (Clears 'Date Added' / 'Where From')
        if sys.platform == "darwin":
            subprocess.run(['xattr', '-c', path], capture_output=True)

    # 4. Parent Directory Reset
    # This prevents the folder itself from showing a "Last Modified" date of today
    if all_mtimes:
        try:
            back_date = min(all_mtimes)
            os.utime(args.hide_carrier, (back_date, back_date))
            logging.info(f"{GREEN}[SUCCESS]{NC} Parent directory back-dated to oldest carrier.")
        except Exception as e:
            logging.debug(f"Parent sync failed: {e}")

    logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} Forensic timestamps restored.")

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
            target_dir = args.hide_carrier
            
            # --- Forensic Timestamp Conversion ---
            raw_ts = data.get("timestamp")
            expected_folder_ts = 0
            if raw_ts:
                try:
                    from datetime import datetime
                    dt_obj = datetime.strptime(raw_ts, "%Y-%m-%d %H:%M:%S")
                    expected_folder_ts = int(dt_obj.timestamp())
                except Exception:
                    pass
                    
    except Exception as e:
        logging.error(f"{RED}[ERROR]{NC} Failed to parse manifest: {e}")
        return

    # Unified Layout Constants
    widths = [45, 7, 7, 7, 7]
    sep = "-" * (sum(widths) + 12)

    # --- [SECTION 1: PARENT DIRECTORY] ---
    if os.path.exists(target_dir):
        logging.info(sep)
        print_table_row(["CARRIER DIR", "BIRTH", "MOD", "ACC", "ADDED"], widths, [CYAN + BOLD] * 5)
        logging.info(sep)

        dir_meta = get_current_meta(target_dir)
        
        # Get name without colors first
        raw_name = os.path.basename(os.path.abspath(target_dir)) or target_dir
        # Format the name with the [DIR] tag but keep the alignment clean
        display_name = f"[DIR] {raw_name}"
        
        # Forensic Check against oldest carrier
        all_mtimes = [int(e.get('meta', {}).get('st_mtime') or e.get('meta', {}).get('mod', 0)) 
                      for e in manifest if e.get('meta')]
        oldest_ts = min(all_mtimes) if all_mtimes else None

        def get_dir_stat(disk_val):
            if oldest_ts is None: return ("N/A", YELLOW)
            drift = abs(int(disk_val) - oldest_ts)
            return ("MATCH", GREEN) if drift <= args.drift_threshold else ("FAIL", RED)

        m_txt, m_col = get_dir_stat(dir_meta['mod'])
        a_txt, a_col = get_dir_stat(dir_meta['acc'])
        
        # Pass the BLUE color to the first column specifically through the color list
        print_table_row(
            [display_name, "---", m_txt, a_txt, "---"],
            widths,
            [BLUE, "", m_col, a_col, ""]
        )
        logging.info(sep)

    # print("") # Aesthetic gap

    # --- [SECTION 2: CARRIER FILES] ---
    # logging.info(f"{CYAN}[INFO]{NC} Auditing {len(manifest)} Carrier Files...")
    
    # logging.info(sep)
    print_table_row(["CARRIER FILE", "BIRTH", "MOD", "ACC", "ADDED"], widths, [CYAN + BOLD] * 5)
    logging.info(sep)

    for entry in manifest:
        raw_fname = entry['file_name']
        meta_j = entry.get('meta', {})
        idx = entry.get("carrier_index", "?")
        id_name = f"[{idx}] {raw_fname}"
        path = os.path.join(target_dir, raw_fname)

        if not os.path.exists(path):
            print_table_row([id_name, "MISSING"], [widths[0], sum(widths[1:])+9], ["", RED])
            continue

        meta_d = get_current_meta(path)

        def get_stat_info(json_val, disk_val):
            drift = abs((json_val or 0) - (disk_val or 0))
            return ("MATCH", GREEN) if drift <= args.drift_threshold else ("FAIL", RED)

        b_txt, b_col = get_stat_info(meta_j.get('st_birthtime') or meta_j.get('birth'), meta_d['birth'])
        m_txt, m_col = get_stat_info(meta_j.get('st_mtime') or meta_j.get('mod'), meta_d['mod'])
        a_txt, a_col = get_stat_info(meta_j.get('st_atime') or meta_j.get('acc'), meta_d['acc'])
        
        added_txt = "CLEAN" if meta_d['added'] is None else "DIRTY"
        added_col = GREEN if added_txt == "CLEAN" else RED

        print_table_row(
            [id_name, b_txt, m_txt, a_txt, added_txt],
            widths,
            ["", b_col, m_col, a_col, added_col]
        )

    logging.info(sep)
    logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} Forensic audit finished.")

def diff(args):
    """Compares actual disk size against expected manifest size."""
    logging.info(f"\n{BLUE}{BOLD}--- [5] CARRIER DIFF ---{NC}")
    
    if not os.path.exists(args.json_file):
        logging.warning(f"{YELLOW}[SKIP]{NC} No {args.json_file} found.")
        return

    try:
        with open(args.json_file, "r") as f:
            session_json = json.load(f)
            manifest = session_json.get("carriers", [])
    except Exception as e:
        logging.error(f"{RED}[ERROR]{NC} Failed to parse manifest: {e}")
        return

    # Table Layout: Carrier (45), Growth (15), Status (20)
    widths = [45, 15, 20]
    headers = ["CARRIER", "GROWTH", "STATUS"]
    separator = "-" * (sum(widths) + 6)

    logging.info(separator)
    print_table_row(headers, widths, [CYAN + BOLD] * 3)
    logging.info(separator)
    
    for entry in manifest:
        rel = entry['file_name']
        idx = entry.get("carrier_index", "?")
        path = os.path.join(args.hide_carrier, rel)
        
        id_name = f"[{idx}] {rel}"

        if not os.path.exists(path):
            print_table_row([id_name, "0 B", "MISSING"], widths, ["", "", RED])
            continue

        current_size = os.path.getsize(path)
        # Expected = Original Size + Injected Payload
        expected_size = entry['start_offset'] + entry['payload_size']
        
        # Calculate actual growth compared to the clean original file
        actual_growth = current_size - entry['start_offset']
        growth_str = f"+{actual_growth:,} B"

        if current_size == expected_size:
            status_text = "SIZE OK"
            status_col = GREEN
        else:
            # Calculate the delta between what we expected and what we found
            delta = current_size - expected_size
            status_text = f"MISMATCH ({delta:+,}B)"
            status_col = RED
            
        print_table_row([id_name, growth_str, status_text], widths, ["", "", status_col])

    logging.info(separator)
    logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} Structural diff finished.")

def hash(args): # Renamed to hash_audit to avoid conflict with built-in hash()
    """Verifies hidden shards against the forensic hashes in the manifest."""
    logging.info(f"\n{BLUE}{BOLD}--- [6] PAYLOAD INTEGRITY HASH ---{NC}")
    
    if not os.path.exists(args.json_file):
        logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found.")
        return

    try:
        with open(args.json_file, "r") as f:
            data = json.load(f)
            manifest = data.get("carriers", [])
            target_dir = args.hide_carrier
    except Exception as e:
        logging.error(f"{RED}[ERROR]{NC} Failed to parse manifest: {e}")
        return

    if not manifest:
        logging.warning(f"{YELLOW}[SKIP]{NC} No carriers found in manifest.")
        return

    logging.info(f"{CYAN}[INFO]{NC} Verifying {len(manifest)} shards...")

    # Table Layout: Carrier (45), Expected Hash (20), Status (10)
    widths = [45, 20, 10]
    headers = ["CARRIER", "EXPECTED (SHA256)", "STATUS"]
    separator = "-" * (sum(widths) + 6)

    logging.info(separator)
    print_table_row(headers, widths, [CYAN + BOLD] * 3)
    logging.info(separator)

    for entry in manifest:
        rel = entry['file_name']
        idx = entry.get("carrier_index", "?")
        expected = entry.get('shard_hash', 'N/A')
        path = os.path.join(target_dir, rel)
        
        id_name = f"[{idx}] {rel}"

        if not os.path.exists(path):
            print_table_row([id_name, expected[:16], "MISSING"], widths, ["", "", RED])
            continue

        try:
            with open(path, "rb") as f:
                # Forensic Seek: Only verify the hidden bytes, ignore the carrier PDF's bytes
                f.seek(entry['start_offset'])
                actual_data = f.read(entry['payload_size'])
                current_hex = hashlib.sha256(actual_data).hexdigest()[:16]
                
                if expected == 'N/A':
                    status_text, status_col = "UNTRACKED", YELLOW
                elif current_hex == expected:
                    status_text, status_col = "MATCH", GREEN
                else:
                    status_text, status_col = "CORRUPT", RED
                    
                print_table_row([id_name, expected[:16], status_text], widths, ["", "", status_col])
                
        except Exception as e:
            print_table_row([id_name, expected[:16], "READ ERR"], widths, ["", "", RED])

    logging.info(separator)
    logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} Integrity hash audit finished.")

def touch(args):
    """
    Forensic Command: Detects 'Stat Diff' (Metadata drift).
    Compares live filesystem stats against manifest signatures with a custom threshold.
    """
    logging.info(f"\n{BLUE}{BOLD}--- [9] FORENSIC TOUCH AUDIT ---{NC}")
    
    if not os.path.exists(args.json_file):
        logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found.")
        return

    try:
        with open(args.json_file, "r") as f:
            data = json.load(f)
            manifest = data.get("carriers", [])
            carriers_total = data.get("carriers_total", len(manifest))
    except Exception as e:
        logging.error(f"{RED}[ERROR]{NC} Failed to parse manifest: {e}")
        return

    logging.info(f"{CYAN}[INFO]{NC} Auditing {carriers_total} carriers with {args.drift_threshold}s tolerance...")

    # Define layout: [ID] Carrier (50 chars), Drift (20 chars), Status (10 chars)
    widths = [50, 20, 10]
    headers = ["CARRIER", "TIMESTAMP DRIFT", "STATUS"]
    separator = "-" * (sum(widths) + 6) # +6 accounts for the " | " spacers

    logging.info(separator)
    print_table_row(headers, widths, [CYAN + BOLD, CYAN + BOLD, CYAN + BOLD])
    logging.info(separator)

    for entry in manifest:
        rel = entry['file_name']
        path = os.path.join(args.hide_carrier, rel)
        idx = entry.get("carrier_index", "?")
        
        # Identity string: e.g., "[1] Crypto101.pdf"
        id_name = f"[{idx}] {rel}"

        if not os.path.exists(path):
            print_table_row([id_name, "N/A", "MISSING"], widths, ["", "", RED])
        else:
            st = os.stat(path)
            meta = entry.get("meta", {})
            stored_mtime = meta.get("st_mtime")
            
            if stored_mtime is None:
                print_table_row([id_name, "Unknown", "NO SIG"], widths, ["", "", YELLOW])
            else:
                drift = st.st_mtime - stored_mtime
                drift_msg = f"{drift:+.2f}s"
                
                if abs(drift) <= args.drift_threshold:
                    print_table_row([id_name, drift_msg, "OK"], widths, ["", "", GREEN])
                else:
                    print_table_row([id_name, drift_msg, "TOUCHED"], widths, ["", "", RED])

    logging.info(separator)
    logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} Metadata audit finished.")

def erase(args):
    """
    Forensic Command: Wipes the session manifest and associated payloads.
    Retrieves dynamic paths from the JSON map before destruction.
    """
    logging.info(f"{RED}{BOLD}--- [8] ERASE ---{NC}")
    
    # 1. Start with defaults from CLI arguments
    targets = {args.json_file, args.hide_payload}
    if args.hide_carrier_backup:
        targets.add(args.hide_carrier_backup)

    # 2. Try to harvest specific paths from the manifest
    if os.path.exists(args.json_file):
        try:
            with open(args.json_file, 'r') as f:
                manifest = json.load(f)
                # Sync paths from the actual session record
                if "hide_payload" in manifest:
                    targets.add(manifest["hide_payload"])
                if "hide_carrier_backup" in manifest and manifest["hide_carrier_backup"]:
                    targets.add(manifest["hide_carrier_backup"])
        except Exception as e:
            logging.warning(f"{YELLOW}[WARN]{NC} Manifest found but unreadable: {e}")

    # 3. Determine wipe depth
    method = 'erase' if args.fast_erase else 'secure'
    
    # 4. Execute cleanup
    # We convert to a list and filter for existence
    for target in sorted(list(targets), reverse=True): # Reverse to hit files before folders if needed
        if os.path.exists(target):
            erase_path(target, method)

    logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} data erased.")

def main():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Steganography Suite v{__version__}{NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"{CYAN}v2.0.2: Stateful Backup & Forensic Timeline Auditing{NC}"
    )
    
    # 1. Commands - Added 'touch' to the choices
    parser.add_argument("action", choices=['hide', 'restore', 'diff', 'hash', 'sync', 'audit', 'erase', 'touch'], 
                        help="Action to perform: hide, restore, audit, erase, or touch.")
    
    crypto = parser.add_argument_group(f'{CYAN}Encryption and security parameters{NC}')
    crypto.add_argument(
        "--crypto", 
        choices=["xor", "aes"], 
        default="xor",
        help="Encryption method (xor: zero-overhead, aes: military-grade)"
    )
    # You might want to allow users to tweak AES complexity later
    crypto.add_argument(
        "--iterations", 
        type=int, 
        default=100000,
        help="PBKDF2 iterations for AES key stretching (default: 100k)"
    )    
    crypto.add_argument(
        "password", 
        nargs='?', 
        help="Encryption password. If omitted in XOR mode, one is generated."
    )
    crypto.add_argument(
        "--no-log-passwd",
        action="store_true",
        help="Do not save the password inside the JSON manifest (enhanced OPSEC)"
    )    
    
    paths = parser.add_argument_group(f'{CYAN}Path Configuration{NC}')
    paths.add_argument("-hp", "--hide_payload", default="hide_payload", 
                       help="Directory containing payload to hide (Default: hide_payload).")
    paths.add_argument("-hc", "--hide_carrier", default="hide_carrier", 
                       help="Directory containing carriers for hiding (Default: hide_carrier).")
    paths.add_argument("--no-overwrite", action="store_true", 
                       help="Request confirmation before overwriting hide carrier files (Default: no).")
    paths.add_argument("-hb", "--hide_carrier_backup", nargs='?', const="hide_carrier_backup", default=None,
                       help="Enable backup by providing a directory name (Default: hide_carrier_backup).")    
    
    sessions = parser.add_argument_group(f'{CYAN}Session Tracking{NC}')    
    sessions.add_argument("-jf", "--json_file", default=json_file_name, 
                          help="Carrier map file (Default: " + json_file_name + ").")
    
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

    erasure = parser.add_argument_group(f'{CYAN}Erase Management{NC}')
    erasure.add_argument("--fast_erase", action="store_true", 
                         help="Use standard OS removal instead of forensic shredding.")

    forensics = parser.add_argument_group(f'{CYAN}Forensic Auditing{NC}')
    forensics.add_argument("-dt", "--drift_threshold", type=float, default=1.0,
                           help="Timestamp drift tolerance in seconds (Default: 1.0).")
    # Global Flags
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()
    
    # 2. Actions dictionary - Integrated touch
    actions = {
        'hide': hide, 
        'restore': restore, 
        'diff': diff, 
        'hash': hash, 
        'sync': sync,
        'audit': audit,
        'erase': erase,
        'touch': touch
    }

    if args.action in actions:
        try: 
            actions[args.action](args)
        except KeyboardInterrupt:
            logging.info(f"\n{YELLOW}[SHUTDOWN]{NC} Interrupted by user.")
            sys.exit(0)
        except Exception as e: 
            logging.critical(f"{RED}{BOLD}[CRITICAL]{NC} {str(e)}")
            # For debugging purposes during v2.0.2 development, you might want to see the traceback
            # import traceback; traceback.print_exc() 
            sys.exit(1)

if __name__ == "__main__":
    main()
