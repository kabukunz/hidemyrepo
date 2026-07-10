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
import struct
import shutil

# --- Version Summary ---

__version__    = "2.7.0"
__algo__       = "AES-256-GCM"
__kdf__        = "PBKDF2-SHA256"
__iterations__ = 600000

__json_file_name__ = "pdf_map.json"

# --- UI & Logging ---

# 1. Get the current terminal width
# fallback=(80, 24) ensures it works even if redirected to a pipe
term_width, _ = shutil.get_terminal_size(fallback=(80, 24))
# 2. Subtract the "Fixed" costs
# Logging prefix "[HH:MM:SS] [INFO] " is ~20 chars
# Separators and Status columns take ~30 chars
fixed_overhead = 50 
# 3. Calculate dynamic max
LOG_MAX_FNAME = max(20, term_width - fixed_overhead)

# ANSI Escape Sequences for Terminal Colors
RED      = "\033[31m"    # Danger / Errors
GREEN    = "\033[32m"    # Success / Completion
YELLOW   = "\033[33m"    # Warnings / OpSec Alerts
BLUE     = "\033[34m"    # Information / Secondary Headers
MAGENTA  = "\033[35m"    # Special / Encrypted Logic
CYAN     = "\033[36m"    # Data Values / Stats
WHITE    = "\033[37m"    # Labels / Regular Text
BOLD     = "\033[1m"     # Emphasis
NC       = "\033[0m"     # No Color (Reset)

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

def print_stat_row(label, value):
    """Pads the text first so ANSI codes don't mess up the alignment."""
    # 1. Create the padded strings (raw text)
    padded_label = f"{label:<18}"
    padded_value = f"{value:>19}" 
    
    # 2. Wrap them in color codes and print
    # Note: I used 18 and 19 to fit your 42-character wide box perfectly
    row = f"{GREEN}{BOLD}│{NC} {WHITE}{padded_label}{NC} {GREEN}{BOLD}│{NC} {CYAN}{padded_value}{NC} {GREEN}{BOLD}│{NC}"
    logging.info(row)

def draw_progress(current, total, prefix=""):
    """Renders a progress bar aligned to the left with a fixed-width prefix."""
    if total <= 0: return
    
    bar_len = 40
    filled = int(bar_len * current // total)
    bar = ('█' * filled).ljust(bar_len)
    percent = int(100 * current / total)
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Use f-string padding (e.g., :<10) to force the prefix to a fixed width
    # This keeps the bars aligned regardless of prefix word length
    output = f"\r[{timestamp}] {prefix:<10} |{bar}| {percent:>3}% ({current}/{total})"
    
    sys.stdout.write(output)
    sys.stdout.flush()

    if current == total:
        # sys.stdout.write("\n") # Keep commented if handled by parent
        sys.stdout.flush()

# --- Utility & Crypto Functions ---

def check_python_version():
    """
    Enforces Python version boundaries and library health.
    v2.2.0 Signal Protocol: Returns True if safe, False if incompatible.
    """
    try:
        # 1. Python Version Boundaries
        MIN_PY = (3, 8)
        MAX_PY = (3, 11)
        current = sys.version_info[:2]

        if current < MIN_PY or current > MAX_PY:
            logging.critical(
                f"{RED}[FATAL]{NC} Python {current[0]}.{current[1]} is unsupported. "
                f"Range: {MIN_PY[0]}.{MIN_PY[1]} to {MAX_PY[0]}.{MAX_PY[1]}"
            )
            return False

        # # 2. Critical Dependency Check (v2.2.0 Pinned Stack)
        # try:
        #     import cryptography
        #     from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        #     # logging.debug(f"Crypto Engine: {cryptography.__version__} - OK")
        # except ImportError:
        #     logging.critical(f"{RED}[FATAL]{NC} 'cryptography' library missing. Run: pip install cryptography==3.4.8")
        #     return False

        return True

    except Exception as e:
        logging.error(f"{RED}[ERROR]{NC} Environment check failed: {e}")
        return False
        
def get_crypto_primitives():
    """Lazy-load and version-verify cryptography requirements."""
    try:
        import cryptography
        from packaging import version # Optional dependency for checking
        
        # Simple string-based check if 'packaging' isn't available
        ver = cryptography.__version__
        if int(ver.split('.')[0]) < 3:
            logging.warning(f"{YELLOW}[!] Cryptography version {ver} is outdated.{NC}")

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        
        return AESGCM, PBKDF2HMAC, hashes, default_backend

    except ImportError:
        logging.error(f"{RED}[ERROR]{NC} AES requested but 'cryptography' package not found.")
        logging.info(f"{YELLOW}[INFO]{NC} To use AES mode, install it with: pip install --require-hashes -r requirements.txt")
        return None    

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

def encrypt_payload_aes(data, password, iterations):
    """
    Encrypts a byte blob using __algo__.
    Returns: (ciphertext, crypto_meta_dict)
    """

    # 1. Load primitives (Lazy import check)
    primitives = get_crypto_primitives()
    
    if primitives is None:
        return False

    AESGCM, PBKDF2HMAC, hashes, default_backend = primitives

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
    primitives = get_crypto_primitives()
    
    if primitives is None:
        return False

    AESGCM, PBKDF2HMAC, hashes, default_backend = primitives

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
            draw_progress(i, len(all_paths), prefix="Zipping")
    
    sys.stdout.write("\n") # Visual spacer after progress bar
    return buf.getvalue()

# def get_sorted_files(directory, extension=None):
#     """Gathers all files in a directory, optionally filtered by extension."""
#     if not os.path.exists(directory): return []
#     flist = []
#     for root, _, files in os.walk(directory):
#         for f in files:
#             if extension and not f.lower().endswith(extension): continue
#             flist.append(os.path.join(root, f))
#     flist.sort(); return flist

# def filter_carriers(all_pdfs, exclude_chars):
#     """Filters carrier PDFs based on presence of forbidden characters."""
#     available_pool, char_excluded = [], []
#     for f in all_pdfs:
#         fname = os.path.basename(f)
#         if any(char in fname for char in exclude_chars):
#             char_excluded.append(fname); continue
#         available_pool.append({'path': f, 'size': os.path.getsize(f)})
#     return available_pool, char_excluded

# def select_carrier_pool(files, payload_len, max_carriers_size_incr, max_count, password=None):
#     """Shuffles and selects a subset of PDFs for shards."""
#     pool = sorted(files, key=lambda x: x['path'].lower())
#     if password: random.Random(password).shuffle(pool)
#     selected, current_cap = [], 0
#     for f in pool:
#         limit = int(f['size'] * max_carriers_size_incr)
#         if len(selected) < max_count and current_cap < payload_len:
#             selected.append(f); current_cap += limit
#     return selected, current_cap

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

def inject_shard(target_path, shard):
    """Appends shard data to the end of a file without creating a copy."""
    try:
        with open(target_path, 'ab') as f:
            f.write(shard)
        return True
    except Exception as e:
        logging.error(f"In-place write failed for {target_path}: {e}")
        return False

def perform_injection(selected_pool, encrypted, args, crypto_meta):
    """
    Orchestrates shard distribution and generates the master manifest.
    Updated for v2.1.0: Returns True on success, False on failure.
    """
    try:
        total_pool_bytes = sum(c['size'] for c in selected_pool)
        payload_len = len(encrypted)
        cursor, manifest_entries = 0, []
        active_password = args.password

        logging.info(f"{BOLD}--- PERFORMING INJECTION ---{NC}")

        for i, c in enumerate(selected_pool, 1):
            rel_path = os.path.relpath(c['path'], args.hide_carrier)
            
            if args.mark_carrier_chars:
                base, ext = os.path.splitext(rel_path)
                rel_path = f"{base}{args.mark_carrier_chars}{ext}"
                
            shard_size = math.floor((c['size'] / total_pool_bytes) * payload_len)
            shard = encrypted[cursor:] if i == len(selected_pool) else encrypted[cursor:cursor + shard_size]
            
            # Forensic Shard Hash
            shard_hash = hashlib.sha256(shard).hexdigest()[:16]

            # File Stats & Physical Injection
            start_offset = os.path.getsize(c['path'])
            st = os.stat(c['path'])
            original_birth = getattr(st, 'st_birthtime', st.st_mtime)
            
            if not inject_shard(c['path'], shard):
                logging.error(f"{RED}[ERROR]{NC} Pipeline failure at carrier: {c['path']}")
                return False # Signal failure to main

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

            cursor += len(shard)
            draw_progress(i, len(selected_pool), prefix="Injecting")
        
        sys.stdout.write("\n")

        # 4. Finalize the Master Manifest (v2.1.0)
        session_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "crypto": crypto_meta,
            "hide_payload": args.hide_payload,
            "hide_carrier_backup": args.hide_carrier_backup,
            "carriers_total": len(manifest_entries),
            "carriers": manifest_entries
        }

        if not args.no_log_password:
            session_data["password"] = active_password

        with open(args.json_file, "w") as f:
            json.dump(session_data, f, indent=4)

        logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} {args.json_file} generated with {crypto_meta.get('algo', 'xor').upper()} metadata.")
        
        return True # Success signaled to main

    except Exception as e:
        logging.error(f"{RED}[CRITICAL]{NC} Injection process interrupted: {e}")
        return False
    
def secure_shred_file(path):
    """Forensic-grade file wipe: Rename, random fill, sync, unlink."""
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
    
def dirlist(target_dir):
    """
    Utility: Low-level directory scanner.
    Scans a directory recursively and returns a sorted list of PDF basenames.
    Returns None if the path does not exist.
    """
    if not os.path.exists(target_dir):
        return None

    pdf_files = []
    for root, _, files in os.walk(target_dir):
        for f in files:
            if f.lower().endswith(".pdf"):
                # Capturing just the filename for exclusion engine matching
                pdf_files.append(f)
                
    pdf_files.sort()
    return pdf_files

def exclude(args):
    """
    Action Workflow: High-level UI/IO layer.
    Generates a targeted exclusion list using percentage-based random elimination.
    v2.7.0: Scale-invariant percentage tracking. Zero/negative inputs explicitly rejected.
    """
    try:
        logging.info(f"\n{BLUE}{BOLD}--- DIRECTORY MANIFEST EXPORT ---{NC}")
        
        # 1. Parameter Validation Guard
        if args.random_drop <= 0 or args.random_drop > 100:
            logging.error(f"{RED}[ERROR]{NC} Invalid drop percentage: {args.random_drop}%. Value must be between 0 (exclusive) and 100.")
            return False

        # 2. Core Data Acquisition
        logging.info(f"{CYAN}[SCAN]{NC} Reading assets from: {args.hide_carrier}...")
        all_pdfs = dirlist(args.hide_carrier)
        
        if all_pdfs is None:
            logging.error(f"{RED}[ERROR]{NC} Target path does not exist: {args.hide_carrier}")
            return False

        if not all_pdfs:
            logging.warning(f"{YELLOW}[WARN]{NC} Directory is empty or contains zero PDF targets.")
            return False

        total_available = len(all_pdfs)

        # 3. Percentage-to-Count Conversion
        # Use max(1, ...) to guarantee at least 1 file drops if a fractional percentage is chosen
        drop_count = max(1, int(total_available * (args.random_drop / 100.0)))
        
        logging.info(f"{YELLOW}[PROPORTION]{NC} Target slice: {args.random_drop}% of pool.")

        # 4. Elimination Processing
        if drop_count >= total_available:
            logging.warning(f"{YELLOW}[WARN]{NC} Computed drop count ({drop_count}) covers total files ({total_available}). Blacklisting whole folder.")
            excluded_pool = all_pdfs
        else:
            logging.info(f"{YELLOW}[RANDOM]{NC} Selecting {drop_count}/{total_available} carriers for random exclusion...")
            excluded_pool = random.sample(all_pdfs, drop_count)
            
            # Print the precise filenames hitting the exclusion vector
            for f in sorted(excluded_pool):
                logging.info(f"  {RED}[DROPPED]{NC} {os.path.basename(f)}")

        # 5. Structure Assignment (Portable Base Names Only)
        payload_data = {
            "excluded_files": [os.path.basename(f) for f in excluded_pool]
        }

        # 6. Secure File Write Block
        output_dest = args.exclude_carrier_file
        logging.info(f"{CYAN}[EXPORT]{NC} Writing {len(excluded_pool)} blacklisted items to {output_dest}...")
        
        with open(output_dest, 'w', encoding='utf-8') as f:
            json.dump(payload_data, f, indent=2, ensure_ascii=False)

        logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} Exclusion manifest finalized flawlessly.")
        return True

    except Exception as e:
        logging.error(f"{RED}[CRITICAL]{NC} dirlist2json workflow collapsed: {e}")
        return False

def dir(args):
    """
    Action Workflow: High-level UI layer.
    Uses dirlist() to grab available assets and outputs a structured terminal layout.
    """
    try:
        logging.info(f"\n{BLUE}{BOLD}--- TARGET CARRIER INDEX ---{NC}")
        
        # 1. Reuse our existing decoupled scanner
        all_pdfs = dirlist(args.hide_carrier)
        
        if all_pdfs is None:
            logging.error(f"{RED}[ERROR]{NC} Target directory not found: {args.hide_carrier}")
            return False

        if not all_pdfs:
            logging.warning(f"{YELLOW}[WARN]{NC} Directory is empty or contains zero PDF targets.")
            return False

        # 2. Render clean scannable layout
        logging.info(f"{CYAN}[INDEX]{NC} Located {len(all_pdfs)} potential carrier(s) in '{args.hide_carrier}':")
        print("-" * 75)
        for idx, fname in enumerate(all_pdfs, start=1):
            # Print a neat numbered list for the operator
            print(f"  {CYAN}{idx:02d}.{NC} {fname}")
        print("-" * 75)
        
        return True

    except Exception as e:
        logging.error(f"{RED}[CRITICAL]{NC} dir_print workflow collapsed: {e}")
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

# --- Functions ---

import random

def hide(args):
    """
    Main workflow for carrier selection and binary embedding with backup.
    v2.5.0: Standardized on pure AES-256-GCM baseline; stripped legacy XOR paths.
    """
    try:
        logging.info(f"\n{BLUE}{BOLD}--- [2] PAYLOAD HIDING ---{NC}")
        
        if not args.password: 
            args.password = generate_robust_password()

        # 1. Payload Acquisition
        raw_payload = get_zip_memory(args.hide_payload)
        if not raw_payload:
            logging.error(f"{RED}[ERROR]{NC} Failed to prepare payload.")
            return False
            
        # 2. Unified Crypto Dispatcher (Pure AES-256-GCM Infrastructure)
        logging.info(f"{CYAN}[CRYPTO]{NC} Mode: AES-256-GCM | Iterations: {args.iterations:,}")
        result = encrypt_payload_aes(raw_payload, args.password, args.iterations)
        if result is False:
            return False
        
        # Unpack the verified payload data and tracking metadata
        encrypted, crypto_meta = result
        payload_size = len(encrypted)
        
        # 3. Carrier Selection Logic (Structured JSON Engine)
        exclude_carrier = set()
        exclude_log = []
        
        if args.exclude_carrier_file and os.path.exists(args.exclude_carrier_file):
            try:
                with open(args.exclude_carrier_file, 'r') as f:
                    exclude_data = json.load(f)
                
                if isinstance(exclude_data, list):
                    exclude_carrier = {os.path.basename(str(item).strip()) for item in exclude_data if item}
                elif isinstance(exclude_data, dict):
                    file_list = exclude_data.get("excluded_files", [])
                    exclude_carrier = {os.path.basename(str(item).strip()) for item in file_list if item}
                else:
                    logging.warning(f"{YELLOW}[WARN]{NC} Unexpected JSON format in exclusion file. Proceeding with empty set.")
            except json.JSONDecodeError as je:
                logging.error(f"{RED}[ERROR]{NC} Exclusion file contains corrupt JSON syntax: {je}")
                return False
            except Exception as e:
                logging.error(f"{RED}[ERROR]{NC} Failed reading exclusion manifest: {e}")
                return False

        # Gather targets from filesystem
        all_pdfs = [os.path.join(r, f) for r, _, fs in os.walk(args.hide_carrier) for f in fs if f.lower().endswith(".pdf")]
        
        # Random pool shuffle for chaotic distribution
        random.shuffle(all_pdfs)
        available = []

        for f in all_pdfs:
            fname = os.path.basename(f)
            char_match = any(c in fname for c in args.exclude_carrier_chars) if args.exclude_carrier_chars else False
            file_match = fname in exclude_carrier
            
            if char_match or file_match:
                reason = f"{'FILE' if file_match else ''}{' + ' if file_match and char_match else ''}{'CHAR' if char_match else ''}"
                exclude_log.append((f"  [SKIP] {fname}", reason))
            else:
                available.append({
                    'path': f, 
                    'size': os.path.getsize(f),
                    'pre_meta': get_current_meta(f) 
                })

        # Display Skip List (Alpha sorting for terminal display consistency)
        if exclude_log:
            logging.info(f"{CYAN}[EXCLUDE]{NC} Skip list:")
            widths = [65, 30]
            logging.info("-" * 103)
            for fname_formatted, reason in sorted(exclude_log, key=lambda x: x[0]):
                print_table_row([fname_formatted, reason], widths, ["", YELLOW])
            logging.info("-" * 103)

        # 4. Capacity Check (v2.5.5 Deficit Reporting Engine)
        selected, current_cap = [], 0
        for f in available:
            if len(selected) >= args.max_carriers_number:
                break
                
            if current_cap < payload_size or len(selected) < args.min_carriers_number:
                selected.append(f)
                current_cap += int(f['size'] * args.max_carriers_size_incr)
            else:
                break

        # Reporting missing capacity
        if current_cap < payload_size:
            missing_bytes = payload_size - current_cap
            missing_mb = missing_bytes / (1024 * 1024)
            payload_mb = payload_size / (1024 * 1024)
            current_cap_mb = current_cap / (1024 * 1024)

            logging.error(f"{RED}[ERROR]{NC} Insufficient capacity in carrier pool.")
            logging.error(
                f"Required Payload: {payload_mb:.2f} MB | "
                f"Available Carrier Cap: {current_cap_mb:.2f} MB"
            )
            logging.error(f"{YELLOW}[DEFICIT]{NC} You are missing exactly {BOLD}{missing_mb:.2f} MB{NC} of storage capacity.")
            return False

        # 5. Backup Logic
        if args.hide_carrier_backup:
            if not os.path.exists(args.hide_carrier_backup):
                os.makedirs(args.hide_carrier_backup)
            
            logging.info(f"{CYAN}[BACKUP]{NC} Archiving {len(selected)} carriers...")
            for f in selected:
                shutil.copy2(f['path'], os.path.join(args.hide_carrier_backup, os.path.basename(f['path'])))
            logging.info(f"{GREEN}[SUCCESS]{NC} Backup complete.")

        # 6. Execute Injection
        if not perform_injection(selected, encrypted, args, crypto_meta):
            return False

        # 7. Unified Stats Reporting
        total_carrier_size = sum(c['size'] for c in selected)
        total_storage_mb = (total_carrier_size + len(encrypted)) / (1024 * 1024)
        avg_growth = (len(encrypted) / total_carrier_size) * 100 if total_carrier_size > 0 else 0
        
        logging.info(f"\n{CYAN}[TARGETS]{NC} Chosen carriers for this injection session:")
        logging.info("-" * 103)
        for idx, c in enumerate(selected, start=1):
            fname = os.path.basename(c['path'])
            size_mb = c['size'] / (1024 * 1024)
            logging.info(f"  {CYAN}{idx:02d}.{NC} {fname:<75} ({size_mb:.2f} MB)")
        logging.info("-" * 103)

        logging.info(f"{GREEN}{BOLD}┌──────────────────────────────────────────┐{NC}")
        logging.info(f"{GREEN}{BOLD}│              INJECTION STATS             │{NC}")
        logging.info(f"{GREEN}{BOLD}├────────────────────┬─────────────────────┤{NC}")
        print_stat_row("Payload Size", f"{len(encrypted)/(1024*1024):.2f} MB")
        print_stat_row("Carriers Used", f"{len(selected)} files")
        print_stat_row("Total Storage", f"{total_storage_mb:.2f} MB")
        print_stat_row("Avg. Growth", f"{avg_growth:.2f}%")
        logging.info(f"{GREEN}{BOLD}└────────────────────┴─────────────────────┘{NC}")    

        logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} Hide applied successfully.")
        return True

    except Exception as e:
        logging.error(f"{RED}[CRITICAL]{NC} Hide workflow failed: {e}")
        return False

def restore(args):
    """
    Reassembles shards and extracts content directly back to the source directory.
    v2.5.0: Hardened to support pure AES-256-GCM baseline recovery operations.
    """
    try:
        logging.info(f"\n{BLUE}{BOLD}--- [4] RESTORE PAYLOAD ---{NC}")
        
        # 1. Load Session Manifest
        if not os.path.exists(args.json_file):
            logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found.")
            return False

        with open(args.json_file, "r") as f:
            session_json = json.load(f)
            active_password = args.password or session_json.get("password")
            crypto_info = session_json.get("crypto", {})
            manifest = session_json.get("carriers", [])

        if not active_password:
            logging.error(f"{RED}[ERROR]{NC} No password provided or found in manifest.")
            return False

        # --- Reassembly Phase ---
        logging.info(f"{YELLOW}[RESTORE]{NC} Reassembling from {len(manifest)} carriers...")
        chunks = []
        
        for i, entry in enumerate(manifest, 1):
            target_path = os.path.join(args.hide_carrier, entry['file_name'])
                
            if not os.path.exists(target_path):
                logging.error(f"{RED}[ERROR]{NC} Carrier missing: {entry['file_name']}")
                return False

            with open(target_path, 'rb') as f:
                f.seek(entry['start_offset'])
                shard_data = f.read(entry['payload_size'])
                
                # Hardened Hash Check (Prefix-Aware Integrity Layer)
                current_hash = hashlib.sha256(shard_data).hexdigest()
                expected = entry.get('shard_hash', '')
                if not current_hash.startswith(expected):
                    logging.warning(f"{RED}[TAMPERED]{NC} Shard {i} integrity check failed!")
                
                chunks.append(shard_data)
            
            draw_progress(i, len(manifest), prefix="Reading")
        
        full_payload = b"".join(chunks)
        sys.stdout.write("\n")

        # --- 2. Decryption Infrastructure ---
        algo = crypto_info.get("algo", "").lower()
        
        # Enforce pure AES-256-GCM validation baseline
        if algo == "aes-256-gcm":
            logging.info(f"{CYAN}[CRYPTO]{NC} Method: AES-256-GCM | Verifying...")
            salt = bytes.fromhex(crypto_info["salt"])
            nonce = bytes.fromhex(crypto_info["nonce"])
            iters = crypto_info.get("iterations", 100000)
            decrypted_zip = decrypt_payload_aes(full_payload, active_password, salt, nonce, iters)
        else:
            logging.error(f"{RED}[ERROR]{NC} Unsupported or legacy crypto method detected: '{algo or 'None'}'.")
            return False
        
        if not decrypted_zip:
            logging.error(f"{RED}[ERROR]{NC} Decryption failed. Wrong password or corrupt data.")
            return False

        # --- 3. Final Extraction ---
        if not decrypted_zip.startswith(b'PK'):
            logging.error(f"{RED}[ERROR]{NC} Decryption succeeded but data is not a valid ZIP archive structure.")
            return False

        with io.BytesIO(decrypted_zip) as mem_buf:
            with zipfile.ZipFile(mem_buf) as zf:
                os.makedirs(args.hide_payload, exist_ok=True)
                items = zf.namelist()
                for i, item in enumerate(items, 1):
                    zf.extract(item, args.hide_payload)
                    draw_progress(i, len(items), prefix="Unpacking")
        
        sys.stdout.write("\n")
        logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} Data restored cleanly to '{args.hide_payload}'")
        return True
        
    except Exception as e:
        logging.error(f"\n{RED}{BOLD}[CRITICAL]{NC} Restoration failed: {e}")
        return False
    
def sync(args):
    """
    Aligns disk timestamps with JSON-stored forensic dates.
    v2.2.0: Returns True if sync completed, False on critical errors.
    """
    try:
        logging.info(f"\n{BLUE}{BOLD}--- [3] DATES ALIGNMENT ---{NC}")
        
        if not os.path.exists(args.json_file):
            logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found.")
            return False

        with open(args.json_file, "r") as f:
            data = json.load(f)
            manifest = data.get("carriers", [])
            # Grab oldest mtime to reset the folder later
            all_mtimes = [int(e.get('meta', {}).get('st_mtime') or e.get('meta', {}).get('mod', 0)) 
                          for e in manifest if e.get('meta')]

        if not os.path.exists(args.hide_carrier):
            logging.error(f"{RED}[ERROR]{NC} Target directory {args.hide_carrier} missing.")
            return False

        # Load libc for macOS birthtime support
        libc = None
        if sys.platform == "darwin":
            try:
                import ctypes
                libc = ctypes.CDLL("/usr/lib/libc.dylib", use_errno=True)
            except OSError:
                logging.warning(f"{YELLOW}[WARN]{NC} libc.dylib missing. Birth date sync unavailable.")

        logging.info(f"{CYAN}[INFO]{NC} Synchronizing {len(manifest)} carriers...")

        for i, entry in enumerate(manifest, 1):
            fname = entry['file_name']
            meta = entry.get('meta', {})
            path = os.path.join(args.hide_carrier, fname)

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
                    pass 

            # 3. Wipe macOS Extended Attributes (Clears 'Date Added' / 'Where From')
            if sys.platform == "darwin":
                subprocess.run(['xattr', '-c', path], capture_output=True)

        sys.stdout.write("\n") 

        # 4. Parent Directory Reset
        if all_mtimes:
            try:
                back_date = min(all_mtimes)
                os.utime(args.hide_carrier, (back_date, back_date))
                logging.info(f"{GREEN}[SUCCESS]{NC} Parent directory back-dated.")
            except Exception as e:
                logging.debug(f"Parent sync failed: {e}")

        logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} Forensic timestamps restored.")
        return True

    except Exception as e:
        logging.critical(f"{RED}[CRITICAL]{NC} Sync workflow failed: {e}")
        return False

def audit(args):
    """
    Forensic comparison report between JSON manifest and current disk state.
    v2.2.0: Returns True if all timestamps match within threshold, False otherwise.
    """
    try:
        logging.info(f"\n{BLUE}{BOLD}--- [7] DATES AUDIT ---{NC}")
        
        if not os.path.exists(args.json_file):
            logging.error(f"{RED}[ERROR]{NC} {args.json_file} missing.")
            return False
        
        with open(args.json_file, "r") as f:
            data = json.load(f)
            manifest = data.get("carriers", [])
            target_dir = args.hide_carrier
                    
        # Unified Layout Constants
        widths = [45, 7, 7, 7, 7]
        sep = "-" * (sum(widths) + 12)
        integrity_passed = True

        # --- [SECTION 1: PARENT DIRECTORY] ---
        if os.path.exists(target_dir):
            logging.info(sep)
            print_table_row(["CARRIER DIR", "BIRTH", "MOD", "ACC", "ADDED"], widths, [CYAN + BOLD] * 5)
            logging.info(sep)

            dir_meta = get_current_meta(target_dir)
            raw_name = f"[DIR] {os.path.basename(os.path.abspath(target_dir)) or target_dir}"
            
            # Forensic Check against oldest carrier timestamp to see if folder was altered
            all_mtimes = [int(e.get('meta', {}).get('st_mtime', 0)) for e in manifest if e.get('meta')]
            oldest_ts = min(all_mtimes) if all_mtimes else None

            def check_drift(disk_val, ref_ts):
                if ref_ts is None: return ("N/A", YELLOW, True)
                drift = abs(int(disk_val) - ref_ts)
                if drift <= args.drift_threshold:
                    return ("MATCH", GREEN, True)
                return ("FAIL", RED, False)

            m_txt, m_col, m_pass = check_drift(dir_meta['mod'], oldest_ts)
            a_txt, a_col, a_pass = check_drift(dir_meta['acc'], oldest_ts)
            
            if not (m_pass and a_pass): integrity_passed = False

            print_table_row([raw_name, "---", m_txt, a_txt, "---"], widths, [BLUE, "", m_col, a_col, ""])
            logging.info(sep)

        # --- [SECTION 2: CARRIER FILES] ---
        print_table_row(["CARRIER FILE", "BIRTH", "MOD", "ACC", "ADDED"], widths, [CYAN + BOLD] * 5)
        logging.info(sep)

        for entry in manifest:
            raw_fname = entry['file_name']
            meta_j = entry.get('meta', {})
            id_name = f"[{entry.get('carrier_index', '?')}] {raw_fname}"
            path = os.path.join(target_dir, raw_fname)

            if not os.path.exists(path):
                print_table_row([id_name, "MISSING"], [widths[0], sum(widths[1:])+9], ["", RED])
                integrity_passed = False
                continue

            meta_d = get_current_meta(path)

            def get_stat_info(json_val, disk_val):
                drift = abs((json_val or 0) - (disk_val or 0))
                if drift <= args.drift_threshold:
                    return ("MATCH", GREEN, True)
                return ("FAIL", RED, False)

            b_txt, b_col, b_p = get_stat_info(meta_j.get('st_birthtime') or meta_j.get('birth'), meta_d['birth'])
            m_txt, m_col, m_p = get_stat_info(meta_j.get('st_mtime') or meta_j.get('mod'), meta_d['mod'])
            a_txt, a_col, a_p = get_stat_info(meta_j.get('st_atime') or meta_j.get('acc'), meta_d['acc'])
            
            added_txt = "CLEAN" if meta_d['added'] is None else "DIRTY"
            added_col = GREEN if added_txt == "CLEAN" else RED
            
            if not (b_p and m_p and a_p) or added_txt == "DIRTY":
                integrity_passed = False

            print_table_row([id_name, b_txt, m_txt, a_txt, added_txt], widths, ["", b_col, m_col, a_col, added_col])

        logging.info(sep)
        
        if integrity_passed:
            logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} Forensic timestamps verified.")
            return True
        else:
            logging.error(f"{RED}{BOLD}[ALERT]{NC} Timestamp anomalies detected!")
            return False

    except Exception as e:
        logging.critical(f"{RED}[CRITICAL]{NC} Audit workflow failed: {e}")
        return False

def diff(args):
    """
    Compares actual disk size against expected manifest size.
    v2.2.0: Returns True if all sizes match exactly, False if any deviation is found.
    """
    try:
        logging.info(f"\n{BLUE}{BOLD}--- [5] CARRIER DIFF ---{NC}")
        
        if not os.path.exists(args.json_file):
            logging.warning(f"{YELLOW}[SKIP]{NC} No {args.json_file} found.")
            return False

        with open(args.json_file, "r") as f:
            session_json = json.load(f)
            manifest = session_json.get("carriers", [])

        # Table Layout
        widths = [45, 15, 20]
        headers = ["CARRIER", "GROWTH", "STATUS"]
        separator = "-" * (sum(widths) + 6)

        logging.info(separator)
        print_table_row(headers, widths, [CYAN + BOLD] * 3)
        logging.info(separator)
        
        integrity_passed = True

        for entry in manifest:
            rel = entry['file_name']
            path = os.path.join(args.hide_carrier, rel)
            id_name = f"[{entry.get('carrier_index', '?')}] {rel}"

            if not os.path.exists(path):
                print_table_row([id_name, "0 B", "MISSING"], widths, ["", "", RED])
                integrity_passed = False
                continue

            current_size = os.path.getsize(path)
            # Math: Where the payload starts + how big the payload is
            expected_size = entry['start_offset'] + entry['payload_size']
            
            # Growth is the total current size minus the original carrier size (start_offset)
            actual_growth = current_size - entry['start_offset']
            growth_str = f"+{actual_growth:,} B"

            if current_size == expected_size:
                status_text, status_col = "SIZE OK", GREEN
            else:
                delta = current_size - expected_size
                status_text = f"MISMATCH ({delta:+,}B)"
                status_col = RED
                integrity_passed = False
                
            print_table_row([id_name, growth_str, status_text], widths, ["", "", status_col])

        logging.info(separator)
        
        if integrity_passed:
            logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} All carrier dimensions are valid.")
            return True
        else:
            logging.error(f"{RED}{BOLD}[FAIL]{NC} Structural anomaly detected in carrier sizes!")
            return False

    except Exception as e:
        logging.critical(f"{RED}[CRITICAL]{NC} Diff workflow failed: {e}")
        return False

def hash(args):
    """
    Verifies hidden shards against forensic hashes in the manifest.
    v2.2.0: Returns True if all tracked shards match, False on corruption or missing files.
    """
    try:
        logging.info(f"\n{BLUE}{BOLD}--- [6] PAYLOAD INTEGRITY HASH ---{NC}")
        
        if not os.path.exists(args.json_file):
            logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found.")
            return False

        with open(args.json_file, "r") as f:
            data = json.load(f)
            manifest = data.get("carriers", [])
            target_dir = args.hide_carrier

        if not manifest:
            logging.warning(f"{YELLOW}[SKIP]{NC} No carriers found in manifest.")
            return True # Technically nothing is broken

        logging.info(f"{CYAN}[INFO]{NC} Verifying {len(manifest)} shards...")

        widths = [45, 20, 10]
        headers = ["CARRIER", "EXPECTED (SHA256)", "STATUS"]
        separator = "-" * (sum(widths) + 6)

        logging.info(separator)
        print_table_row(headers, widths, [CYAN + BOLD] * 3)
        logging.info(separator)

        integrity_passed = True

        for entry in manifest:
            rel = entry['file_name']
            idx = entry.get("carrier_index", "?")
            expected = entry.get('shard_hash', 'N/A')
            path = os.path.join(target_dir, rel)
            id_name = f"[{idx}] {rel}"

            if not os.path.exists(path):
                print_table_row([id_name, expected[:16], "MISSING"], widths, ["", "", RED])
                integrity_passed = False
                continue

            try:
                with open(path, "rb") as f:
                    # Forensic Seek: Isolate the payload bytes
                    f.seek(entry['start_offset'])
                    actual_data = f.read(entry['payload_size'])
                    
                    # Verify read length matches manifest
                    if len(actual_data) != entry['payload_size']:
                        print_table_row([id_name, expected[:16], "TRUNCATED"], widths, ["", "", RED])
                        integrity_passed = False
                        continue

                    current_hash = hashlib.sha256(actual_data).hexdigest()
                    
                    if expected == 'N/A':
                        status_text, status_col = "UNTRACKED", YELLOW
                    elif current_hash.startswith(expected) or current_hash[:16] == expected:
                        status_text, status_col = "MATCH", GREEN
                    else:
                        status_text, status_col = "CORRUPT", RED
                        integrity_passed = False
                        
                    print_table_row([id_name, expected[:16], status_text], widths, ["", "", status_col])
                    
            except Exception as e:
                print_table_row([id_name, expected[:16], "READ ERR"], widths, ["", "", RED])
                integrity_passed = False

        logging.info(separator)
        
        if integrity_passed:
            logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} All payload shards verified.")
            return True
        else:
            logging.error(f"{RED}{BOLD}[FAIL]{NC} Integrity violation detected in shards!")
            return False

    except Exception as e:
        logging.critical(f"{RED}[CRITICAL]{NC} Hash workflow failed: {e}")
        return False

def touch(args):
    """
    Forensic Command: Detects 'Stat Diff' (Metadata drift).
    v2.2.0: Returns True if all carriers are OK, False if drift/missing files detected.
    """
    try:
        logging.info(f"\n{BLUE}{BOLD}--- [9] TOUCH AUDIT ---{NC}")
        
        if not os.path.exists(args.json_file):
            logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found.")
            return False

        with open(args.json_file, "r") as f:
            data = json.load(f)
            manifest = data.get("carriers", [])
            carriers_total = data.get("carriers_total", len(manifest))

        logging.info(f"{CYAN}[INFO]{NC} Auditing {carriers_total} carriers ({args.drift_threshold}s tolerance)...")

        widths = [50, 20, 10]
        headers = ["CARRIER", "TIMESTAMP DRIFT", "STATUS"]
        separator = "-" * (sum(widths) + 6)

        logging.info(separator)
        print_table_row(headers, widths, [CYAN + BOLD, CYAN + BOLD, CYAN + BOLD])
        logging.info(separator)

        integrity_passed = True

        for entry in manifest:
            rel = entry['file_name']
            path = os.path.join(args.hide_carrier, rel)
            id_name = f"[{entry.get('carrier_index', '?')}] {rel}"

            if not os.path.exists(path):
                print_table_row([id_name, "N/A", "MISSING"], widths, ["", "", RED])
                integrity_passed = False
                continue

            st = os.stat(path)
            meta = entry.get("meta", {})
            stored_mtime = meta.get("st_mtime")
            
            if stored_mtime is None:
                print_table_row([id_name, "Unknown", "NO SIG"], widths, ["", "", YELLOW])
                # We don't necessarily fail on NO SIG, but we warn
            else:
                drift = st.st_mtime - stored_mtime
                drift_msg = f"{drift:+.2f}s"
                
                if abs(drift) <= args.drift_threshold:
                    print_table_row([id_name, drift_msg, "OK"], widths, ["", "", GREEN])
                else:
                    print_table_row([id_name, drift_msg, "TOUCHED"], widths, ["", "", RED])
                    integrity_passed = False

        logging.info(separator)
        
        if integrity_passed:
            logging.info(f"{GREEN}{BOLD}[SUCCESS]{NC} All carriers verified within threshold.")
            return True
        else:
            logging.warning(f"{RED}{BOLD}[ALERT]{NC} Integrity compromise detected!")
            return False

    except Exception as e:
        logging.error(f"{RED}[CRITICAL]{NC} Audit crashed: {e}")
        return False

def erase(args):
    """
    Forensic Command: Wipes the session manifest, blacklist targets, and associated payloads.
    v2.2.0: Now securely targets and destroys the exclude_carrier_file asset.
    """
    try:
        logging.info(f"{RED}{BOLD}--- [8] ERASE ---{NC}")
        
        # 1. Harvest targets
        targets = {args.json_file} # Always target the main manifest
        
        # Core additions to the wipe targets
        if args.hide_payload: 
            targets.add(args.hide_payload)
        if args.hide_carrier_backup: 
            targets.add(args.hide_carrier_backup)
        if args.exclude_carrier_file: 
            targets.add(args.exclude_carrier_file)

        # 2. Dynamic Discovery (The Manifest Hit-List)
        if os.path.exists(args.json_file):
            try:
                with open(args.json_file, 'r') as f:
                    manifest = json.load(f)
                    if manifest.get("hide_payload"):
                        targets.add(manifest["hide_payload"])
                    if manifest.get("hide_carrier_backup"):
                        targets.add(manifest["hide_carrier_backup"])
                    # If the manifest explicitly tracked a custom exclusion file path, snag it too
                    if manifest.get("exclude_carrier_file"):
                        targets.add(manifest["exclude_carrier_file"])
            except Exception as e:
                logging.warning(f"{YELLOW}[WARN]{NC} Manifest unreadable, skipping dynamic discovery: {e}")

        # 3. Execution
        method = 'erase' if args.fast_erase else 'secure'
        all_cleared = True

        # Filter and sort (files before dirs via reverse sorting strings)
        to_wipe = [t for t in targets if t and os.path.exists(t)]
        
        if not to_wipe:
            logging.info(f"{CYAN}[INFO]{NC} No forensic traces located. System clean.")
            return True

        for target in sorted(to_wipe, reverse=True):
            try:
                erase_path(target, method)
                logging.info(f"{YELLOW}[WIPE]{NC} Destroyed: {target}")
            except Exception as e:
                logging.error(f"{RED}[ERROR]{NC} Failed to wipe {target}: {e}")
                all_cleared = False

        if all_cleared:
            logging.info(f"{GREEN}{BOLD}[COMPLETE]{NC} Targeted forensic data erased.")
            return True
        else:
            logging.warning(f"{YELLOW}[INCOMPLETE]{NC} Some paths could not be fully cleared.")
            return False

    except Exception as e:
        logging.critical(f"{RED}[CRITICAL]{NC} Erase workflow failed: {e}")
        return False

# --- Main ---

def main():

    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Steganography Suite v{__version__}{NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"{CYAN}v2.0.2: Stateful Backup & Forensic Timeline Auditing{NC}"
    )
    
    # 1. Commands - Added 'touch' to the choices
    parser.add_argument("action", choices=['hide', 'restore', 'diff', 'hash', 'sync', 'audit', 'erase', 'touch', 'dir', 'exclude'], help="Action to perform")
    
    crypto = parser.add_argument_group(f'{CYAN}Encryption and security parameters{NC}')

    crypto.add_argument(
        "--iterations", 
        type=int, 
        default=__iterations__,
        help=__kdf__+ " iterations for "+ __algo__ +" key stretching (default: "+str(__iterations__)+")"
    )    
    crypto.add_argument(
        "password", 
        nargs='?', 
        help="Encryption password. If omitted in XOR mode, one is generated."
    )
    crypto.add_argument(
        "--no_log_password",
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
    sessions.add_argument("-jf", "--json_file", default=__json_file_name__, 
                          help="Carrier map file (Default: " + __json_file_name__ + ").")
    
    carriers = parser.add_argument_group(f'{CYAN}Carrier Management{NC}')
    carriers.add_argument("-mn", "--min_carriers_number", type=int, default=8,
                        help="Minimum number of carriers to split payload across (Default: 8).")
    carriers.add_argument("-mc", "--max_carriers_number", type=int, default=64, 
                          help="Max carriers to utilize (Default: 64).")
    carriers.add_argument("-sc", "--max_carriers_size_incr", type=float, default=0.30, 
                          help="Allowed growth ratio per carrier (Default: 30%%).")
    carriers.add_argument("-xc", "--exclude_carrier_chars", nargs='?', const="^+§", default=None,
                          help="Skip carriers with these characters (Default: ^+§).")
    carriers.add_argument("-xf", "--exclude_carrier_file", default="exclude_carrier.json",
                          help="Blacklist file path (Default: exclude_carrier.json).")
    carriers.add_argument("-kc", "--mark_carrier_chars", default="", 
                          help="Characters to append to carrier filename (Default: None).")

    parser.add_argument(
        "-rd", "--random_drop", 
        type=float, 
        default=10.0,  # Defaulting to 10% of the active carrier pool
        help="Percentage of carrier files to randomly drop into the exclusion manifest (Default: 10.0)."
    )

    erasure = parser.add_argument_group(f'{CYAN}Erase Management{NC}')
    erasure.add_argument("--fast_erase", action="store_true", 
                         help="Use standard OS removal instead of forensic shredding.")

    forensics = parser.add_argument_group(f'{CYAN}Forensic Auditing{NC}')
    forensics.add_argument("-dt", "--drift_threshold", type=float, default=1.0,
                           help="Timestamp drift tolerance in seconds (Default: 1.0).")
    # Global Flags
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # Boundary Validation Guardrail
    if args.min_carriers_number > args.max_carriers_number:
        parser.error(
            f"Configuration Error: --min_carriers_number ({args.min_carriers_number}) "
            f"cannot be greater than --max_carriers_number ({args.max_carriers_number})."
        )

    # 2. Combinatorial Entropy Warning (v2.4.0 Mathematical Security Floor)
    if args.min_carriers_number < 8:
        import math
        current_perms = math.factorial(args.min_carriers_number)
        baseline_perms = math.factorial(8)
        
        logging.warning(
            f"{YELLOW}[WARNING]{NC} Low-entropy structural floor detected (-mn {args.min_carriers_number})."
        )
        logging.warning(
            f"          Combinatorial permutations reduced from {baseline_perms:,} (8!) down to {current_perms:,} ({args.min_carriers_number}!)."
        )
        logging.warning(
            f"          This significantly compromises physical assembly scrambling security."
        )

    # 3. Actions dictionary
    actions = {
        'hide': hide, 
        'restore': restore,
        'diff': diff, 
        'hash': hash,
        'sync': sync,
        'audit': audit,
        'erase': erase,
        'touch': touch,
        'dir' : dir,
        'exclude' : exclude
    }    

    result = False

    if args.action in actions:
        try:
            # Check environment 
            result = check_python_version()
            # Execute the function and capture the success signal
            if result:
                result = actions[args.action](args)
        except KeyboardInterrupt:
            logging.info(f"\n{YELLOW}[SHUTDOWN]{NC} User aborted operation.")
            sys.exit(0)
        except Exception as e: 
            logging.critical(f"{RED}{BOLD}[FATAL ERROR]{NC} {str(e)}")
            # Optional: Log traceback for development
            # import traceback; logging.debug(traceback.format_exc())
            sys.exit(1)

    # Global Signal: 0 for Success, 1 for Failure
    if result is True:
        sys.exit(0)
    else:
        logging.error(f"{RED}[EXIT]{NC} Workflow terminated with errors.")
        sys.exit(1)

if __name__ == "__main__":
    main()
