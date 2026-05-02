import os
import sys
import ctypes
import struct
import json
import subprocess
import logging
import argparse
from datetime import datetime

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; RED = '\033[0;31m'; GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'; BLUE = '\033[0;34m'; CYAN = '\033[0;36m'

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(message)s',
    datefmt='%H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)

def get_current_meta(path):
    """Retrieves current on-disk metadata for auditing."""
    meta = {'birth': 0, 'mod': 0, 'acc': 0, 'size': 0, 'added': False}
    if not os.path.exists(path): return meta
    try:
        st = os.stat(path)
        meta['birth'] = int(getattr(st, 'st_birthtime', 0))
        meta['mod'] = int(st.st_mtime)
        meta['acc'] = int(st.st_atime)
        meta['size'] = st.st_size
        
        # Check for macOS 'Date Added' extended attribute
        res = subprocess.run(['xattr', '-p', 'com.apple.metadata:kMDItemDateAdded', path], 
                            capture_output=True)
        meta['added'] = res.returncode == 0
    except: pass
    return meta

def forensic_sync(args):
    """Aligns disk timestamps with JSON-stored forensic dates."""
    logging.info(f"\n{BLUE}{BOLD}--- [3] DATES ALIGNMENT ---{NC}")
    
    if not os.path.exists(args.json_file):
        logging.error(f"{RED}[ERROR]{NC} {args.json_file} not found.")
        return

    try:
        libc = ctypes.CDLL("/usr/lib/libc.dylib", use_errno=True)
    except OSError:
        logging.error(f"{RED}[CRITICAL]{NC} libc.dylib missing. Birth date sync unavailable.")
        return

    with open(args.json_file, "r") as f:
        data = json.load(f)
        manifest = data.get("carriers", [])
        mode = data.get("mode", "in-place")

    logging.info(f"{CYAN}[INFO]{NC} Processing {len(manifest)} carriers from session ({mode})...")

    for entry in manifest:
        fname = entry['file_name']
        meta = entry.get('meta', {})
        
        # Determine path based on hiding mode
        target_dir = args.hide_carrier if mode == "in-place" else args.found_carrier
        path = os.path.join(target_dir, fname)

        if not os.path.exists(path):
            logging.warning(f"  {YELLOW}[SKIP]{NC} Missing: {fname}")
            continue

        # 1. Standard utime (Modification/Access)
        m_time = int(meta.get('st_mtime', 0))
        a_time = int(meta.get('st_atime', 0))
        os.utime(path, (a_time, m_time))

        # 2. Kernel-Level Birth Date (Creation)
        b_time = int(meta.get('st_birthtime', 0))
        if b_time > 0:
            try:
                # attr_list: 5 shorts. 3rd is the bitmask (0x00000200 = ATTR_CMN_CRTIME)
                attr_list = struct.pack("HHHHH", 5, 0, 0x00000200, 0, 0)
                time_buf = struct.pack("qq", b_time, 0)
                libc.setattrlist(path.encode(), attr_list, time_buf, len(time_buf), 0)
            except Exception as e:
                logging.debug(f"Birthdate fail for {fname}: {e}")

        # 3. Wipe macOS Extended Attributes (The 'Date Added' Snitch)
        if sys.platform == "darwin":
            subprocess.run(['xattr', '-c', path], capture_output=True)

        logging.info(f"  {GREEN}[SYNCED]{NC} {fname}")

    # Sync parent directory date to hide the folder modification
    parent_meta = os.stat(args.hide_carrier)
    os.utime(args.hide_carrier, (parent_meta.st_atime, parent_meta.st_mtime))

def audit_report(args):
    """Forensic comparison report."""    
    logging.info(f"\n{BLUE}{BOLD}--- [7] DATES CHECK ---{NC}")
    
    if not os.path.exists(args.json_file):
        logging.error(f"{RED}[ERROR]{NC} {args.json_file} missing.")
        return
    
    with open(args.json_file, "r") as f:
        data = json.load(f)
        manifest = data.get("carriers", [])
        target_dir = args.hide_carrier if data.get("mode") == "in-place" else args.found_carrier
        mode = data.get("mode", "in-place")

    if not manifest: return
    max_name_len = max(len(entry['file_name']) for entry in manifest)
    col_w = max(max_name_len, 4)

    logging.info(f"{CYAN}[INFO]{NC} Comparing {len(manifest)} carriers from session ({mode})...")

    # --- Header Formatting ---
    # Each status column in the data is 7 chars wide (5 for MATCH + 2 spaces)
    # We match that exactly in the header.
    header = f"{'FILE':<{col_w}} | {'BIRTH':<5} | {'MOD':<5} | {'ACC':<5} | {'ADDED':<5}"
    separator = "-" * len(header)
    
    print(f"\n{BOLD}{header}{NC}")
    print(separator)

    for entry in manifest:
        fname = entry['file_name']
        meta_j = entry.get('meta', {})
        path = os.path.join(target_dir, fname)
        meta_d = get_current_meta(path)

        # Status strings (all exactly 5 chars)
        def get_stat(j, d):
            return f"{GREEN}MATCH{NC}" if int(j or 0) == int(d or 0) else f"{RED}FAIL {NC}"

        b_stat = get_stat(meta_j.get('st_birthtime'), meta_d['birth'])
        m_stat = get_stat(meta_j.get('st_mtime'), meta_d['mod'])
        a_stat = get_stat(meta_j.get('st_atime'), meta_d['acc'])
        added_stat = f"{GREEN}CLEAN{NC}" if not meta_d['added'] else f"{RED}DIRTY{NC}"

        # Each field is printed with a width of 5, matching the header titles.
        # The ANSI codes don't take up space in the terminal's physical grid.
        print(f"{fname:<{col_w}} | {b_stat} | {m_stat} | {a_stat} | {added_stat}")

def main():
    parser = argparse.ArgumentParser(description="PDF Metadata Sync (JSON Mode)")
    parser.add_argument("action", choices=['sync', 'audit'], help="Action to perform.")
    parser.add_argument("-j", "--json_file", default="carrier.json", help="Path to carrier.json")
    parser.add_argument("-hc", "--hide_carrier", default="hide_carrier", help="Target carrier directory")
    parser.add_argument("-fc", "--found_carrier", default="found_carrier", help="Directory for copy-replace mode")
    
    args = parser.parse_args()

    if args.action == 'sync':
        forensic_sync(args)
    else:
        audit_report(args)

if __name__ == "__main__":
    main()