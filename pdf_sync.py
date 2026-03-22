import os
import sys
import ctypes
import struct
import glob
import subprocess
import time
import re
import argparse
import logging

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
        logging.error(f"{RED}{BOLD}[ERROR]{NC} libc.dylib not found. Creation date sync will fail.")
        return

    logging.info(f"\n{BLUE}{BOLD}--- [3] METADATA ALIGNMENT ---{NC}")
    logging.info(f"{CYAN}{BOLD}[INFO]{NC} Synchronizing timestamps and birth dates...")

    for fname in file_list:
        dst = os.path.join(found_carrier, fname)
        src = os.path.join(hide_carrier, fname)
        
        if not os.path.exists(src) or not os.path.exists(dst): continue
        
        m_orig = get_meta(src)

        # STEP A: Native Python Timestamp Sync
        try:
            os.utime(dst, (m_orig['acc_raw'], m_orig['mod_raw']))
        except Exception as e:
            logging.warning(f"{YELLOW}{BOLD}[WARN]{NC} utime failed for {fname}: {e}")

        # STEP B: Kernel-Level Birth Date
        try:
            attr_list = struct.pack("HHHHH", 5, 0, 0x00000200, 0, 0)
            time_buf = struct.pack("qq", m_orig['birth_raw'], 0)
            libc.setattrlist(dst.encode(), attr_list, time_buf, len(time_buf), 0)
        except Exception as e:
            logging.warning(f"{YELLOW}{BOLD}[WARN]{NC} setattrlist failed for {fname}: {e}")
        
        logging.info(f"{GREEN}{BOLD}[SYNC]{NC} Timestamp alignment: {fname}")

def audit(hide_carrier, found_carrier, file_list):
    """Forensic comparison report."""
    logging.info(f"\n{BLUE}{BOLD}--- [7] TIMESTAMP SYNC ---{NC}")
    logging.info(f"\n{BOLD}Forensic 4-Point Audit Report{NC}")
    logging.info("-" * 90)
    for fname in sorted(file_list):
        s_path = os.path.join(found_carrier, fname)
        o_path = os.path.join(hide_carrier, fname)
        if not os.path.exists(o_path) or not os.path.exists(s_path): continue
        m_o, m_s = get_meta(o_path), get_meta(s_path)
        logging.info(f"\n📄 {BOLD}{fname}{NC}")
        logging.info(f"{'ATTRIBUTE':<12} | {'ORIGINAL':<22} | {'STEGO':<22} | STATUS")
        logging.info("-" * 90)
        diff = m_s['size'] - m_o['size']
        logging.info(f"{'SIZE':<12} | {str(m_o['size']):<22} | {str(m_s['size']):<22} | {GREEN}VALID (+{diff}B){NC}")
        for label, key in [('BIRTH', 'birth_raw'), ('MOD', 'mod_raw'), ('ACCESS', 'acc_raw')]:
            status = f"{GREEN}MATCH{NC}" if m_o[key] == m_s[key] else f"{RED}FAIL{NC}"
            logging.info(f"{label:<12} | {str(m_o[key]):<22} | {str(m_s[key]):<22} | {status}")
        status_a = f"{GREEN}MATCH{NC}" if m_o['added_raw'] == m_s['added_raw'] else f"{RED}FAIL{NC}"
        logging.info(f"{'ADDED':<12} | {'Present' if m_o['added_raw'] else 'Empty':<22} | {'Present' if m_s['added_raw'] else 'Empty':<22} | {status_a}")

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
        logging.error(f"{RED}{BOLD}[ERROR]{NC} No target files found in {args.found_carrier}.")
        sys.exit(1)

    logging.info(f"{BOLD}Selection Mode:{NC} {mode_label}")
    logging.info(f"{BOLD}Files Found:{NC}    {len(target_files)}")
    logging.info(f"{BOLD}Action:{NC}         {args.action.upper()}\n")

    if args.action == 'audit':
        audit(args.hide_carrier, args.found_carrier, target_files)
    else:
        sync(args.hide_carrier, args.found_carrier, target_files)