import os, sys, ctypes, struct, glob, subprocess, time, re, argparse

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

def sync(source_dir, target_dir, file_list):
    """Safe-Sync: Forges timestamps and birth dates to match source carriers."""
    try:
        libc = ctypes.CDLL("/usr/lib/libc.dylib", use_errno=True)
    except OSError:
        log("ERROR", "libc.dylib not found. Creation date sync will fail.", RED)
        return

    log("INFO", f"Synchronizing metadata (Safe Mode)...", CYAN)

    for fname in file_list:
        dst = os.path.join(target_dir, fname)
        src = os.path.join(source_dir, fname)
        
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

def audit(source_dir, target_dir, file_list):
    """Forensic comparison report."""
    print(f"\n{BOLD}Forensic 4-Point Audit Report{NC}")
    print("-" * 90)
    for fname in sorted(file_list):
        s_path = os.path.join(target_dir, fname)
        o_path = os.path.join(source_dir, fname)
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
    """Configures the CLI with the final target_dir=restore_pdf_dir defaults."""
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Metadata Sync Tool (macOS Edition){NC}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("action", choices=['sync', 'audit'], 
                        help="Action to perform: 'sync' or 'audit'.")

    paths = parser.add_argument_group(f'{CYAN}Path Configuration{NC}')
    paths.add_argument("-s", "--source_dir", default="source_pdf_dir", help="Original PDF directory.")
    paths.add_argument("-t", "--target_dir", default="restore_pdf_dir", help="Modified PDF directory.")
    paths.add_argument("-l", "--list_file", default="pdf_files.txt", help="Manifest file list.")

    return parser.parse_args()

if __name__ == "__main__":
    args = setup_args()
    
    target_files = []
    mode_label = ""

    # Manifest Resolution
    if os.path.exists(args.list_file):
        with open(args.list_file, 'r') as f:
            target_files = [os.path.basename(l.strip()) for l in f if l.strip() and not l.startswith('#')]
        if target_files:
            mode_label = f"{CYAN}MANIFEST{NC} ({args.list_file})"
    
    # Directory Scan Fallback
    if not target_files:
        target_files = [os.path.basename(f) for f in glob.glob(os.path.join(args.target_dir, "*.pdf"))]
        mode_label = f"{YELLOW}DIRECTORY SCAN{NC} ({args.target_dir})"

    if not target_files:
        log("ERROR", f"No target files found in {args.target_dir}.", RED)
        sys.exit(1)

    print(f"{BOLD}Selection Mode:{NC} {mode_label}")
    print(f"{BOLD}Files Found:{NC}    {len(target_files)}")
    print(f"{BOLD}Action:{NC}        {args.action.upper()}\n")

    if args.action == 'audit':
        audit(args.source_dir, args.target_dir, target_files)
    else:
        sync(args.source_dir, args.target_dir, target_files)