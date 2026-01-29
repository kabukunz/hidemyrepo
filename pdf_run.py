import sys, argparse, os, shutil, time

# --- UI Constants ---
NC = '\033[0m'       # No Color
BOLD = '\033[1m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'

try:
    import pdf_hide
    import pdf_sync
except ImportError as e:
    print(f"Error: Missing baseline script - {e}")
    sys.exit(1)

def log(tag, message, color=NC):
    """Standardized tool logger."""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {color}{BOLD}[{tag}]{NC} {message}")

def log_header(title):
    """Functional section break."""
    print(f"\n{BOLD}{MAGENTA}--- {title} ---{NC}")

# --- Stage Functions (Modular for Testing) ---

def stage_stealth_check(args):
    """Pre-flight check with intelligent carrier suggestions."""
    all_pdfs = pdf_hide.get_sorted_files(args.source_pdf_dir, ".pdf")
    available, _ = pdf_hide.filter_carriers(all_pdfs, args.exclude_carrier_chars)
    
    # Sort largest to smallest for best-case budget calculation
    available.sort(key=lambda x: x['size'], reverse=True)
    
    active_pool = available[:args.max_carriers]
    total_raw_size = sum(f['size'] for f in active_pool)
    total_stealth_cap = total_raw_size * args.carrier_size_max_incr
    
    # Estimate source size
    source_size = 0
    for root, _, files in os.walk(args.source_dir):
        for f in files:
            source_size += os.path.getsize(os.path.join(root, f))
    
    print(f"  {pdf_hide.YELLOW}⚖ Stealth Inventory:{pdf_hide.NC}")
    print(f"    - Carriers Found: {len(available)}")
    print(f"    - Carriers Allowed: {args.max_carriers}")
    print(f"    - Effective Budget: {total_stealth_cap / 1024 / 1024:.2f} MB")
    print(f"    - Payload Estimate: {source_size / 1024 / 1024:.2f} MB")
    
    if source_size > total_stealth_cap:
        # Calculate needed count
        needed_count = 0
        running_cap = 0
        for f in available:
            needed_count += 1
            running_cap += (f['size'] * args.carrier_size_max_incr)
            if running_cap >= source_size:
                break
        
        print(f"\n  {pdf_hide.RED}❌ ABORTING: INSUFFICIENT BUDGET{pdf_hide.NC}")
        if running_cap < source_size:
            print(f"    {pdf_hide.RED}>> Error: Even with ALL carriers, space is insufficient.{pdf_hide.NC}")
        else:
            print(f"    {pdf_hide.CYAN}>> ACTION REQUIRED: Set --max_carriers {needed_count} or higher.{pdf_hide.NC}")
        return False # Signal failure
    
    print(f"    {pdf_hide.GREEN}✅ Capacity looks sufficient.{pdf_hide.NC}")
    return True # Signal success

def stage_prepare_payload(args):
    """Stage 1: Memory-resident compression and encryption."""
    raw = pdf_hide.get_zip_memory(args.source_dir)
    if not raw: return None
    return pdf_hide.xor_crypt(raw, args.password or "test")

def stage_select_carriers(args, payload_len):
    """Stage 2: Filtering and Keyed Shuffle selection."""
    all_pdfs = pdf_hide.get_sorted_files(args.source_pdf_dir, ".pdf")
    available, excluded = pdf_hide.filter_carriers(all_pdfs, args.exclude_carrier_chars)
    
    # PASSING PASSWORD HERE FOR DETERMINISTIC SHUFFLE
    selected, cap, reserves = pdf_hide.select_carrier_pool(
        available, payload_len, args.carrier_size_max_incr, args.max_carriers, 
        password=args.password
    )
    
    pdf_hide.check_capacity(cap, payload_len, available, args.carrier_size_max_incr)
    return selected

def stage_inject_and_sync(args, selected, encrypted):
    """Stage 3: Physical injection and metadata forgery."""
    manifest = pdf_hide.perform_injection(
        selected, encrypted, args.source_pdf_dir, args.restore_pdf_dir
    )
    pdf_hide.save_session(args.password, manifest)
    pdf_sync.sync(args.source_pdf_dir, args.restore_pdf_dir)
    return manifest

def stage_verify_tamper_detection(args, manifest):
    """Stage 4: Controlled corruption for security testing."""
    if not args.test_tamper or not manifest: return
    target_file = os.path.join(args.restore_pdf_dir, manifest[0])
    print(f"  {pdf_hide.YELLOW}! Intentionally corrupting: {os.path.basename(target_file)}{pdf_hide.NC}")
    with open(target_file, "ab") as f:
        f.write(b"\x00\xFF\x00\xFF")

# --- Orchestration ---

def log_step(name, status="START"):
    color = pdf_hide.BLUE if status == "START" else (pdf_hide.YELLOW if status == "TAMPER" else pdf_hide.GREEN)
    print(f"{pdf_hide.BOLD}{color}[{status}: {name}]{pdf_hide.NC}")

def run_pipeline(args):
    log_header("TOOL INITIALIZATION")
    
    # 1. Payload Analysis
    payload_files = pdf_hide.get_payload_files(args.source_dir)
    total_payload_size = sum(f['size'] for f in payload_files)
    log("INFO", f"Payload: {len(payload_files)} files ({total_payload_size} bytes)", BLUE)

    # 2. Carrier Selection & Logic
    available_pdfs = pdf_hide.get_available_carriers(args.source_pdf_dir, args.exclude_carrier_chars)
    password = args.password if args.password else pdf_hide.generate_robust_password()
    
    selected, current_cap, _ = pdf_hide.select_carrier_pool(
        available_pdfs, 
        total_payload_size, 
        args.carrier_size_max_incr, 
        args.max_carriers, 
        password=password
    )

    # Validate Capacity
    pdf_hide.check_capacity(current_cap, total_payload_size, available_pdfs, args.carrier_size_max_incr)

    # 3. Session Persistence (Saves manifest and password)
    manifest_filenames = [os.path.basename(f['path']) for f in selected]
    pdf_hide.save_session(password, manifest_filenames, dry_run=args.dry_run)

    if args.dry_run:
        log("DRY RUN", "Tool manifest saved. Physical write-access skipped.", YELLOW)
        print(f"\n{BOLD}{CYAN}[DRY RUN SUMMARY]{NC}")
        print(f"Target Carriers:  {len(selected)}")
        print(f"Stealth Capacity: {current_cap} bytes")
        return

# 4. Processing Phase
    log_header("DATA PROCESSING")
    
    # Compress the source directory into a single memory buffer
    raw_payload = pdf_hide.get_zip_memory(args.source_dir)
    if not raw_payload:
        log("ERROR", "No data found in source directory to process.", RED)
        return
        
    # Encrypt the buffer to create the final byte-stream
    log("INFO", f"Encrypting payload with provided key...", CYAN)
    encrypted_data = pdf_hide.xor_crypt(raw_payload, password)
    
    log("ACTION", f"Injecting shards into {len(selected)} carriers...", GREEN)
    
    # CORRECTED: Pass the 'encrypted_data' bytes, not the file list
    pdf_hide.perform_injection(
        selected, 
        encrypted_data, 
        args.source_pdf_dir, 
        args.restore_pdf_dir
    )

    # 5. Metadata Sync
    log_header("FORENSIC SYNCHRONIZATION")
    log("SYNC", "Mirroring original timestamps and attributes...", BLUE)
    import pdf_sync
    pdf_sync.sync(args.source_pdf_dir, args.restore_pdf_dir, manifest=manifest_filenames)

    log("STATUS", "Tool execution complete. Forensic parity achieved.", GREEN)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{pdf_hide.BOLD}PDF Forensic Execution Runner{pdf_hide.NC}\n"
                    "Orchestrates the full pipeline: stealth audit, sharding, injection, and forgery sync.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{pdf_hide.YELLOW}Forensic Scenarios:{NC}
  {pdf_hide.BOLD}1. Standard Run:{pdf_hide.NC}  python3 pdf_run.py -m 8 -z 0.35
  {pdf_hide.BOLD}2. Custom Key: {pdf_hide.NC}  python3 pdf_run.py "MySecretPass" --source_dir ./data
  {pdf_hide.BOLD}3. Dry Run:    {pdf_hide.NC}  python3 pdf_run.py --dry_run
        """
    )

    # 1. Identity & Data Source
    p_group = parser.add_argument_group(f'{pdf_hide.CYAN}Mission Configuration{pdf_hide.NC}')
    p_group.add_argument("password", nargs='?', default=None, 
                        help="The secret key. If omitted, a robust key is auto-generated.")
    p_group.add_argument("-s", "--source_dir", default="source_dir",
                        help="Directory containing payload files. (Default: %(default)s)")
    p_group.add_argument("-c", "--source_pdf_dir", default="source_pdf_dir",
                        help="Directory containing original cover PDFs. (Default: %(default)s)")

    # 2. Stealth & Sharding Limits
    s_group = parser.add_argument_group(f'{pdf_hide.CYAN}Stealth & Sharding Parameters{pdf_hide.NC}')
    s_group.add_argument("-m", "--max_carriers", type=int, default=1,
                        help="Max number of PDF carriers to utilize. (Default: %(default)s)")
    s_group.add_argument("-z", "--carrier_size_max_incr", type=float, default=0.30,
                        help="Max growth limit (0.30 = 30%%). (Default: %(default)s)")
    s_group.add_argument("-x", "--exclude_carrier_chars", default="^+§",
                        help="Skip carriers with these characters in filename. (Default: '%(default)s')")

    # 3. Output & Testing
    o_group = parser.add_argument_group(f'{pdf_hide.CYAN}Output & Security Testing{pdf_hide.NC}')
    o_group.add_argument("--restore_pdf_dir", default="restore_pdf_dir",
                        help="Output directory for sharded PDFs. (Default: %(default)s)")
    o_group.add_argument("--restore_dir", default="restore_dir",
                        help="Directory for verification extraction. (Default: %(default)s)")
    o_group.add_argument("--dry_run", action="store_true",
                        help="Simulate the mission without writing data. (Default: %(default)s)")
    o_group.add_argument("--test-tamper", action="store_true",
                        help="Force a corruption on one shard for testing. (Default: %(default)s)")

    args = parser.parse_args()
    run_pipeline(args)