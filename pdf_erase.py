import os
import shutil
import argparse
from pdf_hide import BLUE, GREEN, RED, YELLOW, BOLD, NC, LIST_FILE, PWD_FILE

def wipe_path(path):
    """Deletes a file or an entire directory tree with status feedback."""
    if not os.path.exists(path):
        return False

    try:
        if os.path.isfile(path) or os.path.islink(path):
            os.remove(path)
            print(f"  {RED}[-] Removed File:{NC} {path}")
        elif os.path.isdir(path):
            shutil.rmtree(path)
            print(f"  {RED}[-] Removed Dir: {NC} {path}")
        return True
    except Exception as e:
        print(f"  {RED}[!] Error wiping {path}: {e}{NC}")
        return False

def erase(args):
    print(f"\n{BOLD}{YELLOW}[ERASE: PURGE SESSION & DATA]{NC}")
    
    # 1. Define Targets
    # We include the standard session files and the user-specified dirs
    targets = [
        LIST_FILE, 
        PWD_FILE, 
        args.restore_pdf_dir, 
        args.restore_dir
    ]
    
    wiped_count = 0
    for target in targets:
        if wipe_path(target):
            wiped_count += 1
            
    if wiped_count == 0:
        print(f"  {BLUE}No artifacts found to erase.{NC}")
    else:
        print(f"\n{BOLD}{GREEN}✓ PURGE COMPLETE:{NC} {wiped_count} forensic artifacts destroyed.")

def main():
    parser = argparse.ArgumentParser(
        description=f"{BOLD}PDF Forensic Eraser{NC}\n"
                    "Purges session manifests, passwords, and restored data outputs.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-r", "--restore_dir", default="restore_dir",
                        help="The directory where payload files were restored. (Default: %(default)s)")
    parser.add_argument("--restore_pdf_dir", default="restore_pdf_dir",
                        help="The directory where modified PDFs were stored. (Default: %(default)s)")
    
    args = parser.parse_args()
    
    # Safety Confirmation
    confirm = input(f"{YELLOW}[?] This will permanently delete your session keys and restored data. Proceed? (y/N): {NC}")
    if confirm.lower() == 'y':
        erase(args)
    else:
        print(f"{BLUE}Erasure aborted.{NC}")

if __name__ == "__main__":
    main()