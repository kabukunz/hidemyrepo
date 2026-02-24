#!/bin/bash

# --- PDF FORENSIC STEGANOGRAPHY SUITE ---
# Automated deployment and audit pipeline

# [1] SESSION CLEANING
# Purges previous manifests, keys, and restoration directories
python3 pdf_erase.py erase

# [2] INJECTION (SHARDING)
# Shards payload into carriers
python3 pdf_hide.py hide

# [3] METADATA ALIGNMENT
# Kernel-level forgery of timestamps and birth dates to match source templates
python3 pdf_sync.py sync

# [4] EXTRACTION TEST
# Verifies that the payload can be perfectly reassembled from the modified carriers
python3 pdf_hide.py restore

# [5] FORENSIC INTEGRITY AUDITS
# 5a. Carrier Diff (Size growth audit)
python3 pdf_hide.py diff

# 5b. Payload Hash (Bit-for-bit extraction verification)
python3 pdf_hide.py hash

# 5c. Timestamp Sync (Metadata alignment audit)
python3 pdf_sync.py audit

# 5d. Forensic Scan (Carrier vs clean detection scan)
python3 pdf_hide.py find

echo -e "\n\033[0;32m[COMPLETE]\033[0m Full forensic suite execution finished."