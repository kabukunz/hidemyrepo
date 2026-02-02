#!/bin/bash
# Master Forensic Workflow v1.2.2

BLUE='\033[1;34m'
NC='\033[0m'

echo -e "${BLUE}--- [1] SESSION SANITIZATION ---${NC}"
python3 pdf_erase.py erase

echo -e "\n${BLUE}--- [2] INJECTION (SHARDING) ---${NC}"
python3 pdf_hide.py hide

echo -e "\n${BLUE}--- [3] METADATA FORGERY ---${NC}"
python3 pdf_sync.py sync

echo -e "\n${BLUE}--- [4] EXTRACTION TEST ---${NC}"
python3 pdf_hide.py restore

echo -e "\n${BLUE}--- [5] FORENSIC INTEGRITY AUDITS ---${NC}"
python3 pdf_hide.py diff
python3 pdf_hide.py hash
python3 pdf_sync.py audit

echo -e "\n${BLUE}========================================${NC}"
echo "COMPLETE: Forensic baseline established."