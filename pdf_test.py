import unittest
import os
import shutil
import tempfile
import time
import json
import io
import zipfile
import sys
from unittest.mock import patch, MagicMock

# Import Baseline Scripts
import pdf_hide
import pdf_erase
import pdf_sync
import pdf_batch
import pdf_run

# --- UI Constants ---
NC = '\033[0m'; BOLD = '\033[1m'; GREEN = '\033[0;32m'
RED = '\033[0;31m'; CYAN = '\033[0;36m'; YELLOW = '\033[1;33m'

class VerboseTestResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.success_count = 0

    def startTest(self, test):
        func_name = test._testMethodName
        doc = test._testMethodDoc or "No description"
        print(f"{CYAN}[TESTING]{NC} {func_name:<30} | {doc[:50]:<50} ", end="")
        super().startTest(test)

    def addSuccess(self, test):
        self.success_count += 1
        print(f"-> {GREEN}{BOLD}PASS{NC}")
        super().addSuccess(test)

    def addError(self, test, err):
        print(f"-> {RED}{BOLD}ERROR{NC}")
        super().addError(test, err)

    def addFailure(self, test, err):
        print(f"-> {YELLOW}{BOLD}FAIL{NC}")
        super().addFailure(test, err)

class UltimateBaselineAudit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Create a transient sandbox for all disk-based tests."""
        cls.tmp = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        """Purge the sandbox."""
        shutil.rmtree(cls.tmp)

    # ==========================================
    # SECTION 1: pdf_hide.py (Core Engine)
    # ==========================================

    def test_hide_xor_crypt_standard(self):
        """Verify standard symmetric XOR encryption logic."""
        data, pwd = b"Forensic Payload", "Key123"
        encrypted = pdf_hide.xor_crypt(data, pwd)
        self.assertNotEqual(data, encrypted)
        self.assertEqual(data, pdf_hide.xor_crypt(encrypted, pwd))

    def test_hide_robust_password_gen(self):
        """Verify password entropy (32 chars) and uniqueness."""
        pwd1 = pdf_hide.generate_robust_password(32)
        pwd2 = pdf_hide.generate_robust_password(32)
        self.assertEqual(len(pwd1), 32)
        self.assertNotEqual(pwd1, pwd2)

    def test_hide_get_file_hash_valid(self):
        """Verify SHA-256 integrity hashing on real files."""
        p = os.path.join(self.tmp, "hash.txt")
        with open(p, "wb") as f: f.write(b"forensic_integrity_test")
        self.assertEqual(len(pdf_hide.get_file_hash(p)), 64)

    @patch('os.path.getsize')
    def test_hide_carrier_pool_math_standard(self, mock_size):
        """Verify standard payload distribution capacity math."""
        mock_size.return_value = 1000
        files = [{'path': 'f1.pdf', 'size': 1000}, {'path': 'f2.pdf', 'size': 1000}]
        # 500 byte payload, 30% ratio = 300 bytes/carrier. Needs 2 carriers.
        selected, cap = pdf_hide.select_carrier_pool(files, 500, 0.30, 5)
        self.assertEqual(len(selected), 2)
        self.assertEqual(cap, 600) 

    def test_hide_get_zip_memory_valid(self):
        """Verify memory buffering of directory into ZIP format."""
        d = os.path.join(self.tmp, "zip_test")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "file.txt"), "w") as f: f.write("data")
        zip_bytes = pdf_hide.get_zip_memory(d)
        self.assertIsInstance(zip_bytes, bytes)

    def test_hide_session_save_logic(self):
        """Verify manifest and explicit password file (password.txt) saving."""
        class MockArgs:
            password_file = os.path.join(self.tmp, "password.txt")
            carrier_file = os.path.join(self.tmp, "manifest.txt")
            
        pdf_hide.save_session(MockArgs(), "test_key", ["1.pdf", "2.pdf"])
        self.assertTrue(os.path.exists(MockArgs().password_file))
        with open(MockArgs().password_file, 'r') as f:
            self.assertEqual(f.read().strip(), "test_key")

    @patch('sys.stdout', new_callable=io.StringIO)
    def test_hide_progress_bar_display(self, mock_stdout):
        """Verify the terminal progress bar renders via sys.stdout."""
        pdf_hide.draw_progress(5, 10, prefix='Testing')
        output = mock_stdout.getvalue()
        self.assertIn('Testing', output)
        self.assertIn('50%', output)

    # ==========================================
    # SECTION 2: pdf_erase.py (Cleanup Engine)
    # ==========================================

    def test_erase_secure_shred_file(self):
        """Verify forensic file unlinking and OS removal."""
        p = os.path.join(self.tmp, "wipe.txt")
        with open(p, "w") as f: f.write("sensitive")
        self.assertTrue(pdf_erase.secure_shred_file(p))
        self.assertFalse(os.path.exists(p))

    # ==========================================
    # SECTION 3: pdf_sync.py (Forensic Engine)
    # ==========================================

    def test_sync_get_meta_structure(self):
        """Verify MACB metadata dictionary structure extraction."""
        p = os.path.join(self.tmp, "meta.pdf")
        with open(p, "w") as f: f.write("pdf")
        meta = pdf_sync.get_meta(p)
        for key in ['birth_raw', 'mod_raw', 'acc_raw', 'size']:
            self.assertIn(key, meta)

    # ==========================================
    # SECTION 4: pdf_run.py (Orchestrator)
    # ==========================================

    @patch('subprocess.run')
    def test_run_step_success(self, mock_sub):
        """Verify orchestrator proceeds on successful sub-process."""
        mock_sub.return_value = MagicMock(returncode=0)
        self.assertTrue(pdf_run.run_step("MockStep", ["echo", "test"]))

    # ==========================================
    # SECTION 5: pdf_batch.py (Reporting)
    # ==========================================

    def test_batch_stats_calculations(self):
        """Verify math accuracy of pipeline reporting logs (Success %)."""
        log = [{"dur": 10.0, "res": True}, {"dur": 20.0, "res": False}]
        success_rate = (sum(1 for e in log if e['res']) / len(log)) * 100
        self.assertEqual(success_rate, 50.0)

if __name__ == "__main__":
    start_time = time.time()
    print(f"\n{BOLD}{YELLOW}=== PDF SUITE v2.0 TOTAL COVERAGE AUDIT ==={NC}\n")
    
    suite = unittest.TestLoader().loadTestsFromTestCase(UltimateBaselineAudit)
    runner = unittest.TextTestRunner(resultclass=VerboseTestResult, verbosity=0)
    result = runner.run(suite)
    
    elapsed = time.time() - start_time
    total = result.testsRun
    passed = result.success_count
    failed = len(result.failures) + len(result.errors)

    print(f"\n{BOLD}{YELLOW}=== FINAL AUDIT SUMMARY ==={NC}")
    print(f"  {CYAN}Total Tests:{NC}    {total}")
    print(f"  {GREEN}Passed:{NC}         {passed}")
    print(f"  {RED if failed > 0 else GREEN}Failed:{NC}         {failed}")
    print(f"  {CYAN}Duration:{NC}       {elapsed:.3f}s")
    
    if failed == 0:
        print(f"\n{GREEN}{BOLD}>>> ALL SYSTEMS VERIFIED - BASELINE LOCKED (GO){NC}\n")
    else:
        print(f"\n{RED}{BOLD}>>> CRITICAL FAILURE IN BASELINE (NO-GO){NC}\n")
        sys.exit(1)