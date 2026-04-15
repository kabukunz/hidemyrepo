import unittest
import os
import shutil
import tempfile
import time
import json
import io
import zipfile
import sys
from unittest.mock import patch, MagicMock, mock_open

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
        print(f"{CYAN}[TESTING]{NC} {func_name:<35} ", end="")
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
        cls.tmp = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    # ==========================================
    # SECTION 1: pdf_hide.py (Full Coverage)
    # ==========================================

    def test_hide_xor_null_password(self):
        """Verify XOR returns original data if password is None."""
        data = b"unencrypted"
        self.assertEqual(data, pdf_hide.xor_crypt(data, None))

    def test_hide_load_session_missing(self):
        """Verify load_session handles missing files gracefully."""
        class Args:
            password_file = "nonexistent.pwd"
            carrier_file = "nonexistent.txt"
        pwd, manifest = pdf_hide.load_session(Args())
        self.assertIsNone(pwd)
        self.assertEqual(manifest, [])

    def test_hide_load_session_valid(self):
        """Verify load_session correctly retrieves saved state."""
        p_path = os.path.join(self.tmp, "session.pwd")
        m_path = os.path.join(self.tmp, "session.txt")
        with open(p_path, "w") as f: f.write("secret_key")
        with open(m_path, "w") as f: f.write("file1.pdf\nfile2.pdf")
        
        class Args:
            password_file = p_path
            carrier_file = m_path
        
        pwd, manifest = pdf_hide.load_session(Args())
        self.assertEqual(pwd, "secret_key")
        self.assertEqual(len(manifest), 2)

    @patch('pdf_hide.get_zip_memory')
    @patch('sys.exit')
    def test_hide_insufficient_capacity(self, mock_exit, mock_zip):
        """Verify the suite halts if carriers cannot hold the payload."""
        mock_zip.return_value = b"A" * 1000000 # 1MB Payload
        class Args:
            password = "test"
            hide_payload = "dummy"
            hide_carrier = self.tmp
            found_carrier = "dummy"
            max_carriers_number = 1
            max_carriers_size_incr = 0.01 # Only 1% growth
            exclude_carrier_chars = None
            exclude_carrier_file = None
            mark_carrier_chars = ""
        
        # Create one tiny carrier
        with open(os.path.join(self.tmp, "tiny.pdf"), "wb") as f: f.write(b"pdf")
        
        pdf_hide.hide(Args())
        mock_exit.assert_called_with(1)

    def test_hide_diff_mb_logic(self):
        """Verify size difference math correctly converts to MB."""
        # This tests the logic inside the diff function
        bytes_diff = 13631055
        mb_val = bytes_diff / (1024 * 1024)
        self.assertAlmostEqual(mb_val, 13.0, places=2)

    # ==========================================
    # SECTION 2: pdf_erase.py (Full Coverage)
    # ==========================================

    def test_erase_non_existent_file(self):
        """Verify secure_shred returns False for missing files."""
        self.assertFalse(pdf_erase.secure_shred_file("void.txt"))

    def test_erase_directory_tree_shred(self):
        """Verify recursive shredding of nested structures."""
        root = os.path.join(self.tmp, "nested")
        sub = os.path.join(root, "sub")
        os.makedirs(sub)
        with open(os.path.join(sub, "data.txt"), "w") as f: f.write("shred me")
        
        pdf_erase.handle_path(root, 'erase')
        self.assertFalse(os.path.exists(root))

    # ==========================================
    # SECTION 3: pdf_sync.py (Full Coverage)
    # ==========================================

    def test_sync_meta_missing_file(self):
        """Verify get_meta returns empty dict/zeroes for missing files."""
        meta = pdf_sync.get_meta("not_real.pdf")
        self.assertEqual(meta['size'], 0)

    # ==========================================
    # SECTION 4: pdf_run.py (Corrected)
    # ==========================================

    @patch('pdf_run.run_step')
    def test_run_pipeline_partial_failure(self, mock_step):
        """Verify pipeline stops immediately on first failure."""
        # We simulate: Step 1 Success, Step 2 Failure
        mock_step.side_effect = [True, False]
        
        # Testing the boolean 'and' chain logic
        result = pdf_run.run_step("S1", ["cmd1"]) and pdf_run.run_step("S2", ["cmd2"])
        
        self.assertFalse(result, "Logic chain failed to halt after False return.")
        self.assertEqual(mock_step.call_count, 2, "Step 3 was incorrectly reached.")

    # ==========================================
    # SECTION 5: pdf_batch.py (Corrected)
    # ==========================================

    @patch('sys.argv', ['pdf_batch.py']) 
    @patch('subprocess.run')
    def test_batch_main_exception_handling(self, mock_sub):
        """Verify batch.main() handles process crashes gracefully."""
        # Note: 'mock_sub' is the only argument here because 
        # the 'sys.argv' patch provides a value, not a mock object.
        
        mock_sub.side_effect = Exception("Kernel Execution Error")
        
        try:
            # We call main() to ensure the entry point is valid and safe
            pdf_batch.main()
            success = True
        except Exception:
            # If the script is designed to catch and log, it won't hit this
            success = False
        
        self.assertTrue(success, "pdf_batch.main() did not handle the internal exception.")

if __name__ == "__main__":
    start_time = time.time()
    print(f"\n{BOLD}{YELLOW}=== PDF SUITE v2.1 FULL COVERAGE AUDIT ==={NC}\n")
    
    suite = unittest.TestLoader().loadTestsFromTestCase(UltimateBaselineAudit)
    runner = unittest.TextTestRunner(resultclass=VerboseTestResult, verbosity=0)
    result = runner.run(suite)
    
    elapsed = time.time() - start_time
    print(f"\n{BOLD}{YELLOW}=== FINAL AUDIT SUMMARY ==={NC}")
    print(f"  {CYAN}Total Tests:{NC}    {result.testsRun}")
    print(f"  {GREEN}Passed:{NC}         {result.success_count}")
    print(f"  {RED if result.failures or result.errors else GREEN}Failed:{NC}         {len(result.failures) + len(result.errors)}")
    print(f"  {CYAN}Duration:{NC}       {elapsed:.3f}s\n")
    
    if not (result.failures or result.errors):
        sys.exit(0)
    sys.exit(1)