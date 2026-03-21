import unittest
import os
import shutil
import tempfile
from unittest.mock import patch

# Import Baseline Scripts
import pdf_hide
import pdf_erase
import pdf_sync

class TestGranularLogic(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    # --- SECTION 1: pdf_hide.py LOGIC ---

    def test_xor_crypt_basic(self):
        """UNIT: xor_crypt - Test basic symmetry."""
        data = b"Hello"
        pwd = "123"
        encrypted = pdf_hide.xor_crypt(data, pwd)
        self.assertEqual(data, pdf_hide.xor_crypt(encrypted, pwd))

    @patch('os.path.getsize')
    def test_filter_carriers_logic(self, mock_getsize):
        """UNIT: filter_carriers - Test char exclusion without real files."""
        # We tell the mock to return 1024 whenever getsize is called
        mock_getsize.return_value = 1024
        
        mock_files = ["/tmp/clean.pdf", "/tmp/bad^char.pdf"]
        available, excluded = pdf_hide.filter_carriers(mock_files, "^")
        
        # Verify filtering logic
        self.assertEqual(len(available), 1)
        self.assertEqual(len(excluded), 1)
        self.assertEqual(os.path.basename(excluded[0]), "bad^char.pdf")

    # --- SECTION 2: pdf_erase.py LOGIC ---

    def test_handle_path_missing(self):
        """UNIT: handle_path - Ensure [SKIP] log happens without crash."""
        # This is the test that produced your [SKIP] log in the previous run
        try:
            pdf_erase.handle_path("void_path_999", "erase")
            success = True
        except Exception as e:
            print(f"Failed with: {e}")
            success = False
        self.assertTrue(success)

    # --- SECTION 3: SESSION LOGIC ---

    def test_session_save_load(self):
        """UNIT: save_session/load_session - Test round-trip manifest storage."""
        class MockArgs:
            password_file = os.path.join(self.tmp, "test_pwd.txt")
            carrier_file = os.path.join(self.tmp, "test_manifest.txt")
        
        args = MockArgs()
        test_pwd = "robust_key_v1.7"
        test_manifest = ["file1.pdf", "file2.pdf"]
        
        # Save
        pdf_hide.save_session(args, test_pwd, test_manifest)
        
        # Load
        loaded_pwd, loaded_manifest = pdf_hide.load_session(args)
        
        self.assertEqual(test_pwd, loaded_pwd)
        self.assertEqual(test_manifest, loaded_manifest)

    # --- SECTION 4: UTILITIES ---

    def test_robust_password_entropy(self):
        """UNIT: generate_robust_password - Ensure complexity."""
        pwd = pdf_hide.generate_robust_password(16)
        self.assertEqual(len(pwd), 16)
        # Check for at least one punctuation/digit (usually present in robust gen)
        has_special = any(c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" for c in pwd)
        self.assertTrue(has_special or any(c.isdigit() for c in pwd))

if __name__ == "__main__":
    print(f"\n{pdf_hide.CYAN}{pdf_hide.BOLD}>>> v1.2.1 UNIT TEST: MOCKED GRANULAR AUDIT{pdf_hide.NC}")
    unittest.main()