import os
import unittest
import tempfile
import shutil
import hashlib
import zipfile
import pdf_hide
import pdf_sync
import pdf_run

class TestForensicSuite(unittest.TestCase):

    def setUp(self):
        """Initialize a fresh sandbox with multiple carriers."""
        self.root = tempfile.mkdtemp()
        self.paths = {
            'src': os.path.join(self.root, "src"),
            'pdf': os.path.join(self.root, "pdf"),
            'out': os.path.join(self.root, "out"),
            'res': os.path.join(self.root, "res")
        }
        for p in self.paths.values(): 
            os.makedirs(p)
        
        # CREATE 10 CARRIERS (50KB each = 500KB total capacity)
        for i in range(10):
            path = os.path.join(self.paths['pdf'], f"carrier_{i}.pdf")
            with open(path, "wb") as f:
                f.write(b"%PDF-1.4\n" + b"X" * 51200 + b"\n%%EOF")
            
        self.password = "unittest_pwd_2026"
        self.payload_content = "Procedural Test Payload - Forensic Parity Check"

    def tearDown(self):
        """Clean up the sandbox and session files."""
        shutil.rmtree(self.root)
        # Session files are written to CWD by pdf_hide
        for f in ["pdf_files.txt", "pdf_pwd.txt"]:
            if os.path.exists(f): 
                os.remove(f)

    def test_01_crypto_integrity(self):
        """Unit: Verify XOR encryption is reversible."""
        original = b"Secret_Data_Stream"
        encrypted = pdf_hide.xor_crypt(original, self.password)
        decrypted = pdf_hide.xor_crypt(encrypted, self.password)
        self.assertEqual(original, decrypted)

    def test_02_compression_logic(self):
        """Unit: Verify ZIP memory buffer creation handles paths and folders."""
        # Create a file and an empty directory
        with open(os.path.join(self.paths['src'], "test.txt"), "w") as f:
            f.write(self.payload_content)
        os.makedirs(os.path.join(self.paths['src'], "empty_dir"))
        
        data = pdf_hide.get_zip_memory(self.paths['src'])
        self.assertTrue(data.startswith(b"PK\x03\x04"), "ZIP header missing")

    def test_03_metadata_sync(self):
        """Unit: Verify timestamp forgery (macOS/Linux)."""
        c_name = "carrier_0.pdf"
        dst_path = os.path.join(self.paths['out'], c_name)
        shutil.copy(os.path.join(self.paths['pdf'], c_name), dst_path)
        
        # Sync metadata
        pdf_sync.sync(self.paths['pdf'], self.paths['out'], manifest=[c_name])
        
        m_src = pdf_sync.get_meta(os.path.join(self.paths['pdf'], c_name))
        m_dst = pdf_sync.get_meta(dst_path)
        # Delta 2s accounts for filesystem commitment delays
        self.assertAlmostEqual(m_src['birth_raw'], m_dst['birth_raw'], delta=2)

    def test_04_dry_run_safety(self):
        """Integration: Verify --dry_run writes manifest but NO binary data."""
        class Args:
            source_dir = self.paths['src']
            source_pdf_dir = self.paths['pdf']
            restore_pdf_dir = self.paths['out']
            max_carriers = 5
            carrier_size_max_incr = 0.5
            exclude_carrier_chars = ""
            password = self.password
            dry_run = True

        pdf_run.run_pipeline(Args())
        # Output directory should remain empty
        self.assertEqual(len(os.listdir(self.paths['out'])), 0)
        # But manifest should exist for audit
        self.assertTrue(os.path.exists("pdf_files.txt"))

    def test_05_sharded_restoration_loop(self):
        """Regression: Verify reassembly from multiple carriers via pdf_run."""
        fname = "multi_shard_secret.txt"
        with open(os.path.join(self.paths['src'], fname), "w") as f:
            f.write(self.payload_content)

        class Args:
            source_dir = self.paths['src']
            source_pdf_dir = self.paths['pdf']
            restore_pdf_dir = self.paths['out']
            max_carriers = 10
            carrier_size_max_incr = 0.8
            exclude_carrier_chars = ""
            password = self.password
            dry_run = False

        pdf_run.run_pipeline(Args())

        class MockRestoreArgs:
            password = self.password
            restore_dir = self.paths['res']
            restore_pdf_dir = self.paths['out']

        pdf_hide.restore(MockRestoreArgs())

        restored_path = os.path.join(self.paths['res'], fname)
        self.assertTrue(os.path.exists(restored_path))
        with open(restored_path, "r") as f:
            self.assertEqual(f.read(), self.payload_content)

    def test_06_empty_directory_preservation(self):
        """Forensic: Verify that empty folders are correctly sharded and restored."""
        unique_empty = "forensic_empty_test_dir"
        os.makedirs(os.path.join(self.paths['src'], unique_empty))

        class Args:
            source_dir = self.paths['src']
            source_pdf_dir = self.paths['pdf']
            restore_pdf_dir = self.paths['out']
            max_carriers = 5
            carrier_size_max_incr = 0.5
            exclude_carrier_chars = ""
            password = self.password
            dry_run = False

        pdf_run.run_pipeline(Args())

        class MockRestoreArgs:
            password = self.password
            restore_dir = self.paths['res']
            restore_pdf_dir = self.paths['out']

        pdf_hide.restore(MockRestoreArgs())

        # WALK the result to find the folder, regardless of parent nesting
        found_dirs = []
        for root, dirs, _ in os.walk(self.paths['res']):
            found_dirs.extend(dirs)
        
        self.assertIn(unique_empty, found_dirs, 
                     f"Folder not found! Actual structure: {found_dirs}")
        
    def test_07_session_load_auto_password(self):
        """Logic: Verify restore works using saved pdf_pwd.txt without explicit password arg."""
        with open(os.path.join(self.paths['src'], "session_data.bin"), "wb") as f:
            f.write(b"Verification_Data_2026")

        class Args:
            source_dir = self.paths['src']
            source_pdf_dir = self.paths['pdf']
            restore_pdf_dir = self.paths['out']
            max_carriers = 1
            carrier_size_max_incr = 0.9
            exclude_carrier_chars = ""
            password = self.password  # This will be saved to pdf_pwd.txt
            dry_run = False

        pdf_run.run_pipeline(Args())

        # Attempt restore WITHOUT password to test session persistence
        class MockRestoreArgs:
            password = None 
            restore_dir = self.paths['res']
            restore_pdf_dir = self.paths['out']

        pdf_hide.restore(MockRestoreArgs())
        
        res_file = os.path.join(self.paths['res'], "session_data.bin")
        with open(res_file, "rb") as f:
            self.assertEqual(f.read(), b"Verification_Data_2026")

if __name__ == "__main__":
    unittest.main(verbosity=2)