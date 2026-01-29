import os
import unittest
import tempfile
import shutil
import hashlib
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
        for p in self.paths.values(): os.makedirs(p)
        
        # CREATE 10 CARRIERS (50KB each = 500KB total capacity)
        # This tests the distribution logic across multiple files
        for i in range(10):
            path = os.path.join(self.paths['pdf'], f"carrier_{i}.pdf")
            with open(path, "wb") as f:
                f.write(b"%PDF-1.4\n" + b"X" * 51200 + b"\n%%EOF")
            
        self.password = "unittest_pwd_2026"
        self.payload_content = "Procedural Test Payload - Forensic Parity Check"

    def tearDown(self):
        """Clean up the sandbox after every test."""
        shutil.rmtree(self.root)
        for f in ["pdf_files.txt", "pdf_pwd.txt"]:
            if os.path.exists(f): os.remove(f)

    def test_01_crypto_integrity(self):
        """Unit: Verify XOR encryption is reversible."""
        original = b"Secret_Data_Stream"
        encrypted = pdf_hide.xor_crypt(original, self.password)
        decrypted = pdf_hide.xor_crypt(encrypted, self.password)
        self.assertEqual(original, decrypted)

    def test_02_compression_logic(self):
        """Unit: Verify ZIP memory buffer creation."""
        with open(os.path.join(self.paths['src'], "test.txt"), "w") as f:
            f.write(self.payload_content)
        data = pdf_hide.get_zip_memory(self.paths['src'])
        self.assertTrue(data.startswith(b"PK\x03\x04"))

    def test_03_metadata_sync(self):
        """Unit: Verify macOS birthtime forgery on first carrier."""
        c_name = "carrier_0.pdf"
        dst_path = os.path.join(self.paths['out'], c_name)
        shutil.copy(os.path.join(self.paths['pdf'], c_name), dst_path)
        
        pdf_sync.sync(self.paths['pdf'], self.paths['out'], manifest=[c_name])
        
        m_src = pdf_sync.get_meta(os.path.join(self.paths['pdf'], c_name))
        m_dst = pdf_sync.get_meta(dst_path)
        self.assertAlmostEqual(m_src['birth_raw'], m_dst['birth_raw'], delta=1)

    def test_04_dry_run_safety(self):
        """Integration: Verify --dry_run does not modify filesystem."""
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
        self.assertEqual(len(os.listdir(self.paths['out'])), 0)

    def test_05_sharded_restoration_loop(self):
        """Regression: Verify reassembly from multiple carriers."""
        fname = "multi_shard_secret.txt"
        with open(os.path.join(self.paths['src'], fname), "w") as f:
            f.write(self.payload_content)

        class Args:
            source_dir = self.paths['src']
            source_pdf_dir = self.paths['pdf']
            restore_pdf_dir = self.paths['out']
            max_carriers = 10
            carrier_size_max_incr = 0.8 # Allow more growth for test stability
            exclude_carrier_chars = ""
            password = self.password
            dry_run = False

        pdf_run.run_pipeline(Args())

        class MockRestoreArgs:
            manifest = "pdf_files.txt"
            password = self.password
            restore_dir = self.paths['res']
            restore_pdf_dir = self.paths['out']

        pdf_hide.restore(MockRestoreArgs())

        restored_path = os.path.join(self.paths['res'], fname)
        self.assertTrue(os.path.exists(restored_path))
        with open(restored_path, "r") as f:
            self.assertEqual(f.read(), self.payload_content)

    def test_06_high_entropy_multi_carrier_hash(self):
        """Regression: SHA-256 Bit-level parity across multiple shards."""
        import hashlib
        fname = "heavy_payload.bin"
        original_path = os.path.join(self.paths['src'], fname)
        # 150KB will force use of multiple 50KB carriers at 0.5 growth
        data = os.urandom(1024 * 150) 
        with open(original_path, "wb") as f:
            f.write(data)
        
        original_hash = hashlib.sha256(data).hexdigest()

        class Args:
            source_dir = self.paths['src']
            source_pdf_dir = self.paths['pdf']
            restore_pdf_dir = self.paths['out']
            max_carriers = 10
            carrier_size_max_incr = 0.5
            exclude_carrier_chars = ""
            password = self.password
            dry_run = False

        pdf_run.run_pipeline(Args())

        # Verify multiple carriers were actually used
        out_files = os.listdir(self.paths['out'])
        self.assertGreater(len(out_files), 1, "Test failed to force multi-carrier sharding.")

        class MockRestoreArgs:
            manifest = "pdf_files.txt"
            password = self.password
            restore_dir = self.paths['res']
            restore_pdf_dir = self.paths['out']

        pdf_hide.restore(MockRestoreArgs())

        restored_path = os.path.join(self.paths['res'], fname)
        with open(restored_path, "rb") as f:
            restored_data = f.read()
        
        self.assertEqual(original_hash, hashlib.sha256(restored_data).hexdigest())

if __name__ == "__main__":
    unittest.main(verbosity=2)