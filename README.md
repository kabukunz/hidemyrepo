
# 📑 PDF Forensic Steganography Suite — v1.1

A high-entropy data embedding tool designed to split, encrypt, and shard binary payloads across multiple PDF carrier files. v1.1 introduces standardized short-flags and a **Stealth-by-Default** filename policy.

## 🛠 Command Reference

### **Primary Actions**

* `hide`: Zips, XOR-encrypts, and injects data after the `%%EOF` marker of selected PDFs.
* `restore`: Reassembles shards from the manifest and decrypts the payload.
* `diff`: Forensic check of file size growth across carrier sets.
* `hash`: Bit-for-bit integrity audit between source and restored files.
* `find`: Scans a directory for PDFs containing hidden steganographic data.

---

## 🚩 Flag Cheat-Sheet

### **Path Configuration**

| Short | Long Flag | Default | Description |
| --- | --- | --- | --- |
| `-sp` | `--source_payload_dir` | `source_dir` | Directory containing the raw files to hide. |
| `-rp` | `--restore_payload_dir` | `restore_dir` | Where files are extracted during `restore`. |
| `-sd` | `--source_pdf_dir` | `source_pdf_dir` | Location of clean "decoy" PDF files. |
| `-rd` | `--restore_pdf_dir` | `restore_pdf_dir` | Target for modified "carrier" PDF files. |

### **Carrier Management**

| Short | Long Flag | Default | Description |
| --- | --- | --- | --- |
| `-mc` | `--max_carriers` | `50` | Max number of PDFs to distribute data across. |
| `-sc` | `--carrier_size_max_incr` | `0.30` | Max growth (30%) allowed per file. |
| `-xc` | `--exclude_carrier_chars` | `^+§` | Filter out PDFs containing these symbols. |
| `-kc` | `--mark_carrier_chars` | `""` | Suffix to add to carriers (e.g., `%`). |

---

## 💡 Quick Examples

**1. Stealth Run (No filename changes)**

```bash
python3 pdf_hide.py hide

```

**2. Marked Run (Suffix carriers with % for easy ID)**

```bash
python3 pdf_hide.py hide -kc %

```

**3. Aggressive Compression (Higher growth ratio, fewer files)**

```bash
python3 pdf_hide.py hide -sc 0.60 -mc 5

```

**4. Forensic Integrity Audit**

```bash
python3 pdf_hide.py hash

```

---

### 🧠 Tactical Notes for v1.1

* **Manifest Dependency**: The `pdf_files.txt` manifest stores the *actual* filenames used during injection. If you use `-kc %`, the manifest records the `%` names so that `restore` and `sync` work without manual renaming.
* **XOR Persistence**: The session key is stored in `pdf_pwd.txt`. If you provide a manual password as a positional argument, it will override the saved session key.

