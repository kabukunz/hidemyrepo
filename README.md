
### Work in progress

```text
*** DO NOT USE! NOT READY YET! ***
```
---

# 🛡️ PDF Forensic Steganography Suite

A cross-platform toolkit for sharding, encrypting, and embedding high-capacity data payloads within standard PDF carriers. Designed for forensic invisibility and data integrity.

## 🚀 Execution Guide

To ensure compatibility across Windows, macOS, and Linux, always invoke the script using the Python interpreter:

### 1. The "Hide" Phase

Prepare your sensitive data in `source_dir` and cover PDFs in `source_pdf_dir`.

```powershell
# Audit the plan (Stealth check)
python pdf_hide.py hide --dry_run

# Execute injection (Shards across up to 50 carriers)
python pdf_hide.py hide

```

### 2. The "Sync" Phase (Forensic Alignment)

Ensure modified PDFs match the timestamps of the originals to avoid "Date Modified" detection.

```bash
# Sync metadata
python pdf_sync.py sync -s source_pdf_dir -t restore_pdf_dir

```

### 3. The "Restore" Phase

Reassemble the payload from the stego-carriers:

```bash
python pdf_hide.py restore

```

### 4. The "Audit" Phase

Verify that every bit was restored correctly using SHA-256 hashing.

```bash
python pdf_hide.py hash

```

---

## 📋 Action Summary (v1.1.5)

| Action | Purpose | Key Logic |
| --- | --- | --- |
| **`hide`** | Encrypt & Embed | Deterministic shuffle, XOR encryption, `%%EOF` injection. |
| **`restore`** | Reassemble | Binary concatenation, XOR decryption, ZIP extraction. |
| **`hash`** | Deep Audit | SHA-256 comparison of every single payload file. |
| **`diff`** | Growth Check | Compares file sizes between Source and Restore dirs. |
| **`find`** | Forensic Scan | Byte-scan for stego-carriers (`%PDF` + `PK\x03\x04`). |

---

## ⚙️ Key Configuration Flags

* **`-m 50`**: Max carriers. Spreading data across 50 files keeps individual growth low.
* **`-z 0.30`**: Stealth ceiling. Limits file size increase to 30%.
* **`-x "^+§"`**: Filename filter. Skips PDFs with suspicious characters.
* **`password`**: If not provided during `hide`, a 32-character robust key is generated.

---

### 🏁 AI disclaimer

```text
Vibe coded with Gemini 3.0
```