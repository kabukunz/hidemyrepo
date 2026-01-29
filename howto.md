This **`HOWTO.md`** is designed as a clear, step-by-step guide for a first-time user. It covers the logic of the tool, the forensic goals, and the specific commands needed to go from a clean state to a fully hidden (and restored) payload.

---

# 🕵️ Forensic PDF Sharding Suite: User Guide

This suite allows you to hide a private directory inside a collection of PDF files. Unlike standard tools, it uses **Proportional Sharding** and **macOS Kernel Forgery** to make the changes nearly invisible to forensic audits.

---

## 1. Setup & Requirements

* **Operating System**: Designed for **macOS** (uses `libc.dylib` for birth-date forging).
* **Python**: Version 3.9 or higher.
* **Folder Structure**: Ensure the following folders exist in your working directory:
* `source_dir/`: Put the secret files you want to hide here.
* `source_pdf_dir/`: Put your "clean" carrier PDFs here (the more, the better).
* `restore_pdf_dir/`: This is where the "injected" (stego) PDFs will be created.
* `restore_dir/`: This is where files appear when you extract them later.



---

## 2. Core Concepts

### Proportional Sharding

Instead of filling one PDF to the brim, the tool calculates the total size of your PDF library and grows **every** file by the exact same percentage (e.g., every file grows by 4.2%). This prevents a single file from looking "suspiciously large."

### Forensic Forgery

When a file is modified, its "Modified" and "Added" dates usually update. This tool:

1. Strips system locks.
2. Forges the **Birth Date** (Creation Date) using macOS kernel calls.
3. Mirrors the **Extended Attributes** (`kMDItemDateAdded`).
4. Matches the **Access/Modify** timestamps to the originals.

---

## 3. How to Hide Data (The "Injection")

### Step A: The Dry Run (Safety First)

Before processing, check if you have enough PDF space to stay "stealthy." If you want no file to grow more than 10%, run:

```bash
python3 cycle_test.py --dry_run --max_carrier_size 0.10

```

* **Result**: It will show an "Action Plan." If it says `PASS`, you are safe to proceed.

### Step B: The Execution

Run the full automated pipeline:

```bash
python3 cycle_test.py --max_carrier_size 0.10

```

* **What happens**: The tool zips your data, encrypts it, shards it into the PDFs, and then forges the metadata.
* **Important**: Note the password generated in the console (or check `session.pwd`).

---

## 4. How to Extract Data (The "Restoration")

If you are using the same machine and the `session.pwd` and `hidden_pdf_files.txt` files are present, simply run:

```bash
python3 pdf_hide.py restore

```

Your files will reappear exactly as they were in the `restore_dir/` folder.

---

## 5. Command Reference Table

| Command | Purpose |
| --- | --- |
| `python3 cycle_test.py` | Runs the **entire** process (Hide → Sync → Audit → Restore). |
| `python3 cycle_test.py --dry_run` | Predicts growth percentages without touching files. |
| `python3 pdf_sync.py audit` | Compares original vs. stego PDFs to check for timestamp leaks. |
| `python3 pdf_hide.py hash` | Compares original secret files vs. restored files to ensure 100% integrity. |

---

## 6. Advanced Constraints

* **Banning Carriers**: If a PDF has a sensitive name you don't want to touch, add a `+` or `§` to its filename. The tool will skip it automatically.
* **Forcing Spread**: To force the data to be spread across many files (even if it fits in one), use:
`--max_carriers 10`
* **Tightening Stealth**: For extreme security, use a 5% growth limit:
`--max_carrier_size 0.05`

---

## ⚠️ Vital Security Warning

* **Do not lose `hidden_pdf_files.txt**`: This manifest tells the tool the order in which the shards were hidden. Without it, reassembly is nearly impossible.
* **Clean Up**: After a successful hide, it is recommended to move your `source_dir` to an encrypted vault or delete it.

Would you like me to add a section on how to "Clean" your tracks from the macOS terminal history after you finish a session?