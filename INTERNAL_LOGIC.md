# INTERNAL_LOGIC.md

## 1. Data Processing Pipeline

The transformation from raw files to hidden carrier shards follows a strictly linear, deterministic path:

1. **Aggregation**: The `source_dir` is walked, and all files are compressed into a single ZIP stream in memory. This reduces the footprint and simplifies sharding.
2. **Encryption**: The ZIP stream is processed through an XOR cipher.
3. **Keyed Shuffle**: The list of available PDF carriers is sorted alphabetically and then shuffled using a `random.Random(password)` instance. This ensures that even if two users use the same PDFs, the data is stored in a different sequence if their passwords differ.
4. **Injection**: Data is appended after the final `%%EOF` marker of the PDF. This preserves the PDF's readability in standard viewers.

---

## 2. Forensic Metadata Mirroring

The most critical aspect of this tool is the preservation of the **MAC (Modified, Accessed, Created)** timestamps. On macOS (Darwin), the `birth_time` (Creation Date) is an HFS+/APFS attribute that standard Python `os.utime` cannot modify.

### The `setattrlist` Implementation

The tool interfaces with the macOS system kernel via `libc.setattrlist`. We define a specific attribute list structure:

When a carrier is modified (injected), it naturally receives a new "Now" timestamp. The `pdf_sync` module performs the following:

1. Captures the **nanosecond-precise** timestamp from the original carrier.
2. Populates a C-style buffer (`struct`).
3. Invokes the kernel call to force the "Restored" carrier to match the "Original" carrier perfectly.

---

## 3. Capacity & Stealth Guard

The tool implements a **Growth-Ratio Constraint** to prevent detection via file-size anomalies.

* **Growth Formula**: 
* **Thresholding**: If the payload requires a shard that exceeds the user-defined limit (e.g., 30%), the tool aborts before writing to disk. This prevents "suspiciously large" PDFs from being created.

---

## 4. Keyed Retrieval (Restoration)

Restoration is the exact inverse of the injection process:

1. **Seed Regeneration**: The password is used to recreate the identical shuffle order of the carriers.
2. **Extraction**: The tool opens each carrier and reads all bytes following the standard PDF `%%EOF` marker.
3. **Stream Reassembly**: The shards are concatenated, XOR-decrypted, and the resulting ZIP stream is extracted to the destination.
