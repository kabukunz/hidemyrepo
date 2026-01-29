To complete the professional look of your repository, here is a polished **Quick Start** section for your `README.md`.

I’ve designed this to be "Copy-Paste" ready, using standard Markdown formatting that renders beautifully on GitHub.

---

## 🚀 Quick Start

### 1. Prerequisites

This tool is designed for **macOS** (utilizing Darwin-specific `libc` calls for forensic parity).

* Python 3.8+
* Administrative privileges (required for certain `setattrlist` kernel calls)

### 2. Installation

Clone the repository and ensure you are in the project root:

```bash
git clone https://github.com/yourusername/pdf-stegano-forensic.git
cd pdf-stegano-forensic

```

### 3. Hiding Data (The "Injection" Phase)

Point the tool to your secrets and a folder of "Clean" PDFs to use as carriers.

```bash
python pdf_run.py \
  --source_dir ./my_secrets \
  --source_pdf_dir ./clean_pdfs \
  --restore_pdf_dir ./injected_output \
  --password "your_secure_passphrase"

```

> **Note**: A file named `pdf_files.txt` will be created. This is your manifest—keep it safe or remember the carrier names for restoration.

### 4. Restoring Data (The "Retrieval" Phase)

To get your data back, run the `restore` command from the `pdf_hide` module.

```bash
python pdf_hide.py restore \
  --manifest pdf_files.txt \
  --restore_pdf_dir ./injected_output \
  --restore_dir ./recovered_data \
  --password "your_secure_passphrase"

```

---

## 🛡 Forensic Verification

After restoration, you can verify that the metadata of your injected PDFs matches the originals perfectly:

```bash
python pdf_sync.py audit --source ./clean_pdfs --target ./injected_output

```

**Expected Output:**

```text
[✓] carrier_01.pdf : Birthtime Match
[✓] carrier_01.pdf : Modtime Match
[✓] carrier_02.pdf : Birthtime Match...

```

---

## 🧪 Running Tests

Always run the suite before deployment to ensure your local environment supports the kernel calls:

```bash
python pdf_test.py

```

---

### 🏁 Final Project Structure

To make this GitHub-ready, your folder should look like this:

* `pdf_hide.py`
* `pdf_sync.py`
* `pdf_run.py`


* `pdf_test.py`
* `README.md`
* `INTERNAL_LOGIC.md`
* `.gitignore` (Add `__pycache__/`, `pdf_files.txt`, and `pdf_pwd.txt` here)

**Would you like me to generate a `.gitignore` file for you so you don't accidentally upload your passwords or temporary test files to GitHub?**