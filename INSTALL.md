================================================================================
FORENSIC PDF STEGANOGRAPHY SUITE - SYSTEM & ENVIRONMENT REQUIREMENTS
================================================================================

CATEGORY       | REQUIREMENT            | PURPOSE / DEPENDENCY
---------------|------------------------|---------------------------------------
Language       | Python >= 3.9          | Core execution environment
Library        | Standard Library       | Zero-dependency architecture (no pip)
OS Platform    | macOS (Darwin)         | Required for libc kernel & xattr calls
System Tool    | xattr                  | Mirroring 'Date Added' attributes
System Tool    | chflags                | Managing 'locked' file attributes
System Tool    | stat                   | High-precision timestamp extraction
System Tool    | touch                  | Temporal window alignment
Kernel Lib     | /usr/lib/libc.dylib    | Low-level Birth Date (creation) forgery
---------------|------------------------|---------------------------------------

REQUIRED DIRECTORY STRUCTURE:
-----------------------------
DIRECTORY NAME     | ROLE               | USER ACTION
-------------------|--------------------|---------------------------------------
source_dir/        | Payload Source     | Place secret files to be hidden here
source_pdf_dir/    | Carrier Pool       | Place clean/original PDFs here
restore_pdf_dir/   | Output Directory   | Destination for injected stego-PDFs
restore_dir/       | Verification Path  | Destination for restored/extracted data
================================================================================
