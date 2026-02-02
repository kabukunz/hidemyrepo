python3 pdf_erase.py erase

# python3 pdf_hide.py hide \
#   --source_pdf_dir source_pdf_dir \
#   --restore_pdf_dir restore_pdf_dir \
#   --max_carriers 50 \
#   --carrier_size_max_incr 0.30

python3 pdf_hide.py hide

python3 pdf_sync.py sync

python3 pdf_hide.py restore

python3 pdf_hide.py diff

python3 pdf_hide.py hash

python3 pdf_sync.py audit
