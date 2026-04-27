rm -rf hide_carrier
cp -R hide_carrier_copy hide_carrier
python pdf_hide.py hide -xf -xc --in-place
python pdf_sync.py sync --hide_carrier ./hide_carrier_copy --found_carrier ./hide_carrier
python pdf_hide.py diff --hide_carrier ./hide_carrier_copy --found_carrier ./hide_carrier
python pdf_sync.py audit --hide_carrier ./hide_carrier_copy --found_carrier ./hide_carrier