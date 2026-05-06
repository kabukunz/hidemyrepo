rm -rf hide_carrier
cp -R hide_carrier_copy hide_carrier
rm -rf hide_payload
cp -R hide_payload_copy hide_payload
python pdf_hide.py hide -xf -xc

python pdf_hide.py diff
python pdf_hide.py hash
python pdf_hide.py sync
python pdf_hide.py audit

python pdf_hide.py restore

#python pdf_hide.py erase

diff -rq hide_payload hide_payload_copy

