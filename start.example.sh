export DNSPOD_TOKEN_ID=123456
export DNSPOD_TOKEN=12345c555551effec3cb06d555554444
python3 ddns_dnspod.py --domain example.com --sub-domain `hostname` 2>&1 | tee -a ddns.log
