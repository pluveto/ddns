# coding: utf-8
# Install deps first:
# pip install requests
# Usage:
# To setup some-sub-domain.yourdomain.com:
# $ DNSPOD_TOKEN_ID=*** DNSPOD_TOKEN=*** python update_ddns_on_dnspod.py --domain yourdomain.com --sub-domain some-sub-domain

import os
import sys
import json
import argparse
import socket
import subprocess
import requests
import logging
# https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
logging.captureWarnings(True)

DNSPOD_TOKEN_ID = ""
DNSPOD_TOKEN = ""

DNSPOD_MY_IP_SERVICE = ('ns1.dnspod.net', 6666)
DNS_PUBLIC_IP_SERVICES = [
    # dig_type, ns_server, special_domain
    ("txt", "ns1.google.com", "o-o.myaddr.l.google.com"),
    ("a", "ns1-1.akamaitech.net", "whoami.akamai.net"),
    ("a", "resolver1.opendns.com", "myip.opendns.com"),
]
DNSPOD_BASE_URL = "https://dnsapi.cn"

logger = logging.getLogger(__name__)


def is_valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except:
        return False


def get_public_ip_using_dig():
    for dig_type, ns_server, special_domain in DNS_PUBLIC_IP_SERVICES:
        for retry in range(2):
            try:
                output = subprocess.check_output([
                    "dig", "-4", "-t", dig_type,
                    "@%s" % ns_server,
                    special_domain,
                    "+short"
                ])
            except subprocess.CalledProcessError:
                continue

            for line in output.splitlines():
                line = line.strip(' "\n"')
                if is_valid_ip(line):
                    return line

    raise RuntimeError("Failed to fetch public ip")


def get_public_ip():
    services = ['http://ip.42.pl/raw', 'http://ifconfig.me/ip',
                'http://ipecho.net/plain', 'http://icanhazip.com/']
    for service in services:
        try:
            return requests.get(service).text.strip()
        except:
            continue
    raise RuntimeError("Failed to fetch public ip")


def request_dnspod_api(api_name, payload={}):
    url = "%s/%s" % (DNSPOD_BASE_URL, api_name)
    data = payload.copy()

    data.update({
        "login_token": "%s,%s" % (DNSPOD_TOKEN_ID, DNSPOD_TOKEN),
        "format": "json"
    })

    res = requests.post(url, data)
    res_dict = res.json()
    if res_dict.get("status", {}).get("code") != '1':
        raise RuntimeError(
            "Failed to request %s: %s" % (
                api_name,
                json.dumps(res_dict, indent=2,
                           ensure_ascii=False, encoding='utf-8')
            )
        )
    return res_dict


def get_domain_id(domain_name):
    domains_dict = request_dnspod_api("Domain.List")
    for domain_dict in domains_dict["domains"]:
        if domain_dict["name"] == domain_name:
            return domain_dict["id"]


def get_record(domain_id, sub_domain):
    payload = {
        "domain_id": str(domain_id),
    }
    records_dict = request_dnspod_api("Record.List", payload)
    for record_dict in records_dict["records"]:
        if record_dict["name"] == sub_domain:
            return record_dict


def update_ddns(domain_id, sub_domain, ip, record_id=None):
    """
    Args:
        Create record if record_id is None
    """
    payload = {
        "domain_id": str(domain_id),
        "sub_domain": sub_domain,
        "record_type": "A",
        "record_line": "默认",
        "value": ip,
    }
    if record_id is not None:
        payload["record_id"] = str(record_id),
        return request_dnspod_api("Record.Ddns", payload)
    else:
        return request_dnspod_api("Record.Create", payload)


def setup_ddns(domain_name, sub_domain, ip):

    domain_id = get_domain_id(domain_name)
    if domain_id is None:
        logger.error("Failed to find domain_id for %s" % domain_name)
        return 1

    record_id = None
    record = get_record(domain_id, sub_domain)
    if record is not None:
        if record["value"] == ip:
            logger.info("No change")
            return
        record_id = record["id"]

    res_dict = update_ddns(domain_id, sub_domain, ip, record_id)
    logger.info(json.dumps(res_dict, indent=2))


def setup_logger(logger):
    log_format = '%(asctime)-15s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s'
    formatter = logging.Formatter(log_format)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def main():
    setup_logger(logger)

    global DNSPOD_TOKEN_ID
    global DNSPOD_TOKEN

    for k in ("DNSPOD_TOKEN_ID", "DNSPOD_TOKEN"):
        if k not in os.environ:
            logger.error('%r is not found in os.environ' % k)
            return 1

    DNSPOD_TOKEN_ID = os.environ["DNSPOD_TOKEN_ID"]
    DNSPOD_TOKEN = os.environ["DNSPOD_TOKEN"]

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--domain", required=True,
        help="Domain name to setup. e.g.: google.com"
    )

    parser.add_argument(
        "--sub-domain", required=True,
        help="Sub domain name to setup. e.g.: gateway (for gateway.google.com)"
    )

    parser.add_argument(
        "-q", "--quiet", action="store_true", default=False,
        help="Run quietly."
    )

    opts = parser.parse_args()

    domain = opts.domain
    sub_domain = opts.sub_domain
    quiet = opts.quiet
    if quiet:
        logger.setLevel(logging.WARN)

    ip = get_public_ip()
    logger.info("Public IP: %s" % ip)
    return setup_ddns(domain, sub_domain, ip)


if __name__ == '__main__':
    sys.exit(main())
