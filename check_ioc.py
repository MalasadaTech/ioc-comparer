import os
import json
import random
import time
import ipaddress
from datetime import datetime, timezone, timedelta
from utils import get_ips, get_asn, get_rdap_data, get_ssl_certs

def is_ip(ioc):
    """Determine if an IOC is an IP address."""
    try:
        ipaddress.ip_address(ioc)
        return True
    except ValueError:
        return False

def check_ioc(ioc, tld_to_rdap):
    """Check a single IOC and save its metadata to a JSON file."""
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    json_file = os.path.join(output_dir, f"{ioc}.json")
    current_time = datetime.now(timezone.utc)

    # Check if IOC was recently analyzed
    if os.path.exists(json_file):
        with open(json_file, "r") as f:
            data = json.load(f)
        check_date_str = data.get("check_date")
        if check_date_str:
            check_date = datetime.fromisoformat(check_date_str)
            if current_time - check_date < timedelta(days=1):
                print(f"{ioc} was not re-checked because it was already checked on {check_date_str}.")
                return

    # Handle IP (placeholder for future implementation)
    if is_ip(ioc):
        print("IP checking will be implemented in the future.")
        return

    # Handle domain
    time.sleep(random.uniform(1, 3))  # Random delay between 1000ms and 3000ms
    ips = get_ips(ioc)
    ip_list = []
    # Update the ASN extraction to include both asn_name and asn_country
    for ip in ips:
        asn_number, asn_name, asn_country = get_asn(ip)  # Update get_asn to return asn_country
        ip_dict = {"address": ip}
        if asn_number:
            ip_dict["asn_number"] = asn_number
            ip_dict["asn_name"] = asn_name
            ip_dict["asn_country"] = asn_country  # Add asn_country to the IP dictionary
        ip_list.append(ip_dict)

    rdap_data = get_rdap_data(ioc, tld_to_rdap)
    ssl_certs = get_ssl_certs(ioc)

    data = {
        "check_date": current_time.isoformat(),
        "ips": ip_list,
        "rdap": rdap_data,
        "ssl_certs": ssl_certs
    }

    with open(json_file, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Done checking {ioc}. Info saved in {ioc}.json")