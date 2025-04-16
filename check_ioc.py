import os
import json
import random
import time
import ipaddress
from datetime import datetime, timezone, timedelta
from utils import get_ips, get_asn, get_rdap_data, get_ssl_certs, calculate_nshash

def is_ip(ioc):
    """Determine if an IOC is an IP address."""
    try:
        ipaddress.ip_address(ioc)
        return True
    except ValueError:
        return False

def format_single_ioc_output(ioc, data, output_dir):
    """Format the output for a single IOC analysis and save to file."""
    output = [f"Analysis for {ioc}:"]
    output.append("=" * 50)
    output.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    output.append("=" * 50)

    # Add RDAP information
    rdap = data.get("rdap", {})
    output.append("\n(PTA0001: Domain) RDAP Data:")
    for key, value in rdap.items():
        if key == "name_servers" and value:
            # Calculate the nshash for name servers
            nshash = calculate_nshash(value)
            output.append(f"- {key.capitalize()}: {', '.join(value) if value else 'None'} (nshash: {nshash})")
        elif isinstance(value, list):
            output.append(f"- {key.capitalize()}: {', '.join(value) if value else 'None'}")
        else:
            output.append(f"- {key.capitalize()}: {value if value else 'None'}")

    # Add IP information
    ips = data.get("ips", [])
    if ips:
        output.append("\n(PTA0002: IP) IPs:")
        for ip in ips:
            ip_info = f"- Address: {ip['address']} (Type: {ip['type']})"
            if ip.get("hostname"):
                ip_info += f", Hostname: {ip['hostname']}"
            if ip.get("asn_number"):
                ip_info += f", ASN: {ip['asn_number']} ({ip.get('asn_name', 'Unknown')}, {ip.get('asn_country', 'Unknown')})"
            output.append(ip_info)
    else:
        output.append("- No IPs found.")

    # Add SSL certificate information
    ssl_certs = data.get("ssl_certs", [])
    output.append("\n(PTA0003: SSL) SSL Certificates:")
    if ssl_certs:
        for cert in ssl_certs:
            output.append(f"- ID: {cert.get('id', 'Unknown')}, Issuer: {cert.get('issuer_name', 'Unknown')}, Common Name: {cert.get('common_name', 'Unknown')}, Validity: {cert.get('not_before', 'Unknown')} to {cert.get('not_after', 'Unknown')}")
    else:
        output.append("- No SSL certificates found.")

    # Create formatted string
    formatted_output = "\n".join(output)
    
    # Save to file
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    analysis_filename = os.path.join(output_dir, f"Analysis-{ioc}-{timestamp}.txt")
    with open(analysis_filename, "w") as f:
        f.write(formatted_output)
    
    print(f"Analysis saved to {analysis_filename}")
    return formatted_output, analysis_filename

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
    ip_data = get_ips(ioc)
    ip_list = []
    
    # Update the ASN extraction to include both asn_name and asn_country
    for ip_entry in ip_data:
        ip_address = ip_entry["ip"]
        asn_number, asn_name, asn_country = get_asn(ip_address)
        ip_dict = {
            "address": ip_address,
            "type": ip_entry["type"],
            "hostname": ip_entry["hostname"]  # Include the reverse DNS lookup result
        }
        if asn_number:
            ip_dict["asn_number"] = asn_number
            ip_dict["asn_name"] = asn_name
            ip_dict["asn_country"] = asn_country
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

    # Print detailed analysis output
    formatted_output, analysis_filename = format_single_ioc_output(ioc, data, output_dir)
    print(formatted_output)