import os
import json
import random
import time
import ipaddress
from datetime import datetime, timezone, timedelta
from utils import get_ips, get_asn, get_rdap_data, get_ssl_certs, calculate_nshash
try:
    from otx_client import OTXClient
except ImportError:
    OTXClient = None

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
            output.append(f"- Address: {ip['address']} (Type: {ip['type']})")
            if ip.get("hostname"):
                output.append(f"  Hostname: {ip['hostname']}")
            if ip.get("asn_number"):
                output.append(f"  ASN: {ip['asn_number']} ({ip.get('asn_name', 'Unknown')}, {ip.get('asn_country', 'Unknown')})")
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
    
    # Add OTX information if available
    otx_data = data.get("otx", {})
    if otx_data:
        output.append("\nAlienVault OTX Data:")
        
        # Add general details
        if "details" in otx_data:
            details = otx_data["details"]
            output.append("- OTX General Details:")
            
            # Add indicator type
            if "type" in details:
                output.append(f"  - OTX Type: {details['type']}")
            
            # Add creation date
            if "created" in details:
                output.append(f"  - OTX First Seen: {details['created']}")

            # Check for pulse info directly in the details
            if "pulse_info" in details and details["pulse_info"].get("count", 0) > 0:
                pulse_info = details["pulse_info"]
                output.append(f"  - OTX Pulse Count: {pulse_info.get('count', 0)}")
        
        # Add pulse information from top-level data
        if "pulse_count" in otx_data:
            output.append(f"- OTX Threat Intelligence: Associated with {otx_data['pulse_count']} OTX threat reports")
            if "recent_pulses" in otx_data and otx_data["recent_pulses"]:
                output.append("- OTX Recent Reports:")
                for pulse in otx_data["recent_pulses"]:
                    output.append(f"  - {pulse}")
            if "most_recent_pulse" in otx_data:
                output.append(f"- OTX Most Recent Report: {otx_data['most_recent_pulse']}")
        
        # Add reputation data if available
        if "reputation" in otx_data:
            rep = otx_data["reputation"]
            output.append("- OTX Reputation:")
            if "reputation" in rep:
                output.append(f"  - OTX Reputation Score: {rep['reputation']}")
            if "threat_score" in rep:
                output.append(f"  - OTX Threat Score: {rep['threat_score']}")
    else:
        output.append("\nAlienVault OTX Data: Not available")

    # Create formatted string
    formatted_output = "\n".join(output)
    
    # Save to file
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    analysis_filename = os.path.join(output_dir, f"Analysis-{ioc}-{timestamp}.txt")
    with open(analysis_filename, "w") as f:
        f.write(formatted_output)
    
    print(f"Analysis saved to {analysis_filename}")
    return formatted_output, analysis_filename

def determine_ioc_type(ioc):
    """Determine the type of IOC."""
    try:
        # Check if it's an IP address
        ipaddress.ip_address(ioc)
        if ':' in ioc:
            return 'ipv6'
        return 'ipv4'
    except ValueError:
        # Check if it's a domain (simple check)
        if '.' in ioc and not ioc.startswith('http'):
            return 'domain'
        # Check if it's a URL
        elif ioc.startswith(('http://', 'https://')):
            return 'url'
        # Check if it could be a hash (simple length-based guess)
        elif len(ioc) == 32:
            return 'md5'
        elif len(ioc) == 40:
            return 'sha1'
        elif len(ioc) == 64:
            return 'sha256'
        elif len(ioc) == 128:
            return 'sha512'
        # Default to unknown
        return 'unknown'

def check_ioc(ioc, tld_to_rdap, config_path="config.ini"):
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

    # Initialize the OTX client by default
    otx_client = None
    if OTXClient:
        try:
            otx_client = OTXClient(config_path=config_path)
        except (FileNotFoundError, ValueError) as e:
            otx_client = None

    # Determine IOC type
    ioc_type = determine_ioc_type(ioc)

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

    # Get OTX data by default when available
    otx_data = {}
    if otx_client:
        # Get general indicator details
        details = otx_client.get_indicator_details(ioc_type, ioc)
        if details:
            otx_data["details"] = details
            
            # Extract pulse_info from the general details response if available
            if 'pulse_info' in details and details['pulse_info'].get('count', 0) > 0:
                pulse_info = details['pulse_info']
                pulses = pulse_info.get('pulses', [])
                
                # Add pulse count
                otx_data["pulse_count"] = pulse_info.get('count', 0)
                
                # Add recent pulses
                if pulses:
                    otx_data["recent_pulses"] = [p.get('name') for p in pulses[:5]]
                    
                    # Get the most recent modified date
                    try:
                        most_recent = max(pulses, key=lambda x: x.get('modified', ''))
                        otx_data["most_recent_pulse"] = most_recent.get('modified')
                    except (ValueError, KeyError):
                        # Silently continue if we can't determine most recent date
                        pass
            
        # If we don't have pulse data from general details, try the separate endpoint
        if "pulse_count" not in otx_data:
            pulses = otx_client.get_pulse_info(ioc_type, ioc)
            if pulses:
                # Just get the count and names of the most recent pulses
                otx_data["pulse_count"] = len(pulses)
                otx_data["recent_pulses"] = [p.get('name') for p in pulses[:5]]
                
                # Get the most recent modified date
                if pulses:
                    try:
                        most_recent = max(pulses, key=lambda x: x.get('modified', ''))
                        otx_data["most_recent_pulse"] = most_recent.get('modified')
                    except (ValueError, KeyError):
                        # Silently continue if we can't determine most recent date
                        pass
                
        # Get reputation for IP/domain
        if ioc_type.lower() in ['ipv4', 'ipv6', 'domain']:
            reputation = otx_client.get_reputation(ioc_type, ioc)
            if reputation:
                otx_data["reputation"] = reputation

    data = {
        "check_date": current_time.isoformat(),
        "ips": ip_list,
        "rdap": rdap_data,
        "ssl_certs": ssl_certs
    }

    # Add OTX data if it exists
    if otx_data:
        data["otx"] = otx_data

    with open(json_file, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Done checking {ioc}. Info saved in {ioc}.json")

    # Print detailed analysis output
    formatted_output, analysis_filename = format_single_ioc_output(ioc, data, output_dir)
    print(formatted_output)