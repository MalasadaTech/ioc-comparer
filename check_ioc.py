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
try:
    from vt_client import VTClient
except ImportError:
    VTClient = None
try:
    from threatfox_client import ThreatFoxClient
except ImportError:
    ThreatFoxClient = None
try:
    from ipinfo_client import IPinfoClient
except ImportError:
    IPinfoClient = None

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
                asn_source = ip.get('asn_source', 'Unknown Source')
                output.append(f"  ASN: {ip['asn_number']} ({ip.get('asn_name', 'Unknown')}, {ip.get('asn_country', 'Unknown')}) [Source: {asn_source}]")
    else:
        output.append("- No IPs found.")

    # Add SSL certificate information
    ssl_certs = data.get("ssl_certs", [])
    output.append("\n(PTA0003: SSL) SSL Certificates:")
    if isinstance(ssl_certs, dict) and "error" in ssl_certs:
        # Handle error case
        output.append(f"- Error: {ssl_certs['error']}")
    elif ssl_certs:
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
    
    # Add VirusTotal information if available
    vt_data = data.get("virustotal", {})
    if vt_data:
        output.append("\nVirusTotal Data:")
        
        # Add vendor statistics
        if "vendor_stats" in vt_data:
            stats = vt_data["vendor_stats"]
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            output.append(f"- VT Vendor Score: {malicious + suspicious}/{total} ({malicious} malicious, {suspicious} suspicious)")
        
        # Add community score
        if "community_score" in vt_data:
            output.append(f"- VT Community Score: {vt_data['community_score']}")
        
        # Add tags
        if "tags" in vt_data and vt_data["tags"]:
            output.append(f"- VT Tags: {', '.join(vt_data['tags'])}")
        
        # Add categories if available
        if "categories" in vt_data and vt_data["categories"]:
            cat_strings = [f"{provider}: {category}" for provider, category in vt_data["categories"].items()]
            output.append(f"- VT Categories: {', '.join(cat_strings[:5])}" + 
                          (f" (+ {len(cat_strings) - 5} more)" if len(cat_strings) > 5 else ""))
        
        # Add registrar if available
        if "registrar" in vt_data:
            output.append(f"- VT Registrar: {vt_data['registrar']}")
            
        # Add JARM hash if available
        if "jarm" in vt_data:
            output.append(f"- VT JARM Hash: {vt_data['jarm']}")
            
        # Add DNS records if available
        if "a_records" in vt_data or "aaaa_records" in vt_data or "ns_records" in vt_data:
            output.append("- VT DNS Records:")
            if "a_records" in vt_data:
                output.append(f"  - A Records: {', '.join(vt_data['a_records'])}")
            if "aaaa_records" in vt_data:
                output.append(f"  - AAAA Records: {', '.join(vt_data['aaaa_records'])}")
            if "ns_records" in vt_data:
                output.append(f"  - NS Records: {', '.join(vt_data['ns_records'])}")
        
        # Add community votes if available
        if "total_votes" in vt_data:
            votes = vt_data["total_votes"]
            harmless = votes.get("harmless", 0)
            malicious = votes.get("malicious", 0)
            output.append(f"- VT Community Votes: {malicious} malicious, {harmless} harmless")
            
        # Add popularity information if available
        if "popularity_ranks" in vt_data and vt_data["popularity_ranks"]:
            rank_strings = [f"{provider}: {details.get('rank', 'N/A')}" 
                            for provider, details in vt_data["popularity_ranks"].items()]
            output.append(f"- VT Popularity Ranks: {', '.join(rank_strings[:3])}" + 
                          (f" (+ {len(rank_strings) - 3} more)" if len(rank_strings) > 3 else ""))
        
        # Add analysis dates
        if "last_analysis_date" in vt_data:
            last_date = datetime.fromtimestamp(vt_data["last_analysis_date"], tz=timezone.utc)
            output.append(f"- VT Last Analysis: {last_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            
        if "creation_date" in vt_data:
            creation_date = datetime.fromtimestamp(vt_data["creation_date"], tz=timezone.utc)
            output.append(f"- VT Creation Date: {creation_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            
        if "first_submission_date" in vt_data:
            first_date = datetime.fromtimestamp(vt_data["first_submission_date"], tz=timezone.utc)
            output.append(f"- VT First Submission: {first_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    else:
        output.append("\nVirusTotal Data: Not available")

    # Add ThreatFox information if available
    threatfox_data = data.get("threatfox", {})
    if threatfox_data:
        output.append("\nThreatFox Data:")
        
        # Add IOC information
        if "ioc" in threatfox_data:
            output.append(f"- ThreatFox IOC: {threatfox_data['ioc']}")
        
        # Add threat type and description
        if "threat_type" in threatfox_data and "threat_type_desc" in threatfox_data:
            output.append(f"- ThreatFox Threat Type: {threatfox_data['threat_type']} ({threatfox_data['threat_type_desc']})")
        
        # Add malware information
        if "malware" in threatfox_data and "malware_printable" in threatfox_data:
            output.append(f"- ThreatFox Malware: {threatfox_data['malware_printable']} ({threatfox_data['malware']})")
            
            # Add malware aliases if available
            if "malware_alias" in threatfox_data and threatfox_data["malware_alias"]:
                output.append(f"- ThreatFox Malware Aliases: {threatfox_data['malware_alias']}")
        
        # Add confidence level
        if "confidence_level" in threatfox_data:
            output.append(f"- ThreatFox Confidence Level: {threatfox_data['confidence_level']}")
        
        # Add first seen date
        if "first_seen" in threatfox_data:
            output.append(f"- ThreatFox First Seen: {threatfox_data['first_seen']}")
        
        # Add reporter information
        if "reporter" in threatfox_data:
            output.append(f"- ThreatFox Reporter: {threatfox_data['reporter']}")
        
        # Add tags if available
        if "tags" in threatfox_data and threatfox_data["tags"]:
            output.append(f"- ThreatFox Tags: {threatfox_data['tags']}")
            
        # Add malware samples count if available
        if "malware_samples_count" in threatfox_data:
            output.append(f"- ThreatFox Associated Malware Samples: {threatfox_data['malware_samples_count']}")
            
            # Add sample info if available
            if "sample_info" in threatfox_data:
                sample = threatfox_data["sample_info"]
                if "sha256_hash" in sample:
                    output.append(f"- ThreatFox Sample SHA256: {sample['sha256_hash']}")
                if "malware_bazaar" in sample:
                    output.append(f"- ThreatFox Sample Link: {sample['malware_bazaar']}")
    else:
        output.append("\nThreatFox Data: Not available")

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
    
    # Initialize the VirusTotal client
    vt_client = None
    if VTClient:
        try:
            vt_client = VTClient(config_path=config_path)
        except (FileNotFoundError, ValueError) as e:
            vt_client = None

    # Initialize the ThreatFox client
    threatfox_client = None
    if ThreatFoxClient:
        try:
            threatfox_client = ThreatFoxClient(config_path=config_path)
        except (FileNotFoundError, ValueError) as e:
            threatfox_client = None

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
    
    # Update the ASN extraction to include both asn_name, asn_country, and asn_source
    for ip_entry in ip_data:
        ip_address = ip_entry["ip"]
        asn_number, asn_name, asn_country, asn_source = get_asn(ip_address, config_path)
        ip_dict = {
            "address": ip_address,
            "type": ip_entry["type"],
            "hostname": ip_entry["hostname"]  # Include the reverse DNS lookup result
        }
        if asn_number:
            ip_dict["asn_number"] = asn_number
            ip_dict["asn_name"] = asn_name
            ip_dict["asn_country"] = asn_country
            ip_dict["asn_source"] = asn_source
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
    
    # Get VirusTotal data when available
    vt_data = {}
    if vt_client and vt_client.api_key:
        # Get indicator details
        vt_details = vt_client.get_indicator_details(ioc_type, ioc)
        if vt_details:
            # Extract summary data
            vt_data = vt_client.extract_vt_summary(vt_details)

    # Get ThreatFox data when available
    threatfox_data = {}
    if threatfox_client and threatfox_client.api_key:
        # Search for IOC in ThreatFox
        threatfox_result = threatfox_client.search_ioc(ioc)
        if threatfox_result:
            threatfox_data = threatfox_result

    data = {
        "check_date": current_time.isoformat(),
        "ips": ip_list,
        "rdap": rdap_data,
        "ssl_certs": ssl_certs
    }

    # Add OTX data if it exists
    if otx_data:
        data["otx"] = otx_data
    
    # Add VirusTotal data if it exists
    if vt_data:
        data["virustotal"] = vt_data

    # Add ThreatFox data if it exists
    if threatfox_data:
        data["threatfox"] = threatfox_data

    with open(json_file, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Done checking {ioc}. Info saved in {ioc}.json")

    # Print detailed analysis output
    formatted_output, analysis_filename = format_single_ioc_output(ioc, data, output_dir)
    print(formatted_output)