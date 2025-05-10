try:
    import dns.resolver
    import dns.reversename
except ImportError:
    raise ImportError("The 'dnspython' library is required but not installed. Install it using 'pip install dnspython'.")
import ipaddress
import requests
from datetime import datetime, timezone
import time
import hashlib  # Add this import for MD5 hash calculation

try:
    from ipinfo_client import IPinfoClient
except ImportError:
    IPinfoClient = None

def get_ptr_record(ip):
    """Perform a reverse DNS lookup for an IP address."""
    try:
        addr = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(addr, 'PTR')
        return str(answers[0]).rstrip('.')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except Exception as e:
        print(f"Error resolving PTR record for {ip}: {e}")
        return None

def get_ips(domain):
    """Resolve IP addresses (A and AAAA records) for a domain and perform reverse lookups."""
    ip_data = []
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for answer in answers:
            ip = str(answer)
            hostname = get_ptr_record(ip)
            ip_data.append({"ip": ip, "type": "A", "hostname": hostname})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as e:
        print(f"Error resolving A records for {domain}: {e}")
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        for answer in answers:
            ip = str(answer)
            hostname = get_ptr_record(ip)
            ip_data.append({"ip": ip, "type": "AAAA", "hostname": hostname})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as e:
        print(f"Error resolving AAAA records for {domain}: {e}")
    return ip_data

def reverse_ip(ip):
    """Reverse an IP address for ASN lookup."""
    if ':' in ip:
        ip_obj = ipaddress.ip_address(ip)
        reversed_ip = '.'.join(reversed(ip_obj.exploded.replace(':', '')))
        zone = 'origin6.asn.cymru.com'
    else:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        zone = 'origin.asn.cymru.com'
    return reversed_ip + '.' + zone

def get_asn_from_cymru(ip):
    """Get ASN information from Team Cymru DNS service."""
    query_name = reverse_ip(ip)
    try:
        answers = dns.resolver.resolve(query_name, 'TXT')
        txt_record = answers[0].to_text().strip('"')
        fields = txt_record.split(' | ')
        asn_number = fields[0].split()[0]
        asn_answers = dns.resolver.resolve(f"AS{asn_number}.asn.cymru.com", 'TXT')
        asn_txt_record = asn_answers[0].to_text().strip('"')
        asn_fields = asn_txt_record.split(' | ')
        asn_name = asn_fields[4].strip()  # Correctly assign the AS name (field 4)
        asn_country = asn_fields[1].strip()  # Correctly assign the AS country (field 1)
        # Remove trailing ", {asn_country}" from asn_name if it exists
        if asn_name.endswith(f", {asn_country}"):
            asn_name = asn_name[: -len(f", {asn_country}")]
        return asn_number, asn_name, asn_country, "Team Cymru"
    except Exception as e:
        print(f"Error retrieving ASN from Team Cymru for {ip}: {e}")
        return None, None, None, None

def get_asn(ip, config_path=".env"):
    """Get ASN number, name, and country for an IP."""
    # Try IPinfo.io first if available
    if IPinfoClient:
        try:
            ipinfo_client = IPinfoClient(env_path=config_path)
            if ipinfo_client.api_key:  # Only proceed if we have an API key
                asn_number, asn_name, asn_country = ipinfo_client.get_asn_info(ip)
                if asn_number:
                    return asn_number, asn_name, asn_country, "IPinfo"
        except Exception as e:
            print(f"Error retrieving ASN from IPinfo for {ip}: {e}")
    
    # Fall back to Cymru lookup
    return get_asn_from_cymru(ip)

def get_rdap_bootstrap():
    """Fetch RDAP bootstrap data."""
    url = "https://data.iana.org/rdap/dns.json"
    try:
        response = requests.get(url)
        if 400 <= response.status_code < 600:
            print(f"IANA RDAP bootstrap service returned HTTP {response.status_code}")
            return {}
        response.raise_for_status()
        data = response.json()
        tld_to_rdap = {tld.lower(): urls[0] for entry in data['services'] for tld in entry[0] for urls in [entry[1]]}
        return tld_to_rdap
    except requests.RequestException as e:
        print(f"Error fetching RDAP bootstrap: {e}")
        return {}

def get_rdap_data(domain, tld_to_rdap):
    """Get RDAP data for a domain."""
    parts = domain.split('.')
    if len(parts) < 2:
        return {"error": "Invalid domain"}
    tld = parts[-1].lower()
    rdap_base_url = tld_to_rdap.get(tld)
    if not rdap_base_url:
        return {"error": f"No RDAP server found for TLD: {tld}"}
    rdap_url = f"{rdap_base_url.rstrip('/')}/domain/{domain}"
    try:
        response = requests.get(rdap_url)
        if response.status_code == 404:
            return {"error": "Domain not found"}
        elif 400 <= response.status_code < 600:
            return {"error": f"RDAP server returned HTTP {response.status_code}"}
        response.raise_for_status()
        data = response.json()
        status = data.get('status', [])
        events = data.get('events', [])
        creation_date = next((e['eventDate'] for e in events if e['eventAction'] == 'registration'), None)
        expiration_date = next((e['eventDate'] for e in events if e['eventAction'] == 'expiration'), None)
        entities = data.get('entities', [])
        registrar = next((
            next((i[3] for i in e['vcardArray'][1] if i[0] == 'fn'), "Unknown")
            for e in entities
            if 'registrar' in e.get('roles', []) and 'vcardArray' in e and len(e['vcardArray']) > 1
        ), "Unknown")
        registrar = f"{registrar} ({next((e.get('handle', 'none') for e in entities if 'registrar' in e.get('roles', [])), 'none')})"
        registrant = next(({
            "name": next((i[3] for i in e['vcardArray'][1] if i[0] == 'fn'), "none"),
            "handle": e.get('handle', "none")
        } for e in entities if 'registrant' in e.get('roles', []) and 'vcardArray' in e and len(e['vcardArray']) > 1), {"name": "Unknown", "handle": "none"})
        registrant = f"{registrant['name']} ({registrant['handle']})"
        
        # Normalize and sort name servers - remove trailing dots and convert to lowercase
        name_servers = sorted([ns['ldhName'].lower().rstrip('.') for ns in data.get('nameservers', [])])
        
        return {
            "status": status,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "registrar": registrar,
            "registrant": registrant,
            "name_servers": name_servers
        }
    except Exception as e:
        return {"error": f"RDAP request failed: {e}"}

def get_ssl_certs(domain):
    """Retrieve active SSL certificates from crt.sh."""
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url)
        if 400 <= response.status_code < 600:
            return {"error": f"crt.sh returned HTTP {response.status_code}"}
        response.raise_for_status()
        certs = response.json()
        if not certs:
            return []
        current_time = datetime.now(timezone.utc)
        parsed_certs = []
        for cert in certs:
            try:
                not_before = datetime.fromisoformat(cert.get("not_before").replace(" ", "T")).replace(tzinfo=timezone.utc)
                not_after = datetime.fromisoformat(cert.get("not_after").replace(" ", "T")).replace(tzinfo=timezone.utc)
                if not_before <= current_time <= not_after:
                    parsed_certs.append({
                        "id": cert.get("id"),
                        "issuer_name": cert.get("issuer_name"),
                        "common_name": cert.get("common_name"),
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after")
                    })
            except ValueError as e:
                print(f"Error parsing dates for cert {cert.get('id', 'Unknown')}: {e}")
        return parsed_certs
    except requests.RequestException as e:
        print(f"Error querying crt.sh for {domain}: {e}")
        return {"error": f"SSL cert lookup failed: {str(e)}"}

def get_issuing_org(issuer_name):
    """Extract issuing organization from issuer_name."""
    if not issuer_name:
        return None
    parts = issuer_name.split(', ')
    for part in parts:
        if part.startswith('O='):
            # Extract the organization name and completely remove any quotes
            org_name = part[2:]
            # Remove quotes from the organization name to prevent display issues
            return org_name.replace('"', '')
    return None

def parse_date(date_str):
    """Parse a date string into a datetime object."""
    if date_str:
        try:
            date_str = date_str.replace(" ", "T")
            if 'Z' in date_str:
                date_str = date_str.replace('Z', '+00:00')
            elif '+' not in date_str and 'T' in date_str:
                date_str += '+00:00'
            return datetime.fromisoformat(date_str)
        except ValueError:
            return None
    return None

def calculate_nshash(name_servers):
    """
    Calculate the MD5 hash of nameservers for Silent Push pivoting.
    
    Args:
        name_servers (list): A list of nameserver strings
        
    Returns:
        str: MD5 hash of the comma-joined nameservers without spaces
    """
    if not name_servers:
        return None
    
    # Sort, normalize and join nameservers with commas (no spaces)
    sorted_ns = sorted([ns.lower().rstrip('.') for ns in name_servers])
    ns_string = ','.join(sorted_ns)
    
    # Calculate MD5 hash
    md5_hash = hashlib.md5(ns_string.encode('utf-8')).hexdigest()
    return md5_hash

def re_fang_domain(ioc):
    """Remove defanging from an IOC (e.g., example[.]com -> example.com)."""
    return ioc.replace("[", "").replace("]", "")