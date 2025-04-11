import sys
import json
import dns.resolver
import ipaddress
import requests
from datetime import datetime, timedelta, timezone
import time

# Function to resolve IP addresses (A and AAAA records)
def get_ips(domain):
    ips = []
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ips.extend([str(answer) for answer in answers])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as e:
        print(f"Error resolving A records for {domain}: {e}")
    
    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        ips.extend([str(answer) for answer in answers])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as e:
        print(f"Error resolving AAAA records for {domain}: {e}")
    return ips

# Function to reverse an IP for ASN lookup
def reverse_ip(ip):
    if ':' in ip:
        ip_obj = ipaddress.ip_address(ip)
        reversed_ip = '.'.join(reversed(ip_obj.exploded.replace(':', '')))
        zone = 'origin6.asn.cymru.com'
    else:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        zone = 'origin.asn.cymru.com'
    return reversed_ip + '.' + zone

# Function to get ASN number and name
def get_asn(ip):
    query_name = reverse_ip(ip)
    try:
        answers = dns.resolver.resolve(query_name, 'TXT')
        txt_record = answers[0].to_text().strip('"')
        fields = txt_record.split(' | ')
        asn_number = fields[0].split()[0]
        
        asn_query_name = f"AS{asn_number}.asn.cymru.com"
        asn_answers = dns.resolver.resolve(asn_query_name, 'TXT')
        asn_txt_record = asn_answers[0].to_text().strip('"')
        asn_fields = asn_txt_record.split(' | ')
        asn_name = asn_fields[1].strip()
        
        return asn_number, asn_name
    except Exception as e:
        print(f"Error retrieving ASN for {ip}: {e}")
        return None, None

# Function to fetch RDAP bootstrap data
def get_rdap_bootstrap():
    url = "https://data.iana.org/rdap/dns.json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        tld_to_rdap = {}
        for entry in data['services']:
            tlds = entry[0]
            rdap_urls = entry[1]
            for tld in tlds:
                tld_to_rdap[tld.lower()] = rdap_urls[0]
        return tld_to_rdap
    except requests.RequestException as e:
        print(f"Error fetching RDAP bootstrap: {e}")
        return {}

# Function to get RDAP data for a domain
def get_rdap_data(domain, tld_to_rdap):
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
        response.raise_for_status()
        data = response.json()
        
        status = data.get('status', [])
        events = data.get('events', [])
        creation_date = next((event['eventDate'] for event in events if event['eventAction'] == 'registration'), None)
        expiration_date = next((event['eventDate'] for event in events if event['eventAction'] == 'expiration'), None)
        entities = data.get('entities', [])
        registrar_entity = next((entity for entity in entities if 'registrar' in entity.get('roles', [])), None)
        registrant_entity = next((entity for entity in entities if 'registrant' in entity.get('roles', [])), None)
        reseller_entity = next((entity for entity in entities if 'reseller' in entity.get('roles', [])), None)
        sponsor_entity = next((entity for entity in entities if 'sponsor' in entity.get('roles', [])), None)
        proxy_entity = next((entity for entity in entities if 'proxy' in entity.get('roles', [])), None)

        # Update: 20250405 - Extract registrar, registrant, reseller, sponsor, and proxy information
        # Extract registrar information
        registrar = None
        if registrar_entity and 'vcardArray' in registrar_entity:
            vcard = registrar_entity['vcardArray']
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) > 3 and item[0] == 'fn':
                        registrar = item[3]
                        break
        if registrar:
            registrar = f"{registrar} ({registrar_entity.get('handle', 'none')})"
        else:
            registrar = "Unknown"
        # example: "MarkMonitor Inc. (MMR-88)"

        # Extract registrant information
        registrant = None
        for entity in entities:
            if entity.get('roles') and 'registrant' in entity['roles']:
                vcard = entity.get('vcardArray', [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    registrant = {
                        "handle": entity.get('handle', "none"),
                        "name": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'fn'), "none"),
                        "phone": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'tel'), "none"),
                        "email": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'email'), "none"),
                        "address": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'adr'), "none")
                    }
                break

        if registrant:
            registrant = f"{registrant['name']} ({registrant['handle']})\nPhone: {registrant['phone']}\nEmail: {registrant['email']}\nAddress: {registrant['address']}"
        else:
            registrant = "Unknown"

        # Extract reseller information
        reseller = None
        for entity in entities:
            if entity.get('roles') and 'reseller' in entity['roles']:
                vcard = entity.get('vcardArray', [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    reseller = {
                        "handle": entity.get('handle', "none"),
                        "name": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'fn'), "none"),
                        "phone": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'tel'), "none"),
                        "email": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'email'), "none"),
                        "address": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'adr'), "none")
                    }
                break

        if reseller:
            reseller = f"{reseller['name']} ({reseller['handle']})\nPhone: {reseller['phone']}\nEmail: {reseller['email']}\nAddress: {reseller['address']}"
        else:
            reseller = "Unknown"

        # Extract sponsor information
        sponsor = None
        for entity in entities:
            if entity.get('roles') and 'sponsor' in entity['roles']:
                vcard = entity.get('vcardArray', [])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    sponsor = {
                        "handle": entity.get('handle', "none"),
                        "name": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'fn'), "none"),
                        "phone": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'tel'), "none"),
                        "email": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'email'), "none"),
                        "address": next((item[3] for item in vcard[1] if isinstance(item, list) and len(item) > 3 and item[0] == 'adr'), "none")
                    }
                break

        if sponsor:
            sponsor = f"{sponsor['name']} ({sponsor['handle']})\nPhone: {sponsor['phone']}\nEmail: {sponsor['email']}\nAddress: {sponsor['address']}"
        else:
            sponsor = "Unknown"

        # Extract name servers
        name_servers = [ns['ldhName'] for ns in data.get('nameservers', [])]
        # Update: 20250405 - convert name servers to lowercase, and put it in alphabetical order
        name_servers = sorted(ns.lower() for ns in name_servers)
        
        # Format the RDAP data
        rdap_data = {
            "status": status,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "registrar": registrar,
            "registrant": registrant,
            "reseller": reseller,
            "sponsor": sponsor,
            "name_servers": name_servers
        }
        return rdap_data
    except requests.RequestException as e:
        return {"error": f"RDAP request failed: {e}"}
    except (KeyError, IndexError, TypeError) as e:
        return {"error": f"Error parsing RDAP response: {e}"}

# Function to get SSL certificates from crt.sh
def get_ssl_certs(domain):
    """
    Retrieve active SSL certificate information for a given domain from crt.sh.
    
    Args:
        domain (str): The domain name to query (e.g., "example.com").
    
    Returns:
        list: A list of dictionaries containing details of active certificates, or an error message if the request fails.
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        certs = response.json()
        if not certs:
            return []  # No certificates found

        # Get current UTC time for comparison
        current_time = datetime.now(timezone.utc)
        parsed_certs = []

        for cert in certs:
            try:
                # Extract and normalize date strings
                not_before_str = cert.get("not_before", "")
                not_after_str = cert.get("not_after", "")
                # Replace space with 'T' to handle varying formats (e.g., "YYYY-MM-DD HH:MM:SS" to "YYYY-MM-DDTHH:MM:SS")
                not_before_str = not_before_str.replace(" ", "T")
                not_after_str = not_after_str.replace(" ", "T")

                # Parse dates into datetime objects and make them timezone-aware
                not_before = datetime.fromisoformat(not_before_str).replace(tzinfo=timezone.utc)
                not_after = datetime.fromisoformat(not_after_str).replace(tzinfo=timezone.utc)

                # Check if the certificate is active
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
                continue  # Skip certificates with invalid dates

        return parsed_certs

    except requests.RequestException as e:
        print(f"Error querying crt.sh for {domain}: {e}")
        return {"error": str(e)}

# Helper function to extract issuing organization from issuer_name
def get_issuing_org(issuer_name):
    if not issuer_name:
        return None
    parts = issuer_name.split(', ')
    for part in parts:
        if part.startswith('O='):
            return part[2:]
    return None

# Helper function to parse dates
def parse_date(date_str):
    if date_str:
        try:
            # Replace space with 'T' for consistency and append '+00:00' if no timezone
            date_str = date_str.replace(" ", "T")
            if 'Z' in date_str:
                date_str = date_str.replace('Z', '+00:00')
            elif '+' not in date_str and 'T' in date_str:
                date_str += '+00:00'
            return datetime.fromisoformat(date_str)
        except ValueError:
            return None
    return None

# Function to compare the two domains
def compare_domains(data, domain1, domain2):
    similarities = []
    # Create a low_value_similarities list to store low-value similarities such as none or Unknown
    low_value_similarities = []
    differences = []

    domain1_data = data.get(domain1, {})
    domain2_data = data.get(domain2, {})

    # Compare IPs
    ips1 = [ip['address'] for ip in domain1_data.get('ips', [])]
    ips2 = [ip['address'] for ip in domain2_data.get('ips', [])]
    shared_ips = set(ips1) & set(ips2)
    if shared_ips:
        # Check if the value is none or Unknown
        if 'none' in shared_ips or 'Unknown' in shared_ips:
            low_value_similarities.append(f"Low-value similarity: IP: {', '.join(shared_ips)}")
        else:
            similarities.append(f"P0201 - IP: {', '.join(shared_ips)}")
    else:
        differences.append(f"No shared IPs. {domain1} has {', '.join(ips1) if ips1 else 'none'}, {domain2} has {', '.join(ips2) if ips2 else 'none'}")

    # Compare ASNs
    asns1 = set(ip['asn_number'] for ip in domain1_data.get('ips', []) if 'asn_number' in ip)
    asns2 = set(ip['asn_number'] for ip in domain2_data.get('ips', []) if 'asn_number' in ip)
    shared_asns = asns1 & asns2
    if shared_asns:
        # Check if the value is none or Unknown
        if 'none' in shared_asns or 'Unknown' in shared_asns:
            low_value_similarities.append(f"Low-value similarity: AS: {', '.join(shared_asns)}")
        else:
            similarities.append(f"P0203 - AS: {', '.join(shared_asns)}")
    else:
        differences.append(f"No shared ASNs. {domain1} has ASNs {', '.join(asns1) if asns1 else 'none'}, {domain2} has ASNs {', '.join(asns2) if asns2 else 'none'}")

    # Compare RDAP status
    rdap_status1 = domain1_data.get('rdap', {}).get('status', [])
    rdap_status2 = domain2_data.get('rdap', {}).get('status', [])
    if rdap_status1 == rdap_status2 and rdap_status1:
        # Check if the value is none or Unknown
        low_value_similarities.append(f"Low-value similarity: RDAP Status: {', '.join(rdap_status1)}")
    else:
        differences.append(f"RDAP statuses differ: {domain1}: {', '.join(rdap_status1) if rdap_status1 else 'none'}, {domain2}: {', '.join(rdap_status2) if rdap_status2 else 'none'}")

    # Compare RDAP registrar
    registrar1 = domain1_data.get('rdap', {}).get('registrar')
    registrar2 = domain2_data.get('rdap', {}).get('registrar')
    if registrar1 == registrar2 and registrar1:
        # Check if the value is none or Unknown
        if 'none' in registrar1 or 'Unknown' in registrar1:
            low_value_similarities.append(f"Low-value similarity: Registrar: {registrar1}")
        else:
            similarities.append(f"P0101.001 - Registration: Registrar: {registrar1}")
    else:
        differences.append(f"Registrars differ: {domain1}: {registrar1 if registrar1 else 'none'}, {domain2}: {registrar2 if registrar2 else 'none'}")

    # Update: 20250405 - Compare registrant, reseller, sponsor, and proxy information
    # Compare RDAP registrant
    registrant1 = domain1_data.get('rdap', {}).get('registrant')
    registrant2 = domain2_data.get('rdap', {}).get('registrant')
    if registrant1 == registrant2 and registrant1:
        # Check if the value is none or Unknown
        if 'none' in registrant1 or 'Unknown' in registrant1:
            low_value_similarities.append(f"Low-value similarity: Registrant: {registrant1}")
        else:
            similarities.append(f"P0101.003 - Registration: Registrant: {registrant1}")
    else:
        differences.append(f"Registrants differ: {domain1}: {registrant1 if registrant1 else 'none'}, {domain2}: {registrant2 if registrant2 else 'none'}")

    # Compare RDAP reseller
    reseller1 = domain1_data.get('rdap', {}).get('reseller')
    reseller2 = domain2_data.get('rdap', {}).get('reseller')
    if reseller1 == reseller2 and reseller1:
        # Check if the value is none or Unknown
        if 'none' in reseller1 or 'Unknown' in reseller1:
            low_value_similarities.append(f"Low-value similarity: reseller: {reseller1}")
        else:
            similarities.append(f"Both domains have the same reseller: {reseller1}")
    else:
        differences.append(f"Resellers differ: {domain1}: {reseller1 if reseller1 else 'none'}, {domain2}: {reseller2 if reseller2 else 'none'}")

    # Compare RDAP sponsor
    sponsor1 = domain1_data.get('rdap', {}).get('sponsor')
    sponsor2 = domain2_data.get('rdap', {}).get('sponsor')
    if sponsor1 == sponsor2 and sponsor1:
        # Check if the value is none or Unknown
        if 'none' in sponsor1 or 'Unknown' in sponsor1:
            low_value_similarities.append(f"Low-value similarity: sponsor: {sponsor1}")
        else:
            similarities.append(f"Both domains have the same sponsor: {sponsor1}")
    else:
        differences.append(f"Sponsors differ: {domain1}: {sponsor1 if sponsor1 else 'none'}, {domain2}: {sponsor2 if sponsor2 else 'none'}")

    # Compare RDAP proxy information
    proxy1 = domain1_data.get('rdap', {}).get('proxy')
    proxy2 = domain2_data.get('rdap', {}).get('proxy')
    if proxy1 == proxy2 and proxy1:
        # Check if the value is none or Unknown
        if 'none' in proxy1 or 'Unknown' in proxy1:
            low_value_similarities.append(f"Low-value similarity: proxy information: {proxy1}")
        else:
            similarities.append(f"Both domains have the same proxy information: {proxy1}")
    else:
        differences.append(f"Proxy information differs: {domain1}: {proxy1 if proxy1 else 'none'}, {domain2}: {proxy2 if proxy2 else 'none'}")

    # Compare RDAP name servers
    ns1 = set(domain1_data.get('rdap', {}).get('name_servers', []))
    ns2 = set(domain2_data.get('rdap', {}).get('name_servers', []))
    shared_ns = ns1 & ns2
    if shared_ns:
        # Check if the value is none or Unknown
        if 'none' in shared_ns or 'Unknown' in shared_ns:
            low_value_similarities.append(f"Low-value similarity: Registration: Name Server: {', '.join(shared_ns)}")
        else:
            similarities.append(f"P0101.010 - Registration: Name Server: {', '.join(shared_ns)}")
    if ns1 - shared_ns or ns2 - shared_ns:
        differences.append(f"Unique name servers: {domain1}: {', '.join(ns1 - shared_ns) if ns1 - shared_ns else 'none'}, {domain2}: {', '.join(ns2 - shared_ns) if ns2 - shared_ns else 'none'}")

    # Compare RDAP name server domains
    ns_domain1 = set(tuple(ns.split('.')[-2:]) for ns in ns1 if ns and 'Unknown' not in ns)
    ns_domain2 = set(tuple(ns.split('.')[-2:]) for ns in ns2 if ns and 'Unknown' not in ns)
    shared_ns_domain = ns_domain1 & ns_domain2
    if shared_ns_domain:
        # Check if the value is none or Unknown
        if 'none' in shared_ns_domain or 'Unknown' in shared_ns_domain:
            low_value_similarities.append(f"Low-value similarity: Name Server Domain: {', '.join('.'.join(ns) for ns in shared_ns_domain)}")
        else:
            similarities.append(f"P0101.011 - Registration: Name Server Domain: {', '.join('.'.join(ns) for ns in shared_ns_domain)}")

    # Compare RDAP creation dates
    creation_date1 = parse_date(domain1_data.get('rdap', {}).get('creation_date'))
    creation_date2 = parse_date(domain2_data.get('rdap', {}).get('creation_date'))
    if creation_date1 and creation_date2:
        diff = abs(creation_date1 - creation_date2)
        if diff <= timedelta(days=7):
            similarities.append(f"P0101.002 - Registration: Registration date (7 days): {creation_date1} and {creation_date2}")
        else:
            differences.append(f"Creation dates differ by more than 7 days: {creation_date1} vs {creation_date2}")
    else:
        differences.append(f"Creation dates not comparable: {creation_date1} vs {creation_date2}")

    # Compare RDAP expiration dates
    expiration_date1 = parse_date(domain1_data.get('rdap', {}).get('expiration_date'))
    expiration_date2 = parse_date(domain2_data.get('rdap', {}).get('expiration_date'))
    if expiration_date1 and expiration_date2:
        diff = abs(expiration_date1 - expiration_date2)
        if diff <= timedelta(days=7):
            similarities.append(f"Expiration dates are within 7 days: {expiration_date1} and {expiration_date2}")
        else:
            differences.append(f"Expiration dates differ by more than 7 days: {expiration_date1} vs {expiration_date2}")
    else:
        differences.append(f"Expiration dates not comparable: {expiration_date1} vs {expiration_date2}")

    # Compare SSL certificates (first cert only)
    cert1 = domain1_data.get('ssl_certs', [None])[0]
    cert2 = domain2_data.get('ssl_certs', [None])[0]
    if cert1 and cert2:
        # Compare issuing organization
        org1 = get_issuing_org(cert1.get('issuer_name'))
        org2 = get_issuing_org(cert2.get('issuer_name'))
        if org1 == org2 and org1:
            similarities.append(f"P0301 - Issuer Organization: {org1}")
        else:
            differences.append(f"SSL cert issuing organizations differ: {org1 if org1 else 'none'} vs {org2 if org2 else 'none'}")

        # Compare not_before dates
        not_before1 = parse_date(cert1.get('not_before'))
        not_before2 = parse_date(cert2.get('not_before'))
        if not_before1 and not_before2:
            diff = abs(not_before1 - not_before2)
            if diff <= timedelta(days=7):
                similarities.append(f"SSL cert not_before dates are within 7 days: {not_before1} and {not_before2}")
            else:
                differences.append(f"SSL cert not_before dates differ by more than 7 days: {not_before1} vs {not_before2}")
        else:
            differences.append(f"SSL cert not_before dates not comparable: {not_before1} vs {not_before2}")
    elif cert1:
        differences.append(f"Only {domain1} has SSL certificates")
    elif cert2:
        differences.append(f"Only {domain2} has SSL certificates")
    else:
        similarities.append("Neither domain has SSL certificates")
    
    # Update: 20250405 - Add a feature to save the comparison analysis to a unique analysis.txt file.
    # Format: "analysis-{timestamp}.txt"
    analysis_filename = f"output/analysis-{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    with open(analysis_filename, "w") as f:
        f.write(f"Comparison analysis for {domain1} and {domain2}\n")
        f.write("=" * 50 + "\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Domain 1: {domain1}\n")
        f.write(f"Domain 2: {domain2}\n\n")
        f.write("Similarities and Differences:\n")
        f.write("=" * 50 + "\n")
        f.write("Similarities:\n")
        for sim in similarities:
            f.write(f"- {sim}\n")
        f.write("\nLow-value similarities:\n")
        for low_sim in low_value_similarities:
            f.write(f"- {low_sim}\n")
        f.write("\nDifferences:\n")
        for diff in differences:
            f.write(f"- {diff}\n")
    print(f"Comparison analysis saved to {analysis_filename}")

    # Read the analysis from analysis_filename
    with open(analysis_filename, "r") as f:
        analysis_content = f.read()
    print("\n" + "=" * 50 + "\n")
    print(analysis_content)

# Create a def to re-fang the domain by stripping any [ or ] characters
# For example: example[.]com -> example.com
def re_fang_domain(domain):
    return domain.replace("[", "").replace("]", "")

# Main script
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python ioc_comparer.py domain1 domain2")
        sys.exit(1)
    
    domain1 = re_fang_domain(sys.argv[1])
    domain2 = re_fang_domain(sys.argv[2])
    
    # Fetch RDAP bootstrap data once
    tld_to_rdap = get_rdap_bootstrap()
    
    data = {}
    for domain in [domain1, domain2]:
        # Get IPs and ASNs
        ips = get_ips(domain)
        ip_list = []
        for ip in ips:
            asn_number, asn_name = get_asn(ip)
            ip_dict = {"address": ip}
            if asn_number:
                ip_dict["asn_number"] = asn_number
                ip_dict["asn_name"] = asn_name
            ip_list.append(ip_dict)
        
        # Get RDAP data
        rdap_data = get_rdap_data(domain, tld_to_rdap)
        
        # Get all SSL certificates (no active filter)
        ssl_certs = get_ssl_certs(domain)
        
        # Structure the data
        data[domain] = {
            "ips": ip_list,
            "rdap": rdap_data,
            "ssl_certs": ssl_certs
        }
        
        # Sleep to avoid rate limiting
        time.sleep(1)
    
    # Save to JSON file
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_filename = f"output/domains-{timestamp}.json"
    with open(output_filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"Data saved to {output_filename}")
    
    # Compare the domains
    compare_domains(data, domain1, domain2)
