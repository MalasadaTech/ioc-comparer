import os
import json
from datetime import datetime, timedelta
from utils import get_issuing_org, parse_date

def normalize_nameserver(ns):
    """Normalize a nameserver by converting to lowercase and removing trailing dots."""
    return ns.lower().rstrip('.')

def compare_two_iocs(ioc1, ioc2, data1, data2):
    """Compare two IOCs and return a formatted comparison string."""
    similarities = []
    low_value_similarities = []
    differences = []

    # Compare RDAP registrar
    registrar1 = data1.get('rdap', {}).get('registrar')
    registrar2 = data2.get('rdap', {}).get('registrar')
    if registrar1 == registrar2 and registrar1:
        if 'none' in registrar1 or 'Unknown' in registrar1:
            low_value_similarities.append(f"Low-value similarity: Registrar: {registrar1}")
        else:
            similarities.append(f"P0101.001 - Registration: Registrar: {registrar1}")
    else:
        differences.append(f"Registrars differ: {ioc1}: {registrar1 if registrar1 else 'none'}, {ioc2}: {registrar2 if registrar2 else 'none'}")

    # Compare creation dates
    creation_date1 = parse_date(data1.get('rdap', {}).get('creation_date'))
    creation_date2 = parse_date(data2.get('rdap', {}).get('creation_date'))
    creation_date_comparison = compare_creation_dates(creation_date1, creation_date2)
    if "not comparable" in creation_date_comparison or "differ by more than 7 days" in creation_date_comparison:
        differences.append(creation_date_comparison)
    else:
        similarities.append(creation_date_comparison)
    
    # Compare RDAP name servers - normalize them first by removing trailing dots and converting to lowercase
    ns1 = sorted([normalize_nameserver(ns) for ns in data1.get('rdap', {}).get('name_servers', [])])
    ns2 = sorted([normalize_nameserver(ns) for ns in data2.get('rdap', {}).get('name_servers', [])])
    
    # Use sets for comparison after normalization
    ns1_set = set(ns1)
    ns2_set = set(ns2)
    shared_ns = ns1_set & ns2_set
    
    if shared_ns:
        if 'none' in shared_ns or 'Unknown' in shared_ns:
            low_value_similarities.append(f"Low-value similarity: Name Server: {', '.join(sorted(shared_ns))}")
        else:
            similarities.append(f"P0101.010 - Registration: Name Server: {', '.join(sorted(shared_ns))}")
    
    if ns1_set - shared_ns or ns2_set - shared_ns:
        differences.append(f"Unique name servers: {ioc1}: {', '.join(sorted(ns1_set - shared_ns)) if ns1_set - shared_ns else 'none'}, {ioc2}: {', '.join(sorted(ns2_set - shared_ns)) if ns2_set - shared_ns else 'none'}")

    # Compare name server domains
    ns_domain_comparison = compare_name_server_domains(ns1, ns2)
    if ns_domain_comparison:
        if "Low-value similarity" in ns_domain_comparison:
            low_value_similarities.append(ns_domain_comparison)
        else:
            similarities.append(ns_domain_comparison)

    # Compare IPs
    ips1 = [ip['address'] for ip in data1.get('ips', [])]
    ips2 = [ip['address'] for ip in data2.get('ips', [])]
    shared_ips = set(ips1) & set(ips2)
    if shared_ips:
        if 'none' in shared_ips or 'Unknown' in shared_ips:
            low_value_similarities.append(f"Low-value similarity: IP: {', '.join(shared_ips)}")
        else:
            similarities.append(f"P0201 - IP: {', '.join(shared_ips)}")
    else:
        differences.append(f"No shared IPs. {ioc1} has {', '.join(ips1) if ips1 else 'none'}, {ioc2} has {', '.join(ips2) if ips2 else 'none'}")

    # Compare reverse DNS hostnames
    hostnames1 = {ip['address']: ip['hostname'] for ip in data1.get('ips', []) if ip.get('hostname')}
    hostnames2 = {ip['address']: ip['hostname'] for ip in data2.get('ips', []) if ip.get('hostname')}
    
    # Get unique hostnames from each dataset
    unique_hostnames1 = set(hostnames1.values())
    unique_hostnames2 = set(hostnames2.values())
    shared_hostnames = unique_hostnames1 & unique_hostnames2
    
    if shared_hostnames:
        if any(hostname is None for hostname in shared_hostnames):
            shared_hostnames_filtered = {h for h in shared_hostnames if h is not None}
            if shared_hostnames_filtered:
                similarities.append(f"P0206 - PTR Records: {', '.join(shared_hostnames_filtered)}")
        else:
            similarities.append(f"P0206 - PTR Records: {', '.join(shared_hostnames)}")
    
    # Create a mapping of IP to hostname for both domains
    ip_hostname_map = {}
    for ip, hostname in hostnames1.items():
        if hostname:
            ip_hostname_map[ip] = hostname
    for ip, hostname in hostnames2.items():
        if hostname:
            ip_hostname_map[ip] = hostname
    
    # Add information about each IP's hostname to the differences
    if ip_hostname_map:
        hostname_info = []
        for ip in set(ips1) | set(ips2):
            hostname = ip_hostname_map.get(ip)
            if hostname:
                hostname_info.append(f"{ip} resolves to {hostname}")
        if hostname_info:
            differences.append(f"Reverse DNS info: {'; '.join(hostname_info)}")

    # Compare AS names
    asn_names1 = set(ip['asn_name'] for ip in data1.get('ips', []) if 'asn_name' in ip)
    asn_names2 = set(ip['asn_name'] for ip in data2.get('ips', []) if 'asn_name' in ip)
    shared_asn_names = asn_names1 & asn_names2
    if shared_asn_names:
        if 'none' in shared_asn_names or 'Unknown' in shared_asn_names:
            low_value_similarities.append(f"Low-value similarity: ASN Name: {', '.join(shared_asn_names)}")
        else:
            similarities.append(f"P0203 - AS Name: {', '.join(shared_asn_names)}")
    else:
        differences.append(f"No shared ASN Names. {ioc1} has ASN Names {', '.join(asn_names1) if asn_names1 else 'none'}, {ioc2} has ASN Names {', '.join(asn_names2) if asn_names2 else 'none'}")

    # Compare ASNs
    asns1 = set(ip['asn_number'] for ip in data1.get('ips', []) if 'asn_number' in ip)
    asns2 = set(ip['asn_number'] for ip in data2.get('ips', []) if 'asn_number' in ip)
    shared_asns = asns1 & asns2
    if shared_asns:
        if 'none' in shared_asns or 'Unknown' in shared_asns:
            low_value_similarities.append(f"Low-value similarity: AS: {', '.join(shared_asns)}")
        else:
            similarities.append(f"P0203 - AS Number: {', '.join(shared_asns)}")
    else:
        differences.append(f"No shared ASNs. {ioc1} has ASNs {', '.join(asns1) if asns1 else 'none'}, {ioc2} has ASNs {', '.join(asns2) if asns2 else 'none'}")

    # Compare ASN countries
    asn_countries1 = set(ip['asn_country'] for ip in data1.get('ips', []) if 'asn_country' in ip)
    asn_countries2 = set(ip['asn_country'] for ip in data2.get('ips', []) if 'asn_country' in ip)
    shared_asn_countries = asn_countries1 & asn_countries2
    if shared_asn_countries:
        if 'none' in shared_asn_countries or 'Unknown' in shared_asn_countries:
            low_value_similarities.append(f"Low-value similarity: ASN Country: {', '.join(shared_asn_countries)}")
        else:
            similarities.append(f"P0203 - AS Country: {', '.join(shared_asn_countries)}")
    else:
        differences.append(f"No shared ASN Countries. {ioc1} has ASN Countries {', '.join(asn_countries1) if asn_countries1 else 'none'}, {ioc2} has ASN Countries {', '.join(asn_countries2) if asn_countries2 else 'none'}")

    # Format comparison output
    output = f"Comparison between {ioc1} and {ioc2}:\n"
    output += "Similarities:\n" + "\n".join(f"- {sim}" for sim in similarities) + "\n" if similarities else "Similarities:\n- None\n"
    output += "\nLow-value similarities:\n" + "\n".join(f"- {low_sim}" for low_sim in low_value_similarities) + "\n" if low_value_similarities else "\nLow-value similarities:\n- None\n"
    output += "\nDifferences:\n" + "\n".join(f"- {diff}" for diff in differences) + "\n" if differences else "\nDifferences:\n- None\n"
    output += "\n"
    return output

def compare_name_server_domains(ns1, ns2):
    # ns1 and ns2 are already sorted and normalized lists
    ns_domain1 = set(tuple(ns.split('.')[-2:]) for ns in ns1 if ns and 'Unknown' not in ns)
    ns_domain2 = set(tuple(ns.split('.')[-2:]) for ns in ns2 if ns and 'Unknown' not in ns)
    shared_ns_domain = ns_domain1 & ns_domain2
    if shared_ns_domain:
        if any('none' in '.'.join(ns).lower() for ns in shared_ns_domain):
            return f"Low-value similarity: Name Server Domain: {', '.join('.'.join(ns) for ns in sorted(shared_ns_domain))}"
        else:
            return f"P0101.011 - Registration: Name Server Domain: {', '.join('.'.join(ns) for ns in sorted(shared_ns_domain))}"
    return None

def compare_creation_dates(creation_date1, creation_date2):
    if creation_date1 and creation_date2:
        diff = abs(creation_date1 - creation_date2)
        if diff <= timedelta(days=7):
            return f"P0101.002 - Registration: Registration date (7 days): {creation_date1} and {creation_date2}"
        else:
            return f"Creation dates differ by more than 7 days: {creation_date1} vs {creation_date2}"
    return f"Creation dates not comparable: {creation_date1} vs {creation_date2}"

def compare_iocs(iocs):
    """Compare multiple IOCs pairwise and save results to a text file."""
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    analysis_filename = os.path.join(output_dir, f"Analysis-{'-'.join(iocs)}-{timestamp}.txt")
    with open(analysis_filename, "w") as f:
        f.write(f"Comparison analysis for {', '.join(iocs)}\n")
        f.write("=" * 50 + "\n")
        f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")
        for i in range(len(iocs)):
            for j in range(i + 1, len(iocs)):
                ioc1, ioc2 = iocs[i], iocs[j]
                file1 = os.path.join(output_dir, f"{ioc1}.json")
                file2 = os.path.join(output_dir, f"{ioc2}.json")
                if not (os.path.exists(file1) and os.path.exists(file2)):
                    continue
                with open(file1, "r") as f1, open(file2, "r") as f2:
                    data1, data2 = json.load(f1), json.load(f2)
                comparison = compare_two_iocs(ioc1, ioc2, data1, data2)
                f.write(comparison)

    print(f"Comparison analysis saved to {analysis_filename}")
    with open(analysis_filename, "r") as f:
        print(f.read())