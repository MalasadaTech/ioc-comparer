import os
import json
from datetime import datetime, timedelta
from utils import get_issuing_org, parse_date

def compare_ssl_certificates(cert1, cert2):
    """Compare two SSL certificates and return similarities or differences."""
    similarities = []
    differences = []

    if not cert1 and not cert2:
        similarities.append("Neither domain has SSL certificates")
    elif not cert1:
        differences.append("Only the second domain has SSL certificates")
    elif not cert2:
        differences.append("Only the first domain has SSL certificates")
    else:
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

    return similarities, differences

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
    
    # Compare RDAP name servers
    ns1 = set(data1.get('rdap', {}).get('name_servers', []))
    ns2 = set(data2.get('rdap', {}).get('name_servers', []))
    shared_ns = ns1 & ns2
    if shared_ns:
        if 'none' in shared_ns or 'Unknown' in shared_ns:
            low_value_similarities.append(f"Low-value similarity: Name Server: {', '.join(shared_ns)}")
        else:
            similarities.append(f"P0101.010 - Registration: Name Server: {', '.join(shared_ns)}")
    if ns1 - shared_ns or ns2 - shared_ns:
        differences.append(f"Unique name servers: {ioc1}: {', '.join(ns1 - shared_ns) if ns1 - shared_ns else 'none'}, {ioc2}: {', '.join(ns2 - shared_ns) if ns2 - shared_ns else 'none'}")

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

    # Ensure the SSL certificate list is not empty before accessing the first element
    cert1 = data1.get('ssl_certs', [None])[0] if data1.get('ssl_certs') else None
    cert2 = data2.get('ssl_certs', [None])[0] if data2.get('ssl_certs') else None

    # Compare SSL certificates
    ssl_similarities, ssl_differences = compare_ssl_certificates(cert1, cert2)
    similarities.extend(ssl_similarities)
    differences.extend(ssl_differences)

    # Format comparison output
    output = f"Comparison between {ioc1} and {ioc2}:\n"
    output += "Similarities:\n" + "\n".join(f"- {sim}" for sim in similarities) + "\n" if similarities else "Similarities:\n- None\n"
    output += "\nLow-value similarities:\n" + "\n".join(f"- {low_sim}" for low_sim in low_value_similarities) + "\n" if low_value_similarities else "\nLow-value similarities:\n- None\n"
    output += "\nDifferences:\n" + "\n".join(f"- {diff}" for diff in differences) + "\n" if differences else "\nDifferences:\n- None\n"
    output += "\n"
    return output

def compare_name_server_domains(ns1, ns2):
    ns_domain1 = set(tuple(ns.split('.')[-2:]) for ns in ns1 if ns and 'Unknown' not in ns)
    ns_domain2 = set(tuple(ns.split('.')[-2:]) for ns in ns2 if ns and 'Unknown' not in ns)
    shared_ns_domain = ns_domain1 & ns_domain2
    if shared_ns_domain:
        if 'none' in shared_ns_domain or 'Unknown' in shared_ns_domain:
            return f"Low-value similarity: Name Server Domain: {', '.join('.'.join(ns) for ns in shared_ns_domain)}"
        else:
            return f"P0101.011 - Registration: Name Server Domain: {', '.join('.'.join(ns) for ns in shared_ns_domain)}"
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