import os
import json
from datetime import datetime
from utils import get_issuing_org, parse_date

def compare_two_iocs(ioc1, ioc2, data1, data2):
    """Compare two IOCs and return a formatted comparison string."""
    similarities = []
    low_value_similarities = []
    differences = []

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

    # Compare ASNs
    asns1 = set(ip['asn_number'] for ip in data1.get('ips', []) if 'asn_number' in ip)
    asns2 = set(ip['asn_number'] for ip in data2.get('ips', []) if 'asn_number' in ip)
    shared_asns = asns1 & asns2
    if shared_asns:
        if 'none' in shared_asns or 'Unknown' in shared_asns:
            low_value_similarities.append(f"Low-value similarity: AS: {', '.join(shared_asns)}")
        else:
            similarities.append(f"P0203 - AS: {', '.join(shared_asns)}")
    else:
        differences.append(f"No shared ASNs. {ioc1} has ASNs {', '.join(asns1) if asns1 else 'none'}, {ioc2} has ASNs {', '.join(asns2) if asns2 else 'none'}")

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

    # Format comparison output
    output = f"Comparison between {ioc1} and {ioc2}:\n"
    output += "Similarities:\n" + "\n".join(f"- {sim}" for sim in similarities) + "\n" if similarities else "Similarities:\n- None\n"
    output += "\nLow-value similarities:\n" + "\n".join(f"- {low_sim}" for low_sim in low_value_similarities) + "\n" if low_value_similarities else "\nLow-value similarities:\n- None\n"
    output += "\nDifferences:\n" + "\n".join(f"- {diff}" for diff in differences) + "\n" if differences else "\nDifferences:\n- None\n"
    output += "\n"
    return output

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