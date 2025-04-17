import os
import json
from datetime import datetime, timedelta
from utils import get_issuing_org, parse_date, calculate_nshash
 
def normalize_nameserver(ns):
    """Normalize a nameserver by converting to lowercase and removing trailing dots."""
    return ns.lower().rstrip('.')

def normalize_registrar(registrar):
    """Extract registrar ID from parentheses if it exists."""
    if not registrar:
        return None
    
    # Extract ID from parentheses if it exists
    registrar_id = None
    if '(' in registrar and ')' in registrar:
        parts = registrar.split('(')
        if len(parts) > 1:
            id_part = parts[-1].split(')')[0].strip()
            if id_part.isdigit():
                registrar_id = id_part
    
    # Return the full registrar name and the ID
    return registrar, registrar_id

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
        
        # The get_issuing_org function now properly handles quotes
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

def compare_otx_data(otx1, otx2, ioc1, ioc2):
    """Compare OTX data for two IOCs and return similarities and differences."""
    similarities = []
    enriched_similarities = []  # New category for OTX-specific similarities
    low_value_similarities = []
    differences = []
    
    # If neither has OTX data, return early
    if not otx1 and not otx2:
        differences.append("No OTX data available for either IOC")
        return similarities, enriched_similarities, low_value_similarities, differences
    
    # If only one has OTX data
    if not otx1:
        differences.append(f"Only {ioc2} has OTX data")
        return similarities, enriched_similarities, low_value_similarities, differences
    if not otx2:
        differences.append(f"Only {ioc1} has OTX data")
        return similarities, enriched_similarities, low_value_similarities, differences
    
    # Compare pulse count (general popularity in threat reports)
    pulse_count1 = otx1.get('pulse_count', 0)
    pulse_count2 = otx2.get('pulse_count', 0)
    
    if pulse_count1 > 0 and pulse_count2 > 0:
        if abs(pulse_count1 - pulse_count2) <= max(5, min(pulse_count1, pulse_count2) * 0.2):  # Within 20% or 5 pulses
            enriched_similarities.append(f"Similar number of OTX threat reports: {pulse_count1} vs {pulse_count2}")
        else:
            differences.append(f"Significant difference in OTX threat report count: {ioc1}: {pulse_count1}, {ioc2}: {pulse_count2}")
    
    # Compare shared pulse names (if they're in the same threat reports)
    recent_pulses1 = set(otx1.get('recent_pulses', []))
    recent_pulses2 = set(otx2.get('recent_pulses', []))
    shared_pulses = recent_pulses1 & recent_pulses2
    
    if shared_pulses:
        enriched_similarities.append(f"OTX Shared Threat Reports: {', '.join(shared_pulses)}")
    
    # Compare most recent pulse dates
    most_recent1 = parse_date(otx1.get('most_recent_pulse'))
    most_recent2 = parse_date(otx2.get('most_recent_pulse'))
    
    if most_recent1 and most_recent2:
        diff = abs(most_recent1 - most_recent2)
        if diff <= timedelta(days=7):
            enriched_similarities.append(f"OTX most recent threat reports within 7 days: {most_recent1} and {most_recent2}")
        else:
            differences.append(f"OTX most recent threat reports differ by more than 7 days: {most_recent1} vs {most_recent2}")
    
    # Compare reputation data if available
    rep1 = otx1.get('reputation', {})
    rep2 = otx2.get('reputation', {})
    
    if rep1 and rep2:
        # Compare reputation scores
        score1 = rep1.get('reputation')
        score2 = rep2.get('reputation')
        
        if score1 is not None and score2 is not None:
            # Check if both have similar reputations
            if (score1 > 0 and score2 > 0) or (score1 < 0 and score2 < 0):
                enriched_similarities.append(f"OTX Similar Reputation: Both IOCs have similar OTX reputation scores ({score1}, {score2})")
            else:
                differences.append(f"OTX reputation scores differ: {ioc1}: {score1}, {ioc2}: {score2}")
        
        # Compare threat scores
        threat1 = rep1.get('threat_score')
        threat2 = rep2.get('threat_score')
        
        if threat1 is not None and threat2 is not None:
            # Check if both have similar threat scores (within 20%)
            if abs(threat1 - threat2) <= max(1, min(threat1, threat2) * 0.2):
                enriched_similarities.append(f"Similar OTX threat scores: {threat1} vs {threat2}")
            else:
                differences.append(f"OTX threat scores differ: {ioc1}: {threat1}, {ioc2}: {threat2}")
    
    return similarities, enriched_similarities, low_value_similarities, differences

def compare_vt_data(vt1, vt2, ioc1, ioc2):
    """Compare VirusTotal data for two IOCs and return similarities and differences."""
    similarities = []
    enriched_similarities = []
    low_value_similarities = []
    differences = []
    
    # If neither has VirusTotal data, return early
    if not vt1 and not vt2:
        differences.append("No VirusTotal data available for either IOC")
        return similarities, enriched_similarities, low_value_similarities, differences
    
    # If only one has VirusTotal data
    if not vt1:
        differences.append(f"Only {ioc2} has VirusTotal data")
        return similarities, enriched_similarities, low_value_similarities, differences
    if not vt2:
        differences.append(f"Only {ioc1} has VirusTotal data")
        return similarities, enriched_similarities, low_value_similarities, differences
    
    # Compare vendor assessment stats
    stats1 = vt1.get('vendor_stats', {})
    stats2 = vt2.get('vendor_stats', {})
    
    if stats1 and stats2:
        # Calculate malicious percentages
        total1 = sum(stats1.values()) or 1  # Avoid division by zero
        total2 = sum(stats2.values()) or 1
        
        malicious1 = stats1.get('malicious', 0)
        malicious2 = stats2.get('malicious', 0)
        
        suspicious1 = stats1.get('suspicious', 0)
        suspicious2 = stats2.get('suspicious', 0)
        
        bad_percent1 = (malicious1 + suspicious1) / total1 * 100
        bad_percent2 = (malicious2 + suspicious2) / total2 * 100
        
        # Compare malicious percentages
        # Consider similar if both are below 5% or both are within 10 percentage points
        if (bad_percent1 < 5 and bad_percent2 < 5) or abs(bad_percent1 - bad_percent2) <= 10:
            enriched_similarities.append(f"VT Similar Malicious Ratings: {bad_percent1:.1f}% vs {bad_percent2:.1f}%")
        else:
            differences.append(f"VT Malicious ratings differ significantly: {ioc1}: {bad_percent1:.1f}%, {ioc2}: {bad_percent2:.1f}%")
    
    # Compare community reputation scores
    score1 = vt1.get('community_score')
    score2 = vt2.get('community_score')
    
    if score1 is not None and score2 is not None:
        # If both scores are positive or both are negative, or close to each other
        if (score1 > 0 and score2 > 0) or (score1 < 0 and score2 < 0) or abs(score1 - score2) <= 20:
            enriched_similarities.append(f"VT Similar Community Scores: {score1} vs {score2}")
        else:
            differences.append(f"VT Community scores differ: {ioc1}: {score1}, {ioc2}: {score2}")
    
    # Compare tags
    tags1 = set(vt1.get('tags', []))
    tags2 = set(vt2.get('tags', []))
    shared_tags = tags1 & tags2
    
    if shared_tags:
        enriched_similarities.append(f"VT Shared Tags: {', '.join(shared_tags)}")
    
    # If there are different tags, note them
    unique_tags1 = tags1 - shared_tags
    unique_tags2 = tags2 - shared_tags
    
    if unique_tags1:
        differences.append(f"VT tags unique to {ioc1}: {', '.join(unique_tags1)}")
    if unique_tags2:
        differences.append(f"VT tags unique to {ioc2}: {', '.join(unique_tags2)}")
    
    # Compare submission dates if both are present
    first_date1 = vt1.get('first_submission_date')
    first_date2 = vt2.get('first_submission_date')
    
    if first_date1 and first_date2:
        # Convert timestamps to datetime objects
        first_dt1 = datetime.fromtimestamp(first_date1, tz=datetime.now().astimezone().tzinfo)
        first_dt2 = datetime.fromtimestamp(first_date2, tz=datetime.now().astimezone().tzinfo)
        
        # Check if they're within 7 days of each other
        if abs(first_dt1 - first_dt2) <= timedelta(days=7):
            enriched_similarities.append(f"VT first submission dates within 7 days: {first_dt1.date()} and {first_dt2.date()}")
        else:
            differences.append(f"VT first submission dates differ by more than 7 days: {first_dt1.date()} vs {first_dt2.date()}")
    
    return similarities, enriched_similarities, low_value_similarities, differences

def compare_threatfox_data(tf1, tf2, ioc1, ioc2):
    """Compare ThreatFox data for two IOCs and return similarities and differences."""
    similarities = []
    enriched_similarities = []
    low_value_similarities = []
    differences = []
    
    # If neither has ThreatFox data, return early
    if not tf1 and not tf2:
        differences.append("No ThreatFox data available for either IOC")
        return similarities, enriched_similarities, low_value_similarities, differences
    
    # If only one has ThreatFox data
    if not tf1:
        differences.append(f"Only {ioc2} has ThreatFox data")
        return similarities, enriched_similarities, low_value_similarities, differences
    if not tf2:
        differences.append(f"Only {ioc1} has ThreatFox data")
        return similarities, enriched_similarities, low_value_similarities, differences
    
    # Compare threat types
    threat_type1 = tf1.get('threat_type')
    threat_type2 = tf2.get('threat_type')
    
    if threat_type1 and threat_type2 and threat_type1 == threat_type2:
        enriched_similarities.append(f"Same ThreatFox threat type: {threat_type1}")
    elif threat_type1 and threat_type2:
        differences.append(f"ThreatFox threat types differ: {threat_type1} vs {threat_type2}")
    
    # Compare malware families
    malware1 = tf1.get('malware')
    malware2 = tf2.get('malware')
    
    if malware1 and malware2 and malware1 == malware2:
        enriched_similarities.append(f"Same ThreatFox malware family: {malware1}")
    elif malware1 and malware2:
        differences.append(f"ThreatFox malware families differ: {malware1} vs {malware2}")
    
    # Compare malware aliases (could indicate related malware even if main family differs)
    alias1 = tf1.get('malware_alias', '')
    alias2 = tf2.get('malware_alias', '')
    
    if alias1 and alias2:
        aliases1 = set(a.strip() for a in alias1.split(',') if a.strip())
        aliases2 = set(a.strip() for a in alias2.split(',') if a.strip())
        shared_aliases = aliases1 & aliases2
        
        if shared_aliases:
            enriched_similarities.append(f"Shared ThreatFox malware aliases: {', '.join(shared_aliases)}")
    
    # Compare first seen dates
    first_seen1 = parse_date(tf1.get('first_seen'))
    first_seen2 = parse_date(tf2.get('first_seen'))
    
    if first_seen1 and first_seen2:
        diff = abs(first_seen1 - first_seen2)
        if diff <= timedelta(days=7):
            enriched_similarities.append(f"ThreatFox first seen dates within 7 days: {first_seen1} and {first_seen2}")
        else:
            differences.append(f"ThreatFox first seen dates differ by more than 7 days: {first_seen1} vs {first_seen2}")
    
    # Compare confidence levels
    conf1 = tf1.get('confidence_level')
    conf2 = tf2.get('confidence_level')
    
    if conf1 is not None and conf2 is not None:
        # Check if confidence levels are similar (within 20% or 10 points)
        if abs(conf1 - conf2) <= max(10, min(conf1, conf2) * 0.2):
            low_value_similarities.append(f"Similar ThreatFox confidence levels: {conf1} vs {conf2}")
        else:
            differences.append(f"ThreatFox confidence levels differ: {conf1} vs {conf2}")
    
    # Compare tags
    tags1 = tf1.get('tags')
    tags2 = tf2.get('tags')
    
    if tags1 and tags2:
        tags1_set = set(tags1.split(',')) if isinstance(tags1, str) else set(tags1) if tags1 else set()
        tags2_set = set(tags2.split(',')) if isinstance(tags2, str) else set(tags2) if tags2 else set()
        shared_tags = tags1_set & tags2_set
        
        if shared_tags:
            enriched_similarities.append(f"Shared ThreatFox tags: {', '.join(shared_tags)}")
    
    return similarities, enriched_similarities, low_value_similarities, differences

def compare_two_iocs(ioc1, ioc2, data1, data2, substring=None):
    """Compare two IOCs and return a formatted comparison string."""
    similarities = []
    enriched_similarities = []  # New section for OTX enrichment similarities
    low_value_similarities = []
    differences = []

    # Compare RDAP registrar
    registrar1 = data1.get('rdap', {}).get('registrar')
    registrar2 = data2.get('rdap', {}).get('registrar')
    
    # Use normalized registrar comparison
    norm_reg1 = normalize_registrar(registrar1)
    norm_reg2 = normalize_registrar(registrar2)
    
    if norm_reg1 and norm_reg2:
        full_name1, id1 = norm_reg1
        full_name2, id2 = norm_reg2
        
        # First check if the registrar IDs match
        if id1 and id2 and id1 == id2:
            # Check if the names also match
            if full_name1 == full_name2:
                if 'none' in (full_name1.lower() if full_name1 else '') or 'Unknown' in (full_name1 if full_name1 else ''):
                    low_value_similarities.append(f"Low-value similarity: Registrar: {full_name1}")
                else:
                    similarities.append(f"P0101.001 - Registration: Registrar: {full_name1}")
            else:
                # IDs match but names differ - still a similarity, but note the difference
                similarities.append(f"P0101.001 - Registration: Registrar ID: {id1} ({full_name1} vs {full_name2})")
        else:
            differences.append(f"Registrars differ: {ioc1}: {registrar1 if registrar1 else 'none'}, {ioc2}: {registrar2 if registrar2 else 'none'}")
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
        # Calculate nshash for shared nameservers
        shared_ns_sorted = sorted(shared_ns)
        nshash = calculate_nshash(shared_ns_sorted)
        
        if 'none' in shared_ns or 'Unknown' in shared_ns:
            low_value_similarities.append(f"Low-value similarity: Name Server: {', '.join(shared_ns_sorted)} (nshash: {nshash})")
        else:
            similarities.append(f"P0101.010 - Registration: Name Server: {', '.join(shared_ns_sorted)} (nshash: {nshash})")
    
    if ns1_set - shared_ns or ns2_set - shared_ns:
        # Calculate nshash for each domain's unique nameservers
        unique_ns1 = sorted(ns1_set - shared_ns)
        unique_ns2 = sorted(ns2_set - shared_ns)
        
        nshash1 = calculate_nshash(unique_ns1) if unique_ns1 else None
        nshash2 = calculate_nshash(unique_ns2) if unique_ns2 else None
        
        unique_ns_str1 = f"{', '.join(unique_ns1)} (nshash: {nshash1})" if unique_ns1 else 'none'
        unique_ns_str2 = f"{', '.join(unique_ns2)} (nshash: {nshash2})" if unique_ns2 else 'none'
        
        differences.append(f"Unique name servers: {ioc1}: {unique_ns_str1}, {ioc2}: {unique_ns_str2}")

    # Compare name server domains
    ns_domain_comparison = compare_name_server_domains(ns1, ns2)
    if ns_domain_comparison:
        if "Low-value similarity" in ns_domain_comparison:
            low_value_similarities.append(ns_domain_comparison)
        else:
            similarities.append(ns_domain_comparison)

    # Substring similarity check
    if substring:
        if substring in ioc1 and substring in ioc2:
            similarities.append(f"P0102.002: Domain: Substring: {substring}")

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

    # Ensure the SSL certificate list is not empty before accessing the first element
    cert1 = data1.get('ssl_certs', [None])[0] if data1.get('ssl_certs') else None
    cert2 = data2.get('ssl_certs', [None])[0] if data2.get('ssl_certs') else None

    # Compare SSL certificates
    ssl_similarities, ssl_differences = compare_ssl_certificates(cert1, cert2)
    similarities.extend(ssl_similarities)
    differences.extend(ssl_differences)

    # Compare OTX data if available
    otx1 = data1.get('otx', {})
    otx2 = data2.get('otx', {})
    
    if otx1 or otx2:
        otx_similarities, otx_enriched_similarities, otx_low_value_similarities, otx_differences = compare_otx_data(otx1, otx2, ioc1, ioc2)
        similarities.extend(otx_similarities)
        enriched_similarities.extend(otx_enriched_similarities)
        low_value_similarities.extend(otx_low_value_similarities)
        differences.extend(otx_differences)
    
    # Compare VirusTotal data if available
    vt1 = data1.get('virustotal', {})
    vt2 = data2.get('virustotal', {})
    
    if vt1 or vt2:
        vt_similarities, vt_enriched_similarities, vt_low_value_similarities, vt_differences = compare_vt_data(vt1, vt2, ioc1, ioc2)
        similarities.extend(vt_similarities)
        enriched_similarities.extend(vt_enriched_similarities)
        low_value_similarities.extend(vt_low_value_similarities)
        differences.extend(vt_differences)

    # Compare ThreatFox data if available
    tf1 = data1.get('threatfox', {})
    tf2 = data2.get('threatfox', {})
    
    if tf1 or tf2:
        tf_similarities, tf_enriched_similarities, tf_low_value_similarities, tf_differences = compare_threatfox_data(tf1, tf2, ioc1, ioc2)
        similarities.extend(tf_similarities)
        enriched_similarities.extend(tf_enriched_similarities)
        low_value_similarities.extend(tf_low_value_similarities)
        differences.extend(tf_differences)

    # Format comparison output
    output = f"Comparison between {ioc1} and {ioc2}:\n"
    output += "Similarities:\n" + "\n".join(f"- {sim}" for sim in similarities) + "\n" if similarities else "Similarities:\n- None\n"
    
    # Add the new Enriched Similarities section between Similarities and Low-value similarities
    output += "\nEnriched Similarities:\n" + "\n".join(f"- {sim}" for sim in enriched_similarities) + "\n" if enriched_similarities else "\nEnriched Similarities:\n- None\n"
    
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
        # Create a list of domain strings from the tuples
        domain_strings = ['.'.join(ns) for ns in sorted(shared_ns_domain)]
        
        # Remove the nshash from the output as specified
        if any('none' in '.'.join(ns).lower() for ns in shared_ns_domain):
            return f"Low-value similarity: Name Server Domain: {', '.join(domain_strings)}"
        else:
            return f"P0101.011 - Registration: Name Server Domain: {', '.join(domain_strings)}"
    return None

def compare_creation_dates(creation_date1, creation_date2):
    if creation_date1 and creation_date2:
        diff = abs(creation_date1 - creation_date2)
        if diff <= timedelta(days=7):
            return f"P0101.002 - Registration: Registration date (7 days): {creation_date1} and {creation_date2}"
        else:
            return f"Creation dates differ by more than 7 days: {creation_date1} vs {creation_date2}"
    return f"Creation dates not comparable: {creation_date1} vs {creation_date2}"

def compare_iocs(iocs, substring=None):
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
                comparison = compare_two_iocs(ioc1, ioc2, data1, data2, substring=substring)
                f.write(comparison)

    print(f"Comparison analysis saved to {analysis_filename}")
    with open(analysis_filename, "r") as f:
        print(f.read())