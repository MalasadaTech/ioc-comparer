# IOC Comparer

**IOC Comparer** is a Python tool designed to analyze and compare two domain-based Indicators of Compromise (IOCs). It collects metadata such as IP addresses, Autonomous System Numbers (ASNs), RDAP (Registration Data Access Protocol) data, and SSL certificate information from crt.sh, then compares these attributes to identify similarities and differences between the domains.

## Features

- **IP Resolution**: Retrieves IPv4 and IPv6 addresses for each domain using DNS lookups.
- **ASN Lookup**: Identifies the ASN number and name for each IP address via Team Cymru's DNS service.
- **RDAP Data**: Fetches domain registration details (status, creation/expiration dates, registrar, name servers) from RDAP servers.
- **SSL Certificates**: Queries crt.sh for SSL certificate details (certificate ID, issuer, common name, validity dates).
- **OTX Integration**: Automatically enriches IOCs with threat intelligence from AlienVault Open Threat Exchange (OTX).
- **VirusTotal Integration**: Enriches IOCs with VirusTotal data including vendor score, community score, and tags.
- **ThreatFox Integration**: Enriches IOCs with malware and threat intelligence from ThreatFox.
- **Comparison**: Analyzes the collected metadata, focusing on:
  - Shared IPs and ASNs.
  - RDAP status, registrar, name servers, and date proximity (within 7 days for creation/expiration).
  - SSL certificate issuing organization and `not_before` date proximity (within 7 days) for the first certificate of each domain.
  - OTX data including shared threat reports, reputation scores, and pulse information.
  - VirusTotal data such as similar vendor and community scores, and matching tags.
- **Output**: Saves all data to JSON files and prints a human-readable comparison of similarities and differences.

## Prerequisites

- **Python**: Version 3.6 or higher.
- **Dependencies**:
  - `dnspython`: For DNS resolution.
  - `requests`: For HTTP requests to RDAP servers, crt.sh, and threat intelligence APIs.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/MalasadaTech/ioc-comparer.git
   cd ioc-comparer
   ```

2. **Set Up a Virtual Environment** (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Required Packages**:
   ```bash
   pip install dnspython requests
   ```

4. **Configure API Keys**:
   - Copy `config.ini.template` to `config.ini`
   - Add your API keys to the config file under the [API_KEYS] section:
     - OTX API key (optional) - enables OTX threat intelligence enrichment
     - VirusTotal API key (optional) - enables VirusTotal enrichment
     - ThreatFox API key (optional) - enables ThreatFox malware intelligence enrichment

## Usage

Run the script from the command line by providing two domain names as arguments:

```bash
python main.py domain1 domain2
```

### Options

- `--sstring`: Specify a substring to search for in domain names.
- `--config`: Specify a path to configuration file with API keys (default: config.ini).

### Example

```bash
python main.py example.com example.org
```

### Output

- **JSON Files**: JSON files are created in the output directory with detailed metadata for each domain.
- **Analysis Files**: Text analysis files are created for both individual IOCs and comparisons.
- **Console Output**: A comparison summary is printed, e.g.:

```
Similarities:
- P0101.001 - Registration: Registrar: Example Registrar Inc.
- P0101.002 - Registration: Registration date (7 days): 2022-01-15T00:00:00+00:00 and 2022-01-20T00:00:00+00:00
- P0101.010 - Registration: Name Server: ns1.example.com
- P0201 - IP: 93.184.216.34
- P0203 - AS: 15133

Enriched Similarities:
- OTX Shared Threat Reports: Malicious Domain Campaign
- VT Similar Malicious Ratings: 3.2% vs 4.1%
- VT Shared Tags: phishing, malicious-activity

Differences:
- SSL cert not_before dates differ by more than 7 days: 2023-10-01T00:00:00+00:00 vs 2023-11-01T00:00:00+00:00
```

## Threat Intelligence Integrations

### OTX Integration

The tool automatically enriches IOCs with threat intelligence from AlienVault OTX:

1. Copy `config.ini.template` to `config.ini`
2. Add your OTX API key to the config file under the [API_KEYS] section
3. Run the tool normally - OTX enrichment happens automatically if a valid key is present

The OTX integration provides:
- General indicator details
- Pulse (threat report) information
- Reputation data for IPs and domains
- Comparison of shared threat reports between IOCs

### VirusTotal Integration

VirusTotal enrichment provides additional context about the maliciousness of IOCs:

1. Copy `config.ini.template` to `config.ini` if you haven't already
2. Add your VirusTotal API key to the config file under the [API_KEYS] section
3. Run the tool normally - VirusTotal enrichment happens automatically if a valid key is present

The VirusTotal integration provides:
- Vendor scanner statistics (malicious/suspicious/clean votes)
- Community reputation score
- Associated tags
- First submission and last analysis dates
- Comparison of all these data points between IOCs

### ThreatFox Integration

ThreatFox enrichment provides additional threat intelligence about malware and IOCs:

1. Copy `config.ini.template` to `config.ini` if you haven't already
2. Add your ThreatFox API key to the config file under the [API_KEYS] section
3. Run the tool normally - ThreatFox enrichment happens automatically if a valid key is present

The ThreatFox integration provides:
- Threat type and description for IOCs
- Malware family and printable name information
- Malware aliases and related samples
- Confidence level and first seen dates
- Comparison of shared threat intelligence between IOCs

## How It Works

### Data Collection

- Resolves domain IPs using `dns.resolver`.
- Queries ASNs via Team Cymru's DNS TXT records.
- Fetches RDAP data using the IANA bootstrap file and direct HTTP requests.
- Retrieves SSL certificates from crt.sh.
- Enriches IOCs with threat intelligence from OTX, VirusTotal, and ThreatFox.

### Comparison

- Compares IPs, ASNs, and RDAP fields (status, registrar, name servers).
- Checks if RDAP creation and expiration dates are within 7 days of each other.
- For SSL certificates, uses the first certificate from each domain to compare:
  - Issuing organization (extracted from `issuer_name`).
  - `not_before` dates (within 7 days).
- For OTX data, compares:
  - Shared threat reports (pulses)
  - Reputation and threat scores
  - Timing of most recent threat reports
- For VirusTotal data, compares:
  - Vendor assessment percentages
  - Community reputation scores
  - Shared tags
  - First submission dates proximity
- For ThreatFox data, compares:
  - Threat types and malware families
  - Shared malware aliases
  - First seen dates (within 7 days)
  - Confidence levels and associated samples

### Output

- Saves all data to JSON files in the output directory.
- Creates analysis text files for both individual IOCs and comparisons.
- Prints similarities first, followed by differences.

## Notes

- The previously used `ioc_comparer.py` script is now obsolete and has been renamed to `ioc_comparer.txt` for archival purposes.
- Use `main.py` for all future operations.

## Limitations

- **Rate Limits**: External services (RDAP servers, crt.sh, OTX, VirusTotal) may impose rate limits, potentially causing failures with excessive use.
- **Data Availability**: Some domains may lack RDAP support, SSL certificates, or threat intelligence data, resulting in partial analysis.
- **Time Sensitivity**: Date comparisons depend on the current UTC time when the script runs.
- **API Key Requirement**: OTX and VirusTotal lookups require valid API keys from their respective providers.
- **VirusTotal Free API Limitations**: The free VirusTotal API has usage limits of 4 requests per minute and 500 requests per day.

