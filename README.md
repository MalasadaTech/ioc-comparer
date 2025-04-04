# IOC Comparer

**IOC Comparer** is a Python tool designed to analyze and compare two domain-based Indicators of Compromise (IOCs). It collects metadata such as IP addresses, Autonomous System Numbers (ASNs), RDAP (Registration Data Access Protocol) data, and SSL certificate information from crt.sh, then compares these attributes to identify similarities and differences between the domains.

## Features

- **IP Resolution**: Retrieves IPv4 and IPv6 addresses for each domain using DNS lookups.
- **ASN Lookup**: Identifies the ASN number and name for each IP address via Team Cymru’s DNS service.
- **RDAP Data**: Fetches domain registration details (status, creation/expiration dates, registrar, name servers) from RDAP servers.
- **SSL Certificates**: Queries crt.sh for SSL certificate details (certificate ID, issuer, common name, validity dates).
- **Comparison**: Analyzes the collected metadata, focusing on:
  - Shared IPs and ASNs.
  - RDAP status, registrar, name servers, and date proximity (within 7 days for creation/expiration).
  - SSL certificate issuing organization and `not_before` date proximity (within 7 days) for the first certificate of each domain.
- **Output**: Saves all data to a JSON file (`domains.json`) and prints a human-readable comparison of similarities and differences.

## Prerequisites

- **Python**: Version 3.6 or higher.
- **Dependencies**:
  - `dnspython`: For DNS resolution.
  - `requests`: For HTTP requests to RDAP servers and crt.sh.

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

## Usage

Run the script from the command line by providing two domain names as arguments:

```bash
python ioc_comparer.py domain1 domain2
```

### Example

```bash
python ioc_comparer.py example.com example.org
```

### Output

- **JSON File**: A file named `domains.json` is created in the current directory with detailed metadata for both domains.
- **Console Output**: A comparison summary is printed, e.g.:

```
Data saved to domains.json

Similarities:
- Both domains have the same RDAP status: active
- Both domains have the same registrar: Example Registrar Inc.
- SSL cert issuing organizations are the same: Let's Encrypt

Differences:
- No shared IPs. example.com has 93.184.216.34, example.org has 198.51.100.1
- Creation dates differ by more than 7 days: 2022-01-15T00:00:00+00:00 vs 2022-03-01T00:00:00+00:00
- SSL cert not_before dates differ by more than 7 days: 2023-10-01T00:00:00+00:00 vs 2023-11-01T00:00:00+00:00
```

### Sample `domains.json`

```json
{
    "example.com": {
        "ips": [{"address": "93.184.216.34", "asn_number": "15133", "asn_name": "EDGECAST"}],
        "rdap": {
            "status": ["active"],
            "creation_date": "2022-01-15T00:00:00Z",
            "expiration_date": "2023-01-15T00:00:00Z",
            "registrar": "Example Registrar Inc.",
            "name_servers": ["ns1.example.com"]
        },
        "ssl_certs": [
            {
                "id": "123456789",
                "issuer_name": "C=US, O=Let's Encrypt, CN=R10",
                "common_name": "example.com",
                "not_before": "2023-10-01T00:00:00",
                "not_after": "2024-01-01T00:00:00"
            }
        ]
    },
    "example.org": {...}
}
```

## How It Works

### Data Collection

- Resolves domain IPs using `dns.resolver`.
- Queries ASNs via Team Cymru’s DNS TXT records.
- Fetches RDAP data using the IANA bootstrap file and direct HTTP requests.
- Retrieves SSL certificates from crt.sh.

### Comparison

- Compares IPs, ASNs, and RDAP fields (status, registrar, name servers).
- Checks if RDAP creation and expiration dates are within 7 days of each other.
- For SSL certificates, uses the first certificate from each domain to compare:
  - Issuing organization (extracted from `issuer_name`).
  - `not_before` dates (within 7 days).

### Output

- Saves all data to `domains.json`.
- Prints similarities first, followed by differences.

## Limitations

- **Rate Limits**: External services (RDAP servers, crt.sh) may impose rate limits, potentially causing failures with excessive use.
- **Data Availability**: Some domains may lack RDAP support or SSL certificates, resulting in partial data.
- **Time Sensitivity**: Date comparisons depend on the current UTC time when the script runs.

## Roadmap

- Enhanced SSL Filtering: Add options for filtering SSL certificates based on specific criteria.
- Change the filename from `domains.json` to something unique.
- Change the output write folder to something unique.
- Modify the SSL comparison so that it compares all of the SSL certs.
- Format the nameservers to lowercase, and in alphabetical order for correct matching.
- Parse additional RDAP fields that could prove useful (Registrant info).
- Add a threat feed lookup.
- Map findings to DTF Matrix.
- Parse additional SSL fields that could prove useful (such alias, etc.).
- Provide a reverse lookup on IP.
- Create a method to take a CSV with multiple IOCs as an input.
- Configure it to also allow just one IOC input.
- Add a feature to analyze an existing `domains.json` file.
- Add a feature to save the comparison analysis to a unique `analysis.txt` file.


