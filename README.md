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
python main.py domain1 domain2
```

### Example

```bash
python main.py example.com example.org
```

### Output

- **JSON File**: A file named `domains.json` is created in the current directory with detailed metadata for both domains.
- **Console Output**: A comparison summary is printed, e.g.:

```
Data saved to domains.json

Similarities:
- P0101.001 - Registration: Registrar: Example Registrar Inc.
- P0101.002 - Registration: Registration date (7 days): 2022-01-15T00:00:00+00:00 and 2022-01-20T00:00:00+00:00
- P0101.010 - Registration: Name Server: ns1.example.com
- P0201 - IP: 93.184.216.34
- P0203 - AS: 15133

Differences:
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

## Notes

- The previously used `ioc_comparer.py` script is now obsolete and has been renamed to `ioc_comparer.txt` for archival purposes.
- Use `main.py` for all future operations.

## Limitations

- **Rate Limits**: External services (RDAP servers, crt.sh) may impose rate limits, potentially causing failures with excessive use.
- **Data Availability**: Some domains may lack RDAP support or SSL certificates, resulting in partial data.
- **Time Sensitivity**: Date comparisons depend on the current UTC time when the script runs.

