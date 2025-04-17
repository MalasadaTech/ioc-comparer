import sys
import os
import argparse
from utils import get_rdap_bootstrap, re_fang_domain
from check_ioc import check_ioc
from compare_ioc import compare_iocs

if __name__ == "__main__":
    # Add argument parsing
    parser = argparse.ArgumentParser(description="Process and compare IOCs.")
    parser.add_argument("iocs", nargs="*", help="List of IOCs or a file containing IOCs.")
    parser.add_argument("--sstring", type=str, help="Substring to search for in domain names.")
    parser.add_argument("--config", type=str, default="config.ini", help="Path to configuration file with API keys.")
    args = parser.parse_args()

    # Parse IOCs from file or command line
    if args.iocs and args.iocs[0].endswith(('.txt', '.csv')):
        try:
            with open(args.iocs[0], "r") as f:
                iocs = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading file {args.iocs[0]}: {e}")
            sys.exit(1)
    else:
        iocs = args.iocs

    # Remove defanging and sort IOCs
    iocs = sorted(re_fang_domain(ioc) for ioc in iocs)
    if not iocs:
        print("No valid IOCs provided.")
        sys.exit(1)

    # Fetch RDAP bootstrap data once
    tld_to_rdap = get_rdap_bootstrap()

    # Check each IOC
    for ioc in iocs:
        print(f"Checking {ioc}...")
        check_ioc(ioc, tld_to_rdap, config_path=args.config)

    # Compare IOCs if more than one
    if len(iocs) > 1:
        print("\n\nComparing IOCs...")
        substring = args.sstring
        compare_iocs(iocs, substring)

    print("Exiting.")