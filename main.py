import sys
import os
from utils import get_rdap_bootstrap, re_fang_domain
from check_ioc import check_ioc
from compare_ioc import compare_iocs

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <ioc1> <ioc2> ... OR python main.py <file.txt/csv>")
        sys.exit(1)

    # Parse arguments
    if sys.argv[1].endswith(('.txt', '.csv')):
        try:
            with open(sys.argv[1], "r") as f:
                iocs = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading file {sys.argv[1]}: {e}")
            sys.exit(1)
    else:
        iocs = sys.argv[1:]

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
        check_ioc(ioc, tld_to_rdap)

    # Compare IOCs if more than one
    if len(iocs) > 1:
        print("Comparing IOCs...")
        compare_iocs(iocs)

    print("Exiting.")