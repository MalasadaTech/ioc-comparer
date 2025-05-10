import requests
import configparser
import os
import logging
import ipaddress
from typing import Dict, Any, Optional, Tuple

class IPinfoClient:
    """Client for IPinfo.io API."""
    
    BASE_URL = "https://api.ipinfo.io/lite"
    
    def __init__(self, config_path: str = "config.ini"):
        """Initialize IPinfo client with API key from config."""
        # Initialize logger first before using it
        self.logger = logging.getLogger(__name__)
        self.api_key = self._load_api_key(config_path)
        self.headers = {
            'Accept': 'application/json',
            'User-Agent': 'IOC-Comparer'
        }
    
    def _load_api_key(self, config_path: str) -> str:
        """Load API key from config file."""
        if not os.path.exists(config_path):
            self.logger.warning(f"Config file not found: {config_path}. IPinfo enrichment will be skipped.")
            return ""
        
        config = configparser.ConfigParser()
        config.read(config_path)
        
        try:
            api_key = config.get('API_KEYS', 'ipinfo_api_key')
            if not api_key or api_key == "your_ipinfo_api_key_here":
                self.logger.warning("No valid IPinfo API key found. IPinfo enrichment will be skipped.")
                return ""
            return api_key
        except (configparser.NoSectionError, configparser.NoOptionError) as e:
            self.logger.warning(f"Invalid config file format or missing IPinfo API key: {e}")
            return ""
    
    def get_ip_details(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get details for an IP address from IPinfo.io.
        
        Args:
            ip_address (str): The IP address to look up
            
        Returns:
            Dictionary with IP details or None if not found or error
        """
        if not self.api_key:
            self.logger.info("Skipping IPinfo lookup - no API key")
            return None
        
        # Validate IP address
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            self.logger.warning(f"Invalid IP address format: {ip_address}")
            return None
        
        endpoint = f"{self.BASE_URL}/{ip_address}"
        params = {"token": self.api_key}
        
        try:
            response = requests.get(endpoint, headers=self.headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                self.logger.info(f"IP not found in IPinfo: {ip_address}")
                return None
            else:
                self.logger.error(f"IPinfo API error: {response.status_code}")
                return None
        except requests.RequestException as e:
            self.logger.error(f"IPinfo request failed: {e}")
            return None
    
    def get_asn_info(self, ip_address: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Get ASN information for an IP address.
        
        Args:
            ip_address: The IP address to look up ASN information for
            
        Returns:
            Tuple of (asn_number, asn_name, country_code) or (None, None, None) if not found
        """
        details = self.get_ip_details(ip_address)
        
        if not details:
            return None, None, None
            
        asn_number = None
        if "asn" in details:
            # Remove the "AS" prefix to maintain consistency with Cymru format
            asn_number = details["asn"].replace("AS", "")
            
        asn_name = details.get("as_name")
        country_code = details.get("country_code")
        
        return asn_number, asn_name, country_code