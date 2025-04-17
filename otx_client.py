import requests
import configparser
import os
import logging
from typing import Dict, Any, Optional, List

class OTXClient:
    """Client for AlienVault OTX API."""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, config_path: str = "config.ini"):
        """Initialize OTX client with API key from config."""
        self.api_key = self._load_api_key(config_path)
        self.headers = {
            'X-OTX-API-KEY': self.api_key,
            'User-Agent': 'IOC-Comparer',
            'Content-Type': 'application/json'
        }
        self.logger = logging.getLogger(__name__)
    
    def _load_api_key(self, config_path: str) -> str:
        """Load API key from config file."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}. Please copy config.ini.template to config.ini and add your API key.")
        
        config = configparser.ConfigParser()
        config.read(config_path)
        
        try:
            api_key = config.get('API_KEYS', 'otx_api_key')
            if api_key == "your_otx_api_key_here":
                raise ValueError("Please update config.ini with your actual OTX API key")
            return api_key
        except (configparser.NoSectionError, configparser.NoOptionError) as e:
            raise ValueError(f"Invalid config file format: {e}")
    
    def get_indicator_details(self, ioc_type: str, ioc_value: str) -> Optional[Dict[str, Any]]:
        """Get details for an indicator from OTX.
        
        Args:
            ioc_type: Type of IOC ('domain', 'hostname', 'ip', 'url', 'hash', etc.)
            ioc_value: The IOC value to look up
            
        Returns:
            Dictionary with indicator details or None if not found
        """
        # Map our IOC types to OTX indicator types
        ioc_type_map = {
            'ipv4': 'IPv4',
            'ipv6': 'IPv6',
            'domain': 'domain',
            'url': 'url',
            'md5': 'file',
            'sha1': 'file',
            'sha256': 'file',
            'sha512': 'file',
            'email': 'email',
        }
        
        otx_type = ioc_type_map.get(ioc_type.lower())
        if not otx_type:
            self.logger.warning(f"Unsupported IOC type for OTX: {ioc_type}")
            return None
        
        # Special handling for file hashes
        if otx_type == 'file':
            endpoint = f"{self.BASE_URL}/indicators/file/{ioc_value}/general"
        else:
            endpoint = f"{self.BASE_URL}/indicators/{otx_type}/{ioc_value}/general"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                self.logger.info(f"IOC not found in OTX: {ioc_value}")
                return None
            else:
                self.logger.error(f"OTX API error: {response.status_code}")
                return None
        except requests.RequestException as e:
            self.logger.error(f"OTX request failed: {e}")
            return None
    
    def get_pulse_info(self, ioc_type: str, ioc_value: str) -> List[Dict[str, Any]]:
        """Get pulses (threat reports) that mention this indicator.
        
        Args:
            ioc_type: Type of IOC
            ioc_value: The IOC value to look up
            
        Returns:
            List of pulse details
        """
        # First try to get pulse info from the general endpoint
        details = self.get_indicator_details(ioc_type, ioc_value)
        if details and 'pulse_info' in details:
            pulses = details.get('pulse_info', {}).get('pulses', [])
            if pulses:
                return pulses
        
        # If that didn't work, try the direct pulses endpoint (though this appears to be deprecated)
        ioc_type_map = {
            'ipv4': 'IPv4',
            'ipv6': 'IPv6',
            'domain': 'domain',
            'url': 'url',
            'md5': 'file',
            'sha1': 'file',
            'sha256': 'file',
            'sha512': 'file',
            'email': 'email',
        }
        
        otx_type = ioc_type_map.get(ioc_type.lower())
        if not otx_type:
            self.logger.warning(f"Unsupported IOC type for OTX pulse lookup: {ioc_type}")
            return []
        
        if otx_type == 'file':
            endpoint = f"{self.BASE_URL}/indicators/file/{ioc_value}/pulses"
        else:
            endpoint = f"{self.BASE_URL}/indicators/{otx_type}/{ioc_value}/pulses"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                return result.get('pulses', [])
            else:
                self.logger.info(f"OTX pulse endpoint returned status code: {response.status_code}")
                return []
        except requests.RequestException as e:
            self.logger.error(f"OTX request failed when fetching pulses: {e}")
            return []

    def get_reputation(self, ioc_type: str, ioc_value: str) -> Optional[Dict[str, Any]]:
        """Get reputation data for an indicator.
        
        Args:
            ioc_type: Type of IOC
            ioc_value: The IOC value to look up
            
        Returns:
            Reputation details or None
        """
        if ioc_type.lower() not in ['ipv4', 'ipv6', 'domain']:
            return None
            
        endpoint = f"{self.BASE_URL}/indicators/{ioc_type}/{ioc_value}/reputation"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except requests.RequestException:
            return None