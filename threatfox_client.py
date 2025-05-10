import requests
import os
import logging
import json
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

class ThreatFoxClient:
    """Client for ThreatFox API."""
    
    BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"
    
    def __init__(self, env_path: str = ".env"):
        """Initialize ThreatFox client with API key from environment variables."""
        # Initialize logger first before using it
        self.logger = logging.getLogger(__name__)
        self.api_key = self._load_api_key(env_path)
        self.headers = {
            'Auth-Key': self.api_key,
            'User-Agent': 'IOC-Comparer',
            'Content-Type': 'application/json'
        }
    
    def _load_api_key(self, env_path: str) -> str:
        """Load API key from environment variables."""
        # Load environment variables from .env file if it exists
        if os.path.exists(env_path):
            load_dotenv(env_path)
        
        api_key = os.getenv("THREATFOX_API_KEY")
        if not api_key:
            self.logger.warning("THREATFOX_API_KEY environment variable not found. ThreatFox enrichment will be skipped.")
            return ""
        
        if api_key == "your_threatfox_api_key_here":
            self.logger.warning("No valid ThreatFox API key found. ThreatFox enrichment will be skipped.")
            return ""
            
        return api_key
    
    def search_ioc(self, ioc_value: str) -> Optional[Dict[str, Any]]:
        """Search for an IOC in ThreatFox.
        
        Args:
            ioc_value: The IOC value to look up
            
        Returns:
            Dictionary with IOC details or None if not found or error
        """
        if not self.api_key:
            self.logger.info("Skipping ThreatFox lookup - no API key")
            return None
        
        payload = {
            "query": "search_ioc",
            "search_term": ioc_value,
            "exact_match": True
        }
        
        try:
            response = requests.post(self.BASE_URL, headers=self.headers, data=json.dumps(payload), timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('query_status') == 'ok' and result.get('data'):
                    # Process and return the first match
                    return self._extract_threatfox_summary(result['data'][0])
                elif result.get('query_status') == 'no_result':
                    self.logger.info(f"IOC not found in ThreatFox: {ioc_value}")
                    return None
                else:
                    error_message = result.get('data', {}).get('error_message', 'Unknown error')
                    self.logger.warning(f"ThreatFox API error: {error_message}")
                    return None
            else:
                self.logger.error(f"ThreatFox API error: {response.status_code}")
                return None
        except requests.RequestException as e:
            self.logger.error(f"ThreatFox request failed: {e}")
            return None
    
    def _extract_threatfox_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant information from the ThreatFox response.
        
        Args:
            data: The ThreatFox data for this IOC
            
        Returns:
            Dictionary with summarized data
        """
        summary = {}
        
        # Extract relevant fields from ThreatFox data
        fields_to_extract = [
            'id', 'ioc', 'threat_type', 'threat_type_desc', 
            'ioc_type', 'ioc_type_desc', 'malware', 'malware_printable',
            'malware_alias', 'confidence_level', 'first_seen', 'last_seen',
            'reporter', 'reference', 'tags'
        ]
        
        for field in fields_to_extract:
            if field in data:
                summary[field] = data[field]
        
        # Add malware samples if they exist (but limit to avoid very large response)
        if 'malware_samples' in data and data['malware_samples']:
            summary['malware_samples_count'] = len(data['malware_samples'])
            # Include just the first sample as an example
            if len(data['malware_samples']) > 0:
                summary['sample_info'] = data['malware_samples'][0]
        
        return summary