import requests
import os
import logging
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

class VTClient:
    """Client for VirusTotal API."""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, env_path: str = ".env"):
        """Initialize VirusTotal client with API key from environment variables."""
        # Initialize logger first before using it
        self.logger = logging.getLogger(__name__)
        self.api_key = self._load_api_key(env_path)
        self.headers = {
            'x-apikey': self.api_key,
            'User-Agent': 'IOC-Comparer',
            'Accept': 'application/json'
        }
    
    def _load_api_key(self, env_path: str) -> str:
        """Load API key from environment variables."""
        # Load environment variables from .env file if it exists
        if os.path.exists(env_path):
            load_dotenv(env_path)
        
        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            self.logger.warning("VT_API_KEY environment variable not found. VirusTotal enrichment will be skipped.")
            return ""
        
        if api_key == "your_vt_api_key_here":
            self.logger.warning("No valid VirusTotal API key found. VirusTotal enrichment will be skipped.")
            return ""
            
        return api_key
    
    def get_indicator_details(self, ioc_type: str, ioc_value: str) -> Optional[Dict[str, Any]]:
        """Get details for an indicator from VirusTotal.
        
        Args:
            ioc_type: Type of IOC ('domain', 'hostname', 'ip', 'url', 'md5', 'sha1', 'sha256', etc.)
            ioc_value: The IOC value to look up
            
        Returns:
            Dictionary with indicator details or None if not found or error
        """
        if not self.api_key:
            self.logger.info("Skipping VirusTotal lookup - no API key")
            return None
            
        # Map our IOC types to VT endpoint types
        ioc_type_map = {
            'ipv4': 'ip_addresses',
            'ipv6': 'ip_addresses',
            'domain': 'domains',
            'url': 'urls',
            'md5': 'files',
            'sha1': 'files',
            'sha256': 'files',
            'sha512': 'files',
        }
        
        vt_type = ioc_type_map.get(ioc_type.lower())
        if not vt_type:
            self.logger.warning(f"Unsupported IOC type for VirusTotal: {ioc_type}")
            return None
        
        # For URLs, we need to encode the URL
        if vt_type == 'urls':
            import base64
            ioc_value = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip('=')
        
        endpoint = f"{self.BASE_URL}/{vt_type}/{ioc_value}"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                return result.get('data', {})
            elif response.status_code == 404:
                self.logger.info(f"IOC not found in VirusTotal: {ioc_value}")
                return None
            else:
                self.logger.error(f"VirusTotal API error: {response.status_code}")
                return None
        except requests.RequestException as e:
            self.logger.error(f"VirusTotal request failed: {e}")
            return None
    
    def extract_vt_summary(self, vt_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract a summary of the VirusTotal data for the IOC.
        
        Args:
            vt_data: The full VirusTotal data response
            
        Returns:
            Dictionary with summarized data
        """
        if not vt_data:
            return {}
            
        summary = {}
        
        # Extract attributes
        attributes = vt_data.get('attributes', {})
        
        # Get last analysis stats (vendor scores)
        if 'last_analysis_stats' in attributes:
            summary['vendor_stats'] = attributes['last_analysis_stats']
        
        # Get detailed last analysis results
        if 'last_analysis_results' in attributes:
            summary['analysis_results'] = attributes['last_analysis_results']
            
        # Get community reputation score
        if 'reputation' in attributes:
            summary['community_score'] = attributes['reputation']
            
        # Get tags
        if 'tags' in attributes:
            summary['tags'] = attributes['tags']
        
        # Get categories
        if 'categories' in attributes:
            summary['categories'] = attributes['categories']
            
        # Get registrar
        if 'registrar' in attributes:
            summary['registrar'] = attributes['registrar']
        
        # Get creation date
        if 'creation_date' in attributes:
            summary['creation_date'] = attributes['creation_date']
            
        # Get last update date
        if 'last_update_date' in attributes:
            summary['last_update_date'] = attributes['last_update_date']
        
        # Get last analysis date
        if 'last_analysis_date' in attributes:
            summary['last_analysis_date'] = attributes['last_analysis_date']
            
        # Get first submission date (if exists)
        if 'first_submission_date' in attributes:
            summary['first_submission_date'] = attributes['first_submission_date']
            
        # Get total votes
        if 'total_votes' in attributes:
            summary['total_votes'] = attributes['total_votes']
            
        # Get popularity ranks
        if 'popularity_ranks' in attributes:
            summary['popularity_ranks'] = attributes['popularity_ranks']
            
        # Get DNS records summary (just count)
        if 'last_dns_records' in attributes:
            dns_records = attributes['last_dns_records']
            summary['dns_records_count'] = len(dns_records)
            
            # Extract A and AAAA records for easier reference
            a_records = [r['value'] for r in dns_records if r.get('type') == 'A']
            aaaa_records = [r['value'] for r in dns_records if r.get('type') == 'AAAA']
            ns_records = [r['value'] for r in dns_records if r.get('type') == 'NS']
            
            if a_records:
                summary['a_records'] = a_records
            if aaaa_records:
                summary['aaaa_records'] = aaaa_records
            if ns_records:
                summary['ns_records'] = ns_records
            
        # Get JARM hash if available
        if 'jarm' in attributes:
            summary['jarm'] = attributes['jarm']
        
        return summary