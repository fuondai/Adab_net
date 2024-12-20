import requests
import json
import threading
from typing import List, Dict, Optional

class CVEScanner:
    def __init__(self, nvd_api_key: Optional[str] = None):
        """
        Initialize CVE Scanner with optional NVD API key
        
        :param nvd_api_key: API key for National Vulnerability Database
        """
        self.nvd_api_key = nvd_api_key
        self.headers = {
            'Accept': 'application/json',
            'User-Agent': 'network_scanner'
        }
        if nvd_api_key:
            self.headers['API_KEY'] = nvd_api_key
    
    def _fetch_cves_by_cpe(self, cpe: str) -> List[Dict]:
        """
        Fetch CVEs for a specific CPE from NVD
        
        :param cpe: Common Platform Enumeration string
        :return: List of CVEs
        """
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'cpeName': cpe,
            'resultsPerPage': 20  # Limit results
        }
        
        try:
            response = requests.get(base_url, headers=self.headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            cves = []
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cves.append({
                    'id': cve.get('id', 'N/A'),
                    'description': cve.get('descriptions', [{}])[0].get('value', 'No description'),
                    'severity': self._get_cvss_severity(cve)
                })
            return cves
        except Exception as e:
            print(f"Error fetching CVEs for {cpe}: {e}")
            return []
    
    def _get_cvss_severity(self, cve_data: Dict) -> str:
        """
        Determine CVSS severity from CVE data
        
        :param cve_data: CVE metadata
        :return: Severity level
        """
        try:
            metrics = cve_data.get('metrics', {}).get('cvssMetricV31', [{}])[0]
            score = metrics.get('cvssData', {}).get('baseScore', 0)
            
            if score == 0:
                return 'Unknown'
            elif score < 4:
                return 'Low'
            elif score < 7:
                return 'Medium'
            elif score < 9:
                return 'High'
            else:
                return 'Critical'
        except Exception:
            return 'Unknown'
    
    def scan(self, service_info: Dict[str, str], cpe_mappings: Dict[str, str] = None) -> Dict:
        """
        Scan for CVEs based on service information
        
        :param service_info: Service details from network scan
        :param cpe_mappings: Custom mapping for services to CPE
        :return: Dictionary of CVEs for each service
        """
        default_mappings = {
            'ftp': 'cpe:2.3:a:filezilla:*',
            'ssh': 'cpe:2.3:a:openssh:*',
            'http': 'cpe:2.3:a:apache:*',
            'https': 'cpe:2.3:a:apache:*',
            'mysql': 'cpe:2.3:a:mysql:*',
            # Add more mappings as needed
        }
        
        cpe_mappings = cpe_mappings or default_mappings
        results = {}
        
        # Allow concurrent scanning
        def _process_service(service, version):
            mapping_key = service.lower()
            cpe = cpe_mappings.get(mapping_key, '')
            if cpe:
                cves = self._fetch_cves_by_cpe(cpe)
                if cves:
                    results[service] = cves
        
        threads = []
        for service, version in service_info.items():
            thread = threading.Thread(target=_process_service, args=(service, version))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
        
        return results
