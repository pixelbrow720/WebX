import os
import json
import logging
import subprocess
import requests
import datetime
from urllib.parse import urlparse

def is_valid_domain(domain):
    """Validate if the input is a proper domain."""
    try:
        # Basic validation - can be expanded
        parsed = urlparse(domain if '//' in domain else f'http://{domain}')
        return bool(parsed.netloc)
    except Exception:
        return False

def perform_subdomain_enumeration(domain):
    """
    Attempt to enumerate subdomains using built-in techniques.
    In a real-world scenario, this would integrate with Sublist3r or Amass.
    """
    logging.info(f"Starting subdomain enumeration for {domain}")
    
    # This is a simple implementation for demo purposes
    # In a real implementation, you'd run Sublist3r or Amass as a subprocess
    
    # Simulating a subprocess call to sublist3r
    # subprocess.run(['sublist3r', '-d', domain, '-o', 'subdomains.txt'], check=True)
    
    # For demo purposes, perform basic DNS lookups
    try:
        import socket
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'dev', 'api']
        results = []
        
        for sub in common_subdomains:
            try:
                subdomain = f"{sub}.{domain}"
                socket.gethostbyname(subdomain)
                results.append({
                    'subdomain': subdomain,
                    'status': 'active',
                    'ip': socket.gethostbyname(subdomain)
                })
            except socket.gaierror:
                pass
        
        logging.info(f"Found {len(results)} subdomains for {domain}")
        return results
    except Exception as e:
        logging.error(f"Error in subdomain enumeration: {str(e)}")
        return []

def get_shodan_data(domain):
    """
    Retrieve information from Shodan API.
    """
    shodan_api_key = os.environ.get("SHODAN_API_KEY")
    if not shodan_api_key:
        logging.warning("SHODAN_API_KEY not found in environment variables")
        return {'error': 'Shodan API key not configured'}
    
    try:
        api_url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query=hostname:{domain}"
        response = requests.get(api_url)
        
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Shodan API error: {response.status_code}, {response.text}")
            return {'error': f"Shodan API error: {response.status_code}"}
    except Exception as e:
        logging.error(f"Error fetching Shodan data: {str(e)}")
        return {'error': str(e)}

def perform_reconnaissance(target, scan_type='basic', shodan_enabled=False, subdomains_enabled=False):
    """
    Main reconnaissance function that coordinates the scanning process.
    """
    if not target:
        return {'error': 'No target specified'}
        
    if not is_valid_domain(target):
        return {'error': 'Invalid domain format'}
    
    # Parse the domain from URL if needed
    domain = urlparse(target if '//' in target else f'http://{target}').netloc or target
    
    # Initialize results dictionary
    results = {
        'target': domain,
        'scan_type': scan_type,
        'timestamp': datetime.datetime.now().isoformat(),
        'subdomains': [],
        'shodan_data': {},
        'whois': {},
        'dns_records': {}
    }
    
    # Subdomain enumeration if enabled
    if subdomains_enabled:
        results['subdomains'] = perform_subdomain_enumeration(domain)
    
    # Shodan lookup if enabled
    if shodan_enabled:
        results['shodan_data'] = get_shodan_data(domain)
    
    # Basic DNS information
    try:
        import dns.resolver
        
        for record_type in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results['dns_records'][record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                results['dns_records'][record_type] = [f"Error: {str(e)}"]
    except ImportError:
        logging.warning("dnspython not available, skipping DNS records")
        results['dns_records']['error'] = "DNS resolver library not available"
    
    # Try to get WHOIS information
    try:
        import whois # type: ignore
        whois_data = whois.whois(domain)
        results['whois'] = {
            'registrar': whois_data.registrar,
            'creation_date': str(whois_data.creation_date),
            'expiration_date': str(whois_data.expiration_date),
            'name_servers': whois_data.name_servers
        }
    except Exception as e:
        logging.warning(f"Error getting WHOIS data: {str(e)}")
        results['whois']['error'] = str(e)
    
    return results

