import logging
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import datetime

def is_valid_url(url):
    """Check if URL is valid and has proper scheme."""
    try:
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)
    except Exception:
        return False

def extract_input_fields(html_content, url):
    """Extract all input fields from HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    input_fields = []
    for form in soup.find_all('form'):
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').upper()
        
        # Resolve form action URL
        if form_action:
            if form_action.startswith('/'):
                parsed_url = urlparse(url)
                form_action_url = f"{parsed_url.scheme}://{parsed_url.netloc}{form_action}"
            elif not form_action.startswith(('http://', 'https://')):
                form_action_url = urljoin(url, form_action)
            else:
                form_action_url = form_action
        else:
            form_action_url = url
            
        form_inputs = []
        
        # Process all input elements
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.get('type', 'text')
            input_name = input_tag.get('name', '')
            input_id = input_tag.get('id', '')
            
            if input_name or input_id:
                form_inputs.append({
                    'type': input_type,
                    'name': input_name,
                    'id': input_id
                })
        
        if form_inputs:
            input_fields.append({
                'form_action': form_action_url,
                'method': form_method,
                'inputs': form_inputs
            })
    
    return input_fields

def extract_javascript_endpoints(html_content):
    """Extract potential API endpoints from JavaScript."""
    # Look for URL patterns in JavaScript
    api_patterns = [
        r'"/api/[^"]*"',
        r"'/api/[^']*'",
        r'fetch\([^)]+\)',
        r'\.ajax\([^)]+\)',
        r'\.get\([^)]+\)',
        r'\.post\([^)]+\)',
        r'href="[^"]*"',
        r"href='[^']*'"
    ]
    
    potential_endpoints = []
    
    for pattern in api_patterns:
        matches = re.findall(pattern, html_content)
        for match in matches:
            clean_match = match.strip("'\"(),")
            # Filter out common false positives
            if "/api/" in clean_match or "http" in clean_match:
                potential_endpoints.append(clean_match)
    
    return list(set(potential_endpoints))  # Remove duplicates

def crawl_website(url, max_depth=2, current_depth=0, visited=None):
    """Crawl website to identify all pages and endpoints."""
    if visited is None:
        visited = set()
        
    if current_depth > max_depth:
        return visited
        
    if url in visited or not is_valid_url(url):
        return visited
        
    try:
        logging.info(f"Crawling: {url}")
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Only crawl URLs within the same domain
        if not url.startswith(base_url):
            return visited
            
        response = requests.get(url, timeout=10)
        visited.add(url)
        
        if 'text/html' not in response.headers.get('Content-Type', ''):
            return visited
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all links on the page
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            # Skip anchors, javascript, etc.
            if href.startswith('#') or href.startswith('javascript:'):
                continue
                
            # Resolve relative URLs
            if not href.startswith(('http://', 'https://')):
                href = urljoin(url, href)
                
            # Only follow links to the same domain
            if href.startswith(base_url) and href not in visited:
                crawl_website(href, max_depth, current_depth + 1, visited)
                
    except Exception as e:
        logging.error(f"Error crawling {url}: {str(e)}")
        
    return visited

def map_attack_surface(target, crawl_depth=2, endpoints_only=False):
    """
    Map the attack surface of a target website.
    """
    if not target:
        return {'error': 'No target specified'}
        
    if not is_valid_url(target):
        # Try adding http:// prefix if missing
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
            
        if not is_valid_url(target):
            return {'error': 'Invalid URL format'}
    
    logging.info(f"Starting attack surface mapping for {target}")
    
    # Initialize results
    results = {
        'target': target,
        'timestamp': datetime.datetime.now().isoformat(),
        'pages': [],
        'forms': [],
        'endpoints': [],
        'javascript_endpoints': [],
        'authentication_mechanisms': []
    }
    
    try:
        # Crawl the website
        visited_pages = crawl_website(target, crawl_depth)
        
        # Collect details for each page
        for page_url in visited_pages:
            page_info = {'url': page_url, 'inputs': []}
            
            try:
                response = requests.get(page_url, timeout=10)
                
                # Check for authentication mechanisms
                auth_headers = [h for h in response.headers if h.lower() in 
                               ('www-authenticate', 'authorization', 'set-cookie')]
                                
                if auth_headers:
                    for header in auth_headers:
                        if header not in results['authentication_mechanisms']:
                            results['authentication_mechanisms'].append({
                                'page': page_url, 
                                'type': header, 
                                'value': response.headers[header]
                            })
                
                # Extract form inputs
                if 'text/html' in response.headers.get('Content-Type', ''):
                    page_info['inputs'] = extract_input_fields(response.text, page_url)
                    results['forms'].extend(page_info['inputs'])
                    
                    # Extract potential API endpoints from JavaScript
                    js_endpoints = extract_javascript_endpoints(response.text)
                    if js_endpoints:
                        results['javascript_endpoints'].extend(js_endpoints)
                        
            except Exception as e:
                logging.error(f"Error analyzing page {page_url}: {str(e)}")
                page_info['error'] = str(e)
                
            results['pages'].append(page_info)
                
        # Look for API endpoints in page patterns
        for page in results['pages']:
            url_path = urlparse(page['url']).path
            if ('/api/' in url_path or 
                '/v1/' in url_path or 
                '/v2/' in url_path or
                '/rest/' in url_path or
                '/json/' in url_path):
                
                results['endpoints'].append({
                    'url': page['url'],
                    'type': 'API endpoint'
                })
                
        # If endpoints_only is True, simplify the results
        if endpoints_only:
            results = {
                'target': target,
                'timestamp': results['timestamp'],
                'endpoints': results['endpoints'],
                'javascript_endpoints': results['javascript_endpoints'],
                'forms': results['forms']
            }
            
    except Exception as e:
        logging.error(f"Error in attack surface mapping: {str(e)}")
        results['error'] = str(e)
        
    return results
