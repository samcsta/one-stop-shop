"""
Basic Scanner implementation with the following capabilities:
1. Check if site is active
2. Detect technologies/software running on the site
3. Determine Version Info of Software
4. Check if software is outdated and vulnerable
5. Look for sensitive data/API keys leaked
6. Analyze HTTP Headers
7. Locate and detect main.js file
"""

import os
import json
import re
import socket
import requests
import time
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from flask import current_app
from models import db, Domain, Technology, Vulnerability, Endpoint

# Initialize socketio as None - it will be set from app.py
socketio = None

def init_socketio(socket_instance):
    """Initialize the socketio reference from app.py"""
    global socketio
    socketio = socket_instance

def emit_scan_update(scan_id, message, status="info", data=None):
    """Emit a scan update via websockets for real-time terminal updates"""
    if socketio:
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'message': message,
            'status': status,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
    
    # Also print to console for debugging
    print(f"[{scan_id}] [{status}] {message}")

def basic_scan(url, scan_id=None):
    """
    Perform a basic scan that checks:
    1. If site is active
    2. Technologies/software running on the site
    3. Version info and vulnerability checks
    4. HTTP header analysis
    5. Locate main.js files
    """
    # Generate scan ID if none provided
    if scan_id is None:
        scan_id = f"basic_scan_{int(time.time())}"
    
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    domain_name = url.split('//')[-1].split('/')[0]
    
    emit_scan_update(scan_id, f"Starting basic scan for {url}", "info")
    
    # Check if domain exists in database
    domain = Domain.query.filter_by(url=domain_name).first()
    if not domain:
        domain = Domain(url=domain_name)
        db.session.add(domain)
        db.session.commit()
        emit_scan_update(scan_id, f"Added new domain {domain_name} to database", "info")
    
    # Initialize results dictionary
    result = {
        'domain': domain_name,
        'status': 'UNKNOWN',
        'technologies': [],
        'http_headers': {},
        'vulnerabilities': [],
        'endpoints': [],
        'mainjs_found': False,
        'mainjs_url': None,
        'version_info': {}
    }
    
    # Step 1: Check if site is active
    emit_scan_update(scan_id, f"Step 1: Checking if site is active...", "info")
    is_active = check_site_active(url, scan_id)
    
    domain.status = 'ACTIVE' if is_active else 'INACTIVE'
    domain.last_scanned = datetime.utcnow()
    db.session.commit()
    
    result['status'] = domain.status
    
    if not is_active:
        emit_scan_update(scan_id, f"Site is inactive. Basic scan completed.", "warning")
        return result
    
    # Step 2: Detect technologies
    emit_scan_update(scan_id, f"Step 2: Detecting technologies...", "info")
    
    try:
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        
        # Display HTTP status code
        emit_scan_update(scan_id, f"HTTP Status Code: {response.status_code}", 
                       "success" if response.status_code < 400 else "warning")
        
        # Save HTTP headers for analysis
        result['http_headers'] = dict(response.headers)
        
        # Check for security headers
        security_headers = analyze_security_headers(response.headers)
        result['security_headers'] = security_headers
        
        for header, status in security_headers.items():
            emit_scan_update(scan_id, f"Security header '{header}': {status['status']}", 
                           "success" if status['status'] == "Present" else "warning")
        
        # Detect technologies
        detect_technologies(response, domain, scan_id)
        result['technologies'] = [t.name for t in domain.technologies]
        
        # Check for version info and vulnerabilities
        version_info, vulnerabilities = analyze_version_info(response, result['technologies'], scan_id)
        result['version_info'] = version_info
        
        # Add vulnerabilities to the database and results
        for vuln_data in vulnerabilities:
            vuln = add_vulnerability(
                domain,
                vuln_data['title'],
                vuln_data['description'],
                vuln_data['severity'],
                vuln_data.get('cwe'),
                vuln_data.get('cve'),
                url,
                vuln_data.get('evidence', '')
            )
            result['vulnerabilities'].append(vuln.title)
            
            emit_scan_update(
                scan_id, 
                f"Detected vulnerability: {vuln.title} ({vuln.severity})", 
                "warning" if vuln.severity in ['CRITICAL', 'HIGH'] else "info"
            )
    
    except Exception as e:
        emit_scan_update(scan_id, f"Error during technology detection: {str(e)}", "error")
    
    # Step 3: Find JavaScript files, especially main.js
    emit_scan_update(scan_id, f"Step 3: Locating JavaScript files...", "info")
    js_files = find_js_files(url, scan_id)
    
    # Add endpoints to the database and results
    for js_url in js_files:
        path = urlparse(js_url).path
        
        # Check endpoint status
        status_code, content_type = check_endpoint_status(js_url, scan_id)
        
        endpoint = add_endpoint(
            domain, 
            js_url, 
            path,
            status_code=status_code,
            content_type=content_type
        )
        
        # Check if it's a main.js file
        if (re.search(r'main\.[^.]*\.js$', js_url.lower()) or
            re.search(r'main\.js$', js_url.lower()) or
            re.search(r'app\.[^.]*\.js$', js_url.lower())):
            emit_scan_update(scan_id, f"Found main.js file: {js_url}", "success")
            result['mainjs_found'] = True
            result['mainjs_url'] = js_url
            
            # Mark as interesting in database
            endpoint.is_interesting = True
            db.session.commit()
    
    emit_scan_update(scan_id, f"Basic scan completed for {url}", "success")
    return result

def check_site_active(url, scan_id):
    """Check if a site is active by making HTTP requests"""
    emit_scan_update(scan_id, f"Testing connection to {url}...", "info")
    
    try:
        # Disable SSL warnings
        requests.packages.urllib3.disable_warnings()
        
        # Try HTTPS first
        emit_scan_update(scan_id, f"Attempting HTTPS connection...", "debug")
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        
        emit_scan_update(
            scan_id, 
            f"Received response: HTTP {response.status_code} ({len(response.content)} bytes)", 
            "debug"
        )
        
        if response.status_code < 400:
            emit_scan_update(scan_id, f"Site is active (HTTP {response.status_code})", "success")
            return True
        elif response.status_code == 403:
            # If we get a 403, the site is technically active but forbidden
            emit_scan_update(scan_id, f"Site returned 403 Forbidden - considered active but access restricted", "warning")
            return True
        else:
            # Try HTTP if HTTPS failed with a 4xx/5xx error
            if url.startswith('https://'):
                http_url = url.replace('https://', 'http://', 1)
                emit_scan_update(scan_id, f"HTTPS failed, trying HTTP: {http_url}", "debug")
                
                try:
                    http_response = requests.get(http_url, timeout=10, verify=False, allow_redirects=True)
                    emit_scan_update(
                        scan_id, 
                        f"HTTP response: HTTP {http_response.status_code} ({len(http_response.content)} bytes)", 
                        "debug"
                    )
                    
                    if http_response.status_code < 400:
                        emit_scan_update(scan_id, f"Site is active on HTTP (status {http_response.status_code})", "success")
                        return True
                except:
                    pass
            
            emit_scan_update(scan_id, f"Site returned error status {response.status_code}", "warning")
            return False
        
    except requests.exceptions.ConnectionError:
        emit_scan_update(scan_id, f"Connection error - site appears to be down or unreachable", "error")
        return False
    except requests.exceptions.Timeout:
        emit_scan_update(scan_id, f"Connection timed out - site may be slow or unresponsive", "error")
        return False
    except requests.exceptions.TooManyRedirects:
        emit_scan_update(scan_id, f"Too many redirects - possible redirect loop", "error")
        return False
    except requests.exceptions.RequestException as e:
        emit_scan_update(scan_id, f"Request error: {str(e)}", "error")
        return False

def detect_technologies(response, domain, scan_id=None):
    """Detect technologies from HTTP response headers and body"""
    if scan_id:
        emit_scan_update(scan_id, f"Detecting technologies from response...", "info")
    
    # Server header
    if 'Server' in response.headers:
        server = response.headers['Server']
        add_technology(domain, server)
        if scan_id:
            emit_scan_update(scan_id, f"Detected server: {server}", "info")
    
    # X-Powered-By header
    if 'X-Powered-By' in response.headers:
        powered_by = response.headers['X-Powered-By']
        add_technology(domain, powered_by)
        if scan_id:
            emit_scan_update(scan_id, f"Detected X-Powered-By: {powered_by}", "info")
    
    # Check response body for common technology signatures
    body = response.text.lower()
    
    # WordPress
    if 'wp-content' in body or 'wp-includes' in body:
        # Try to extract WordPress version
        wp_version_match = re.search(r'<meta\s+name=["\']generator["\'].+WordPress\s+([0-9.]+)', response.text)
        if wp_version_match:
            version = wp_version_match.group(1)
            add_technology(domain, f"WordPress {version}", version)
            if scan_id:
                emit_scan_update(scan_id, f"Detected WordPress {version}", "info")
        else:
            add_technology(domain, "WordPress")
            if scan_id:
                emit_scan_update(scan_id, f"Detected WordPress (unknown version)", "info")
    
    # jQuery
    jquery_match = re.search(r'jquery[.-]?(\d+\.\d+\.\d+)', body)
    if jquery_match:
        jquery_version = jquery_match.group(1)
        add_technology(domain, f"jQuery {jquery_version}", jquery_version)
        if scan_id:
            emit_scan_update(scan_id, f"Detected jQuery {jquery_version}", "info")
    
    # Bootstrap
    bootstrap_match = re.search(r'bootstrap[.-]?(\d+\.\d+\.\d+)', body)
    if bootstrap_match:
        bootstrap_version = bootstrap_match.group(1)
        add_technology(domain, f"Bootstrap {bootstrap_version}", bootstrap_version)
        if scan_id:
            emit_scan_update(scan_id, f"Detected Bootstrap {bootstrap_version}", "info")
    
    # React
    if 'react' in body:
        react_match = re.search(r'react[.-]?dom[.-]?(\d+\.\d+\.\d+)', body)
        if react_match:
            react_version = react_match.group(1)
            add_technology(domain, f"React {react_version}", react_version)
            if scan_id:
                emit_scan_update(scan_id, f"Detected React {react_version}", "info")
        else:
            add_technology(domain, "React")
            if scan_id:
                emit_scan_update(scan_id, f"Detected React (unknown version)", "info")
    
    # Vue.js
    if 'vue' in body:
        vue_match = re.search(r'vue[.-]?(\d+\.\d+\.\d+)', body)
        if vue_match:
            vue_version = vue_match.group(1)
            add_technology(domain, f"Vue.js {vue_version}", vue_version)
            if scan_id:
                emit_scan_update(scan_id, f"Detected Vue.js {vue_version}", "info")
        else:
            add_technology(domain, "Vue.js")
            if scan_id:
                emit_scan_update(scan_id, f"Detected Vue.js (unknown version)", "info")
    
    # Common frameworks
    tech_signatures = {
        'laravel': 'Laravel',
        'django': 'Django',
        'flask': 'Flask',
        'express': 'Express.js',
        'node.js': 'Node.js',
        'asp.net': 'ASP.NET',
        'ruby on rails': 'Ruby on Rails',
        'drupal': 'Drupal',
        'joomla': 'Joomla',
        'magento': 'Magento',
        'shopify': 'Shopify',
        'angular': 'Angular',
        'next.js': 'Next.js',
        'nuxt.js': 'Nuxt.js',
    }
    
    for signature, tech_name in tech_signatures.items():
        if signature in body:
            add_technology(domain, tech_name)
            if scan_id:
                emit_scan_update(scan_id, f"Detected {tech_name}", "info")

def analyze_security_headers(headers):
    """
    Analyze HTTP security headers and return report
    """
    security_headers = {
        'Strict-Transport-Security': {
            'status': 'Missing',
            'description': 'HSTS forces browsers to use HTTPS',
            'expected': 'max-age=31536000; includeSubDomains'
        },
        'Content-Security-Policy': {
            'status': 'Missing',
            'description': 'CSP helps prevent XSS attacks',
            'expected': 'Policy that restricts content sources'
        },
        'X-Content-Type-Options': {
            'status': 'Missing',
            'description': 'Prevents MIME type sniffing',
            'expected': 'nosniff'
        },
        'X-Frame-Options': {
            'status': 'Missing',
            'description': 'Protects against clickjacking',
            'expected': 'DENY or SAMEORIGIN'
        },
        'X-XSS-Protection': {
            'status': 'Missing',
            'description': 'Some XSS protection in older browsers',
            'expected': '1; mode=block'
        },
        'Referrer-Policy': {
            'status': 'Missing',
            'description': 'Controls information in the Referer header',
            'expected': 'strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'status': 'Missing',
            'description': 'Controls browser features',
            'expected': 'Restrictive policy'
        }
    }
    
    # Check each security header
    for header, info in security_headers.items():
        header_lower = header.lower()
        
        # Look for header (case-insensitive)
        found = False
        for h in headers:
            if h.lower() == header_lower:
                security_headers[header]['status'] = 'Present'
                security_headers[header]['value'] = headers[h]
                found = True
                break
        
        if not found:
            security_headers[header]['value'] = None
    
    return security_headers

def analyze_version_info(response, technologies, scan_id):
    """
    Analyze version information and check for known vulnerabilities
    """
    version_info = {}
    vulnerabilities = []
    
    # Extract version info from technologies
    for tech in technologies:
        # Parse version from tech name (e.g. "jQuery 1.12.4" -> version: "1.12.4")
        version_match = re.search(r'(.+?)\s+(\d+\.\d+\.?\d*)', tech)
        if version_match:
            tech_name = version_match.group(1).strip()
            version = version_match.group(2).strip()
            version_info[tech_name] = version
            
            # Check for known vulnerable versions
            if tech_name == 'jQuery' and version.startswith(('1.', '2.')):
                if parse_version(version) < parse_version('3.0.0'):
                    vulnerabilities.append({
                        'title': f'Outdated jQuery version ({version})',
                        'description': f'jQuery version {version} is outdated and may contain known security vulnerabilities. Consider upgrading to jQuery 3.x or later.',
                        'severity': 'MEDIUM',
                        'cwe': 'CWE-1035',  # Using vulnerable component
                        'evidence': f'Detected jQuery version: {version}'
                    })
                    emit_scan_update(scan_id, f"Detected outdated jQuery version {version}", "warning")
            
            elif tech_name == 'Bootstrap' and version.startswith(('2.', '3.')):
                if parse_version(version) < parse_version('4.0.0'):
                    vulnerabilities.append({
                        'title': f'Outdated Bootstrap version ({version})',
                        'description': f'Bootstrap version {version} is outdated and may contain known security vulnerabilities. Consider upgrading to Bootstrap 4.x or later.',
                        'severity': 'LOW',
                        'evidence': f'Detected Bootstrap version: {version}'
                    })
                    emit_scan_update(scan_id, f"Detected outdated Bootstrap version {version}", "info")
            
            elif tech_name == 'WordPress':
                wp_latest = '5.9'  # Would be better to fetch this dynamically
                if parse_version(version) < parse_version(wp_latest):
                    vulnerabilities.append({
                        'title': f'Outdated WordPress version ({version})',
                        'description': f'WordPress version {version} is outdated and may contain known security vulnerabilities. Consider upgrading to version {wp_latest} or later.',
                        'severity': 'HIGH',
                        'cwe': 'CWE-1035',  # Using vulnerable component
                        'evidence': f'Detected WordPress version: {version}'
                    })
                    emit_scan_update(scan_id, f"Detected outdated WordPress version {version}", "high")
    
    # Look for possible API keys and tokens in the page content
    api_key_patterns = [
        (r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'API Key'),
        (r'(?i)access[_-]?token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Access Token'),
        (r'(?i)auth[_-]?token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Auth Token'),
        (r'(?i)secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Secret Key'),
        (r'(?i)password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'Password')
    ]
    
    for pattern, key_type in api_key_patterns:
        matches = re.findall(pattern, response.text)
        for match in matches:
            # Skip if it's obviously a placeholder
            if re.search(r'YOUR_|XXXX|example|placeholder|demo', match, re.IGNORECASE):
                continue
                
            vulnerabilities.append({
                'title': f'Potential {key_type} Exposure',
                'description': f'A possible {key_type.lower()} was found in the page source. This may represent a security risk if it is a real credential.',
                'severity': 'HIGH',
                'cwe': 'CWE-312',  # Cleartext Storage of Sensitive Information
                'evidence': f'Found potential {key_type.lower()}: {match[:5]}...[redacted]'
            })
            emit_scan_update(scan_id, f"Potential {key_type} detected in source", "high")
    
    return version_info, vulnerabilities

def find_js_files(url, scan_id=None):
    """
    Find JavaScript files on the page, especially main.js variations
    """
    js_files = []
    
    try:
        # Get the main page content
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        
        if response.status_code >= 400:
            if scan_id:
                emit_scan_update(scan_id, f"Error accessing {url}: HTTP {response.status_code}", "error")
            return js_files
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find script tags with src attribute
        for script in soup.find_all('script', src=True):
            script_url = script['src']
            
            # Convert relative URLs to absolute
            if not script_url.startswith(('http://', 'https://')):
                script_url = urljoin(url, script_url)
            
            js_files.append(script_url)
            
            # Check for main.js with improved regex that matches patterns like main.239507234.js
            if re.search(r'main\.[^.]*\.js$', script_url.lower()) or re.search(r'main\.js$', script_url.lower()) or re.search(r'app\.[^.]*\.js$', script_url.lower()):
                if scan_id:
                    emit_scan_update(scan_id, f"Found main JavaScript file: {script_url}", "success")
            else:
                if scan_id:
                    emit_scan_update(scan_id, f"Found JavaScript file: {script_url}", "info")
        
        if scan_id:
            emit_scan_update(scan_id, f"Found {len(js_files)} JavaScript files", "info")
        
    except Exception as e:
        if scan_id:
            emit_scan_update(scan_id, f"Error finding JavaScript files: {str(e)}", "error")
    
    return js_files

def check_endpoint_status(endpoint_url, scan_id=None):
    """Check the HTTP status code of an endpoint"""
    try:
        requests.packages.urllib3.disable_warnings()
        response = requests.head(endpoint_url, timeout=5, verify=False, allow_redirects=True)
        status_code = response.status_code
        content_type = response.headers.get('Content-Type', 'Unknown')
        
        if scan_id:
            status_class = ""
            if status_code == 200:
                status_class = "success"
                message = f"Endpoint accessible: {endpoint_url} (HTTP 200 OK)"
            elif status_code in (401, 403):
                status_class = "warning"
                message = f"Endpoint protected: {endpoint_url} (HTTP {status_code})"
            else:
                status_class = "info"
                message = f"Endpoint status: {endpoint_url} (HTTP {status_code})"
            
            emit_scan_update(scan_id, message, status_class)
        
        return status_code, content_type
    except Exception as e:
        if scan_id:
            emit_scan_update(scan_id, f"Error checking endpoint {endpoint_url}: {str(e)}", "error")
        return None, None

def analyze_mainjs_file(js_url, scan_id=None):
    """
    Analyze main.js file for interesting endpoints, keys, etc.
    """
    results = {
        'api_endpoints': [],
        'router_links': [],
        'potential_secrets': [],
        'content': ''
    }
    
    try:
        # Fetch the JavaScript file
        requests.packages.urllib3.disable_warnings()
        response = requests.get(js_url, timeout=10, verify=False)
        
        if response.status_code >= 400:
            if scan_id:
                emit_scan_update(scan_id, f"Error accessing {js_url}: HTTP {response.status_code}", "error")
            return results
        
        # Store the content
        js_content = response.text
        results['content'] = js_content
        
        # Look for API endpoints
        api_patterns = [
            r'url:\s*[\'"]([^\'"]*)[\'"]',
            r'path:\s*[\'"]([^\'"]*)[\'"]',
            r'api[\'"]?:\s*[\'"]([^\'"]*)[\'"]',
            r'endpoint[\'"]?:\s*[\'"]([^\'"]*)[\'"]',
            r'fetch\([\'"]([^\'"]*)[\'"]',
            r'axios\.[a-z]+\([\'"]([^\'"]*)[\'"]',
            r'ajax\([\'"]([^\'"]*)[\'"]',
            r'\.get\([\'"]([^\'"]*)[\'"]',
            r'\.post\([\'"]([^\'"]*)[\'"]',
            r'\.put\([\'"]([^\'"]*)[\'"]',
            r'\.delete\([\'"]([^\'"]*)[\'"]'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match and match not in results['api_endpoints']:
                    # Only add actual API endpoints (not HTML files, images, etc.)
                    if not match.endswith(('.html', '.jpg', '.png', '.gif', '.css', '.js')):
                        results['api_endpoints'].append(match)
                        if scan_id:
                            emit_scan_update(scan_id, f"Found API endpoint: {match}", "info")
        
        # Look for router links
        router_patterns = [
            r'route[\'"]?:\s*[\'"]([^\'"]*)[\'"]',
            r'path[\'"]?:\s*[\'"]([^\'"]*)[\'"]',
            r'component:\s*[\'"]([^\'"]*)[\'"]',
            r'Route\s+path=[\'"]([^\'"]*)[\'"]',
            r'[\'"]route[\'"]:\s*[\'"]([^\'"]*)[\'"]',
            r'routes\[[\'"]([^\'"]*)[\'"]'
        ]
        
        for pattern in router_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if match and match not in results['router_links']:
                    results['router_links'].append(match)
                    if scan_id:
                        emit_scan_update(scan_id, f"Found router link: {match}", "info")
        
        # Look for potential secrets
        secret_patterns = [
            (r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'API Key'),
            (r'(?i)access[_-]?token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Access Token'),
            (r'(?i)auth[_-]?token["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Auth Token'),
            (r'(?i)secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']', 'Secret Key'),
            (r'(?i)password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'Password')
        ]
        
        for pattern, key_type in secret_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                # Skip if it's obviously a placeholder
                if re.search(r'YOUR_|XXXX|example|placeholder|demo', match, re.IGNORECASE):
                    continue
                    
                # Add to results with first few chars and redacted suffix
                secret_info = {
                    'type': key_type,
                    'preview': match[:5] + '...[redacted]',
                    'line': find_line_number(js_content, match)
                }
                results['potential_secrets'].append(secret_info)
                
                if scan_id:
                    emit_scan_update(
                        scan_id, 
                        f"Found potential {key_type} at line {secret_info['line']}: {secret_info['preview']}", 
                        "warning"
                    )
        
    except Exception as e:
        if scan_id:
            emit_scan_update(scan_id, f"Error analyzing main.js: {str(e)}", "error")
    
    return results

def find_line_number(content, substring):
    """
    Find the line number where a substring appears in content
    """
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if substring in line:
            return i + 1
    return -1

def add_technology(domain, tech_name, version=''):
    """Add technology to domain if it doesn't exist"""
    # Clean tech name
    tech_name = tech_name.strip()
    if not tech_name:
        return
        
    tech = Technology.query.filter_by(name=tech_name).first()
    if not tech:
        tech = Technology(name=tech_name, version=version)
        db.session.add(tech)
    
    if tech not in domain.technologies:
        domain.technologies.append(tech)

def add_vulnerability(domain, title, description, severity, cwe, cve, location, evidence):
    """Add a vulnerability to the database if it doesn't exist"""
    existing_vuln = Vulnerability.query.filter_by(
        domain_id=domain.id,
        title=title,
        location=location
    ).first()
    
    if not existing_vuln:
        vuln = Vulnerability(
            domain_id=domain.id,
            title=title,
            description=description,
            severity=severity,
            cwe=cwe,
            cve=cve,
            location=location,
            evidence=evidence,
            date_discovered=datetime.utcnow()
        )
        db.session.add(vuln)
        db.session.commit()
        return vuln
    
    return existing_vuln

def add_endpoint(domain, url, path, is_interesting=False, status_code=None, content_type=None):
    """Add an endpoint to the database if it doesn't exist"""
    existing_endpoint = Endpoint.query.filter_by(
        domain_id=domain.id,
        url=url
    ).first()
    
    if not existing_endpoint:
        endpoint = Endpoint(
            domain_id=domain.id,
            url=url,
            path=path,
            status_code=status_code,
            content_type=content_type,
            is_interesting=is_interesting,
            date_discovered=datetime.utcnow(),
            last_checked=datetime.utcnow()
        )
        db.session.add(endpoint)
        db.session.commit()
        return endpoint
    
    return existing_endpoint

def parse_version(version_string):
    """
    Parse version string to comparable parts
    """
    parts = version_string.split('.')
    result = []
    for part in parts:
        try:
            result.append(int(part))
        except ValueError:
            # Handle non-numeric parts (e.g., "1.0.0-beta")
            match = re.match(r'(\d+)(.*)', part)
            if match:
                result.append(int(match.group(1)))
            else:
                result.append(0)
    
    # Pad with zeros to ensure comparison works with different version lengths
    while len(result) < 3:
        result.append(0)
        
    return tuple(result)