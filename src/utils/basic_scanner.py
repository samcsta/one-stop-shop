"""
Enhanced Vulnerability Scanner

A comprehensive vulnerability scanner with the following capabilities:
1. Outdated software versions detection
2. Technology detection with versions
3. Secrets/API key exposure identification
4. CVE detection with CVSS scoring
5. CWE risk classification
6. HTTP/HTTPS accessibility checking
7. Status code categorization
8. Server header analysis
9. Technology stack identification
10. Framework vulnerability detection
11. Authentication bypass testing
12. Angular app detection
13. HTTP method testing
14. API endpoint discovery
15. Security header validation
16. CORS configuration testing
17. Content Security Policy verification
18. Source code pattern matching
19. JavaScript framework vulnerabilities
20. Header manipulation for auth bypass
"""

import os
import json
import re
import time
import socket
import subprocess
import tempfile
import random
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from bs4 import BeautifulSoup
from flask import current_app
from models import db, Domain, Technology, Vulnerability, Endpoint

# Initialize socketio as None - will be set from app.py
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

# ===== CORE SCANNER FUNCTION =====

def enhanced_scan(url, scan_id=None, options=None):
    """
    Perform a comprehensive scan with all features:
    - Site accessibility check
    - Technology detection with versions
    - Security headers analysis
    - Vulnerability detection
    - Authentication bypass testing
    - API endpoint discovery
    - Source code analysis
    """
    # Default scan options
    default_options = {
        'check_versions': True,
        'detect_tech': True,
        'find_vulnerabilities': True,
        'test_auth_bypass': True,
        'discover_endpoints': True,
        'analyze_js': True,
        'test_cors': True,
        'check_headers': True,
        'scan_depth': 'medium'  # options: light, medium, deep
    }
    
    # Use provided options or defaults
    scan_options = default_options
    if options:
        scan_options.update(options)
    
    # Generate scan ID if none provided
    if scan_id is None:
        scan_id = f"enhanced_scan_{int(time.time())}"
    
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    domain_name = url.split('//')[-1].split('/')[0]
    
    emit_scan_update(scan_id, f"Starting enhanced scan for {url}", "info")
    
    # Check if domain exists in database or create it
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
        'vulnerabilities': [],
        'endpoints': [],
        'security_headers': {},
        'has_403_error': False
    }
    
    # Phase 1: Check if site is active
    emit_scan_update(scan_id, f"Phase 1: Checking if site is active...", "info")
    site_status, response = check_site_active(url, scan_id)
    
    # Update domain status
    domain.status = 'ACTIVE' if site_status else 'INACTIVE'
    domain.last_scanned = datetime.utcnow()
    db.session.commit()
    
    result['status'] = domain.status
    
    # Only proceed if site is active
    if not site_status:
        emit_scan_update(scan_id, f"Site is inactive. Enhanced scan completed.", "warning")
        return result
    
    # Phase 2: Security header analysis
    if scan_options['check_headers']:
        emit_scan_update(scan_id, f"Phase 2: Analyzing security headers...", "info")
        security_headers = analyze_security_headers(response.headers, scan_id)
        result['security_headers'] = security_headers
        
        # Check for missing security headers and add vulnerabilities
        for header, info in security_headers.items():
            if info['status'] == 'Missing' and info['importance'] in ['critical', 'high']:
                add_security_header_vulnerability(domain, header, info, scan_id)
    
    # Phase 3: Technology detection
    if scan_options['detect_tech']:
        emit_scan_update(scan_id, f"Phase 3: Detecting technologies...", "info")
        technologies = detect_technologies(response, domain, scan_id)
        result['technologies'] = [t.name for t in domain.technologies]
        
        # Check for outdated software versions
        if scan_options['check_versions']:
            emit_scan_update(scan_id, f"Checking for outdated software versions...", "info")
            check_outdated_software(domain, technologies, scan_id)
    
    # Phase 4: Security vulnerabilities scan
    if scan_options['find_vulnerabilities']:
        emit_scan_update(scan_id, f"Phase 4: Checking for known vulnerabilities...", "info")
        vulnerabilities = find_vulnerabilities(domain, response, url, scan_id)
        result['vulnerabilities'] = [v.title for v in vulnerabilities]
    
    # Phase 5: API endpoint discovery
    if scan_options['discover_endpoints']:
        emit_scan_update(scan_id, f"Phase 5: Discovering API endpoints...", "info")
        discovered_endpoints = discover_endpoints(url, domain, scan_id)
        result['endpoints'] = [e.url for e in discovered_endpoints]
        
        # Test for 403 errors on discovered endpoints
        has_403 = False
        for endpoint in discovered_endpoints:
            if endpoint.status_code == 403:
                has_403 = True
                break
        result['has_403_error'] = has_403
    
    # Phase 6: JavaScript analysis
    if scan_options['analyze_js']:
        emit_scan_update(scan_id, f"Phase 6: Analyzing JavaScript files...", "info")
        js_vulnerabilities = analyze_javascript(url, domain, scan_id)
        # Add JavaScript vulnerabilities to result
        for vuln in js_vulnerabilities:
            if vuln.title not in result['vulnerabilities']:
                result['vulnerabilities'].append(vuln.title)
    
    # Phase 7: Authentication bypass testing
    if scan_options['test_auth_bypass'] and result['has_403_error']:
        emit_scan_update(scan_id, f"Phase 7: Testing for authentication bypasses...", "info")
        bypass_results = test_auth_bypass(url, domain, scan_id)
        # Add any auth bypass findings to vulnerabilities
        if bypass_results:
            for bypass in bypass_results:
                if bypass['title'] not in result['vulnerabilities']:
                    result['vulnerabilities'].append(bypass['title'])
    
    # Phase 8: CORS testing
    if scan_options['test_cors']:
        emit_scan_update(scan_id, f"Phase 8: Testing CORS configuration...", "info")
        cors_vulnerabilities = test_cors_configuration(url, domain, scan_id)
        # Add CORS vulnerabilities to result
        for vuln in cors_vulnerabilities:
            if vuln.title not in result['vulnerabilities']:
                result['vulnerabilities'].append(vuln.title)
    
    # Final update
    emit_scan_update(scan_id, f"Enhanced scan completed for {url}", "success")
    
    return result

# ===== SITE ACCESSIBILITY AND HEADER ANALYSIS =====

def check_site_active(url, scan_id):
    """
    Check if a site is active by making HTTP requests
    Returns a tuple of (is_active, response)
    """
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
            return True, response
        elif response.status_code == 403:
            # If we get a 403, the site is technically active but forbidden
            emit_scan_update(scan_id, f"Site returned 403 Forbidden - considered active but access restricted", "warning")
            return True, response
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
                        return True, http_response
                except:
                    pass
            
            emit_scan_update(scan_id, f"Site returned error status {response.status_code}", "warning")
            return False, response
        
    except requests.exceptions.ConnectionError:
        emit_scan_update(scan_id, f"Connection error - site appears to be down or unreachable", "error")
        return False, None
    except requests.exceptions.Timeout:
        emit_scan_update(scan_id, f"Connection timed out - site may be slow or unresponsive", "error")
        return False, None
    except requests.exceptions.TooManyRedirects:
        emit_scan_update(scan_id, f"Too many redirects - possible redirect loop", "error")
        return False, None
    except requests.exceptions.RequestException as e:
        emit_scan_update(scan_id, f"Request error: {str(e)}", "error")
        return False, None

def analyze_security_headers(headers, scan_id=None):
    """
    Comprehensive analysis of HTTP security headers with importance rating and recommendations
    """
    security_headers = {
        'Strict-Transport-Security': {
            'status': 'Missing',
            'description': 'Enforces secure (HTTPS) connections to the server',
            'expected': 'max-age=31536000; includeSubDomains; preload',
            'importance': 'high',
            'cwe': 'CWE-319',
            'recommendation': 'Add HSTS header with a long max-age (1+ year), includeSubDomains, and preload directives'
        },
        'Content-Security-Policy': {
            'status': 'Missing',
            'description': 'Controls resources the browser is allowed to load',
            'expected': 'default-src \'self\'; script-src \'self\'; object-src \'none\'',
            'importance': 'high',
            'cwe': 'CWE-1021',
            'recommendation': 'Implement a strict CSP that defines allowed sources for all resource types'
        },
        'X-Content-Type-Options': {
            'status': 'Missing',
            'description': 'Prevents MIME type sniffing',
            'expected': 'nosniff',
            'importance': 'medium',
            'cwe': 'CWE-430',
            'recommendation': 'Add X-Content-Type-Options header with value "nosniff"'
        },
        'X-Frame-Options': {
            'status': 'Missing',
            'description': 'Protects against clickjacking attacks',
            'expected': 'DENY or SAMEORIGIN',
            'importance': 'high',
            'cwe': 'CWE-1021',
            'recommendation': 'Add X-Frame-Options header with value "DENY" or "SAMEORIGIN"'
        },
        'X-XSS-Protection': {
            'status': 'Missing',
            'description': 'Mitigates Cross-Site Scripting (XSS) attacks',
            'expected': '1; mode=block',
            'importance': 'medium',
            'cwe': 'CWE-79',
            'recommendation': 'Add X-XSS-Protection header with value "1; mode=block"'
        },
        'Referrer-Policy': {
            'status': 'Missing',
            'description': 'Controls how much referrer information should be included with requests',
            'expected': 'strict-origin-when-cross-origin or no-referrer',
            'importance': 'medium',
            'cwe': 'CWE-200',
            'recommendation': 'Add Referrer-Policy header with appropriate restrictive value'
        },
        'Permissions-Policy': {
            'status': 'Missing',
            'description': 'Controls which browser features and APIs can be used',
            'expected': 'camera=(), microphone=(), geolocation=()',
            'importance': 'medium',
            'cwe': 'CWE-693',
            'recommendation': 'Add Permissions-Policy header restricting access to sensitive browser features'
        },
        'Cache-Control': {
            'status': 'Missing',
            'description': 'Directs browsers and proxies how to cache content',
            'expected': 'no-store, max-age=0',
            'importance': 'medium',
            'cwe': 'CWE-524',
            'recommendation': 'Add Cache-Control header to prevent caching of sensitive information'
        },
        'Cross-Origin-Resource-Policy': {
            'status': 'Missing',
            'description': 'Prevents other domains from loading resources',
            'expected': 'same-origin',
            'importance': 'medium',
            'cwe': 'CWE-346',
            'recommendation': 'Add Cross-Origin-Resource-Policy header with value "same-origin"'
        },
        'Cross-Origin-Opener-Policy': {
            'status': 'Missing',
            'description': 'Controls if a window can communicate with cross-origin tabs',
            'expected': 'same-origin',
            'importance': 'medium',
            'cwe': 'CWE-346',
            'recommendation': 'Add Cross-Origin-Opener-Policy header with value "same-origin"'
        },
        'Cross-Origin-Embedder-Policy': {
            'status': 'Missing',
            'description': 'Controls which cross-origin resources can be loaded',
            'expected': 'require-corp',
            'importance': 'medium',
            'cwe': 'CWE-346',
            'recommendation': 'Add Cross-Origin-Embedder-Policy header with value "require-corp"'
        }
    }
    
    # Check each security header
    for header, info in security_headers.items():
        header_lower = header.lower()
        
        # Look for header (case-insensitive)
        found = False
        for h in headers:
            if h.lower() == header_lower:
                value = headers[h]
                security_headers[header]['status'] = 'Present'
                security_headers[header]['value'] = value
                
                # Analyze if the value is secure
                if header == 'Strict-Transport-Security':
                    if 'max-age=' in value.lower():
                        try:
                            max_age = int(re.search(r'max-age=(\d+)', value.lower()).group(1))
                            if max_age < 31536000:  # Less than a year
                                security_headers[header]['status'] = 'Weak'
                                security_headers[header]['issue'] = 'max-age is less than 1 year'
                        except (AttributeError, ValueError):
                            security_headers[header]['status'] = 'Weak'
                            security_headers[header]['issue'] = 'Invalid max-age value'
                    
                    if 'includesubdomains' not in value.lower():
                        if security_headers[header]['status'] == 'Present':
                            security_headers[header]['status'] = 'Weak'
                        security_headers[header]['issue'] = 'Missing includeSubDomains directive'
                
                elif header == 'Content-Security-Policy':
                    # Check if unsafe-inline is used
                    if 'unsafe-inline' in value:
                        security_headers[header]['status'] = 'Weak'
                        security_headers[header]['issue'] = 'Uses unsafe-inline directive'
                    
                    # Check if CSP uses unsafe-eval
                    if 'unsafe-eval' in value:
                        security_headers[header]['status'] = 'Weak'
                        security_headers[header]['issue'] = 'Uses unsafe-eval directive'
                
                elif header == 'X-Frame-Options':
                    if value.upper() not in ['DENY', 'SAMEORIGIN']:
                        security_headers[header]['status'] = 'Weak'
                        security_headers[header]['issue'] = f'Value "{value}" is not recommended'
                
                found = True
                break
        
        if not found:
            security_headers[header]['value'] = None
    
    # Log header findings
    if scan_id:
        for header, info in security_headers.items():
            if info['status'] == 'Missing':
                if info['importance'] == 'high':
                    emit_scan_update(scan_id, f"Missing critical security header: {header}", "warning")
                else:
                    emit_scan_update(scan_id, f"Missing security header: {header}", "info")
            elif info['status'] == 'Weak':
                emit_scan_update(scan_id, f"Weak security header: {header} - {info['issue']}", "warning")
            else:
                emit_scan_update(scan_id, f"Security header present: {header}", "success")
    
    return security_headers

def add_security_header_vulnerability(domain, header_name, header_info, scan_id=None):
    """Add a vulnerability for a missing security header"""
    # Create vulnerability title
    title = f"Missing {header_name} Security Header"
    
    # Check if this vulnerability already exists
    existing_vuln = Vulnerability.query.filter_by(
        domain_id=domain.id,
        title=title
    ).first()
    
    if not existing_vuln:
        # Assign severity based on importance
        if header_info['importance'] == 'critical':
            severity = 'HIGH'
        elif header_info['importance'] == 'high':
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        # Create detailed description
        description = f"""The {header_name} security header is missing from the HTTP response.
        
Description: {header_info['description']}
Expected value: {header_info['expected']}
        
Recommendation: {header_info['recommendation']}"""
        
        # Add the vulnerability
        vuln = Vulnerability(
            domain_id=domain.id,
            title=title,
            description=description,
            severity=severity,
            cwe=header_info.get('cwe'),
            location=domain.url,
            evidence=f"Header not found in HTTP response",
            date_discovered=datetime.utcnow()
        )
        
        db.session.add(vuln)
        db.session.commit()
        
        if scan_id:
            emit_scan_update(
                scan_id,
                f"Added vulnerability: {title} ({severity})",
                "warning" if severity in ['CRITICAL', 'HIGH'] else "info"
            )
        
        return vuln
    
    return existing_vuln

# ===== TECHNOLOGY DETECTION =====

def detect_technologies(response, domain, scan_id=None):
    """
    Enhanced technology detection from HTTP response headers and body
    Returns list of detected technologies
    """
    if scan_id:
        emit_scan_update(scan_id, f"Detecting technologies from response...", "info")
    
    technologies = []
    
    # Server header
    if 'Server' in response.headers:
        server = response.headers['Server']
        tech = add_technology(domain, server)
        technologies.append(tech)
        if scan_id:
            emit_scan_update(scan_id, f"Detected server: {server}", "info")
    
    # X-Powered-By header
    if 'X-Powered-By' in response.headers:
        powered_by = response.headers['X-Powered-By']
        tech = add_technology(domain, powered_by)
        technologies.append(tech)
        if scan_id:
            emit_scan_update(scan_id, f"Detected X-Powered-By: {powered_by}", "info")
    
    # Check for ASP.NET
    if 'X-AspNet-Version' in response.headers:
        aspnet_version = f"ASP.NET {response.headers['X-AspNet-Version']}"
        tech = add_technology(domain, aspnet_version, response.headers['X-AspNet-Version'])
        technologies.append(tech)
        if scan_id:
            emit_scan_update(scan_id, f"Detected {aspnet_version}", "info")
    
    # Check for JSF (JavaServer Faces)
    if 'X-Powered-By' in response.headers and 'JSF' in response.headers['X-Powered-By']:
        jsf_match = re.search(r'JSF/(\d+\.\d+)', response.headers['X-Powered-By'])
        if jsf_match:
            jsf_version = f"JSF {jsf_match.group(1)}"
            tech = add_technology(domain, jsf_version, jsf_match.group(1))
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected {jsf_version}", "info")
    
    # Check for Laravel
    if 'set-cookie' in response.headers and 'laravel_session' in response.headers['set-cookie'].lower():
        tech = add_technology(domain, "Laravel")
        technologies.append(tech)
        if scan_id:
            emit_scan_update(scan_id, f"Detected Laravel", "info")
    
    # Check response body for common technology signatures
    body = response.text.lower()
    
    # WordPress
    if 'wp-content' in body or 'wp-includes' in body:
        # Try to extract WordPress version
        wp_version_match = re.search(r'<meta\s+name=["\']generator["\'].+WordPress\s+([0-9.]+)', response.text)
        if wp_version_match:
            version = wp_version_match.group(1)
            tech = add_technology(domain, f"WordPress", version)
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected WordPress {version}", "info")
        else:
            tech = add_technology(domain, "WordPress")
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected WordPress (unknown version)", "info")
    
    # Drupal
    if 'drupal' in body:
        drupal_version_match = re.search(r'Drupal (\d+\.\d+)', response.text)
        if drupal_version_match:
            version = drupal_version_match.group(1)
            tech = add_technology(domain, "Drupal", version)
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected Drupal {version}", "info")
        else:
            tech = add_technology(domain, "Drupal")
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected Drupal (unknown version)", "info")
    
    # Joomla
    if 'joomla' in body:
        joomla_version_match = re.search(r'Joomla!?\s+(\d+\.\d+)', response.text)
        if joomla_version_match:
            version = joomla_version_match.group(1)
            tech = add_technology(domain, "Joomla", version)
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected Joomla {version}", "info")
        else:
            tech = add_technology(domain, "Joomla")
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected Joomla (unknown version)", "info")
    
    # jQuery
    jquery_match = re.search(r'jquery[.-]?(\d+\.\d+\.\d+)', body)
    if jquery_match:
        jquery_version = jquery_match.group(1)
        tech = add_technology(domain, "jQuery", jquery_version)
        technologies.append(tech)
        if scan_id:
            emit_scan_update(scan_id, f"Detected jQuery {jquery_version}", "info")
    
    # Bootstrap
    bootstrap_match = re.search(r'bootstrap[.-]?(\d+\.\d+\.\d+)', body)
    if bootstrap_match:
        bootstrap_version = bootstrap_match.group(1)
        tech = add_technology(domain, "Bootstrap", bootstrap_version)
        technologies.append(tech)
        if scan_id:
            emit_scan_update(scan_id, f"Detected Bootstrap {bootstrap_version}", "info")
    
    # React
    if 'reactjs' in body or 'react.js' in body or 'react-dom' in body:
        react_match = re.search(r'react[.-]?(\d+\.\d+\.\d+)', body)
        if react_match:
            react_version = react_match.group(1)
            tech = add_technology(domain, "React", react_version)
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected React {react_version}", "info")
        else:
            tech = add_technology(domain, "React")
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected React (unknown version)", "info")
    
    # Vue.js
    if 'vue' in body:
        vue_match = re.search(r'vue[.-]?(\d+\.\d+\.\d+)', body)
        if vue_match:
            vue_version = vue_match.group(1)
            tech = add_technology(domain, "Vue.js", vue_version)
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected Vue.js {vue_version}", "info")
        else:
            tech = add_technology(domain, "Vue.js")
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected Vue.js (unknown version)", "info")
    
    # Angular.js (AngularJS) or Angular 2+
    if 'angular' in body:
        # Check for Angular 2+
        ng_match = re.search(r'angular[/\\](\d+\.\d+\.\d+)', body)
        if ng_match:
            ng_version = ng_match.group(1)
            if ng_version.startswith('1.'):
                tech = add_technology(domain, "AngularJS", ng_version)
                technologies.append(tech)
                if scan_id:
                    emit_scan_update(scan_id, f"Detected AngularJS {ng_version}", "info")
            else:
                tech = add_technology(domain, "Angular", ng_version)
                technologies.append(tech)
                if scan_id:
                    emit_scan_update(scan_id, f"Detected Angular {ng_version}", "info")
        else:
            # Look for Angular component patterns
            if 'ng-app' in body or 'ng-controller' in body:
                tech = add_technology(domain, "AngularJS")
                technologies.append(tech)
                if scan_id:
                    emit_scan_update(scan_id, f"Detected AngularJS (unknown version)", "info")
            elif 'ng-version' in body or '_ng' in body:
                tech = add_technology(domain, "Angular")
                technologies.append(tech)
                if scan_id:
                    emit_scan_update(scan_id, f"Detected Angular (unknown version)", "info")
    
    # Check for Spring Boot
    if 'X-Application-Context' in response.headers:
        tech = add_technology(domain, "Spring Boot")
        technologies.append(tech)
        if scan_id:
            emit_scan_update(scan_id, f"Detected Spring Boot", "info")
    
    # Django
    if 'csrftoken' in response.headers.get('set-cookie', '').lower():
        tech = add_technology(domain, "Django")
        technologies.append(tech)
        if scan_id:
            emit_scan_update(scan_id, f"Detected Django", "info")
    
    # Ruby on Rails
    if '_rails_' in response.headers.get('set-cookie', '').lower():
        tech = add_technology(domain, "Ruby on Rails")
        technologies.append(tech)
        if scan_id:
            emit_scan_update(scan_id, f"Detected Ruby on Rails", "info")
    
    # Express.js
    if 'express' in response.headers.get('X-Powered-By', '').lower():
        tech = add_technology(domain, "Express.js")
        technologies.append(tech)
        if scan_id:
            emit_scan_update(scan_id, f"Detected Express.js", "info")
    
    # PHP
    if 'php' in response.headers.get('X-Powered-By', '').lower():
        php_match = re.search(r'PHP/(\d+\.\d+\.\d+)', response.headers.get('X-Powered-By', ''))
        if php_match:
            php_version = php_match.group(1)
            tech = add_technology(domain, "PHP", php_version)
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected PHP {php_version}", "info")
        else:
            tech = add_technology(domain, "PHP")
            technologies.append(tech)
            if scan_id:
                emit_scan_update(scan_id, f"Detected PHP (unknown version)", "info")
    
    # Web server software
    if 'Server' in response.headers:
        server_header = response.headers['Server']
        # Apache
        if 'apache' in server_header.lower():
            apache_match = re.search(r'Apache/(\d+\.\d+\.\d+)', server_header)
            if apache_match:
                apache_version = apache_match.group(1)
                tech = add_technology(domain, "Apache", apache_version)
                technologies.append(tech)
                if scan_id:
                    emit_scan_update(scan_id, f"Detected Apache {apache_version}", "info")
        
        # Nginx
        elif 'nginx' in server_header.lower():
            nginx_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server_header)
            if nginx_match:
                nginx_version = nginx_match.group(1)
                tech = add_technology(domain, "Nginx", nginx_version)
                technologies.append(tech)
                if scan_id:
                    emit_scan_update(scan_id, f"Detected Nginx {nginx_version}", "info")
        
        # Microsoft IIS
        elif 'iis' in server_header.lower():
            iis_match = re.search(r'IIS/(\d+\.\d+)', server_header)
            if iis_match:
                iis_version = iis_match.group(1)
                tech = add_technology(domain, "Microsoft IIS", iis_version)
                technologies.append(tech)
                if scan_id:
                    emit_scan_update(scan_id, f"Detected Microsoft IIS {iis_version}", "info")
    
    # Check for other common frameworks in body
    common_tech = {
        'laravel': 'Laravel',
        'symfony': 'Symfony',
        'codeigniter': 'CodeIgniter',
        'yii': 'Yii',
        'zend': 'Zend Framework',
        'flask': 'Flask',
        'tornado': 'Tornado',
        'fastapi': 'FastAPI',
        'express': 'Express.js',
        'nextjs': 'Next.js',
        'nuxt': 'Nuxt.js',
        'svelte': 'Svelte',
        'ember': 'Ember.js',
        'backbone': 'Backbone.js',
        'gatsby': 'Gatsby.js',
        'meteor': 'Meteor.js',
        'shopify': 'Shopify',
        'magento': 'Magento',
        'prestashop': 'PrestaShop',
        'woocommerce': 'WooCommerce'
    }
    
    for keyword, tech_name in common_tech.items():
        if keyword in body:
            # Check if we've already detected this technology
            if not any(t.name == tech_name for t in technologies):
                tech = add_technology(domain, tech_name)
                technologies.append(tech)
                if scan_id:
                    emit_scan_update(scan_id, f"Detected {tech_name}", "info")
    
    return technologies

def check_outdated_software(domain, technologies, scan_id=None):
    """Check detected software versions against known outdated versions"""
    
    # Known outdated version data with CVEs and CVSS scores
    outdated_software = {
        'WordPress': {
            'latest': '6.2.3',
            'outdated_versions': {
                '<5.3.0': {
                    'cves': ['CVE-2020-36326', 'CVE-2020-36327'],
                    'cvss': '7.5',
                    'severity': 'HIGH',
                    'cwe': 'CWE-79'
                },
                '<5.9.0': {
                    'cves': ['CVE-2023-1168'],
                    'cvss': '6.1',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-79'
                }
            }
        },
        'jQuery': {
            'latest': '3.7.0',
            'outdated_versions': {
                '<3.0.0': {
                    'cves': ['CVE-2020-11022', 'CVE-2020-11023'],
                    'cvss': '6.1',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-79'
                },
                '<3.5.0': {
                    'cves': ['CVE-2020-11022'],
                    'cvss': '5.4',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-79'
                }
            }
        },
        'Bootstrap': {
            'latest': '5.3.0',
            'outdated_versions': {
                '<4.3.1': {
                    'cves': ['CVE-2019-8331'],
                    'cvss': '6.1',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-79'
                },
                '<3.4.0': {
                    'cves': ['CVE-2019-8331'],
                    'cvss': '7.2',
                    'severity': 'HIGH',
                    'cwe': 'CWE-94'
                }
            }
        },
        'Apache': {
            'latest': '2.4.57',
            'outdated_versions': {
                '<2.4.55': {
                    'cves': ['CVE-2023-27522', 'CVE-2023-25690'],
                    'cvss': '7.5',
                    'severity': 'HIGH',
                    'cwe': 'CWE-444'
                },
                '<2.4.53': {
                    'cves': ['CVE-2022-22720', 'CVE-2022-22721'],
                    'cvss': '9.1',
                    'severity': 'CRITICAL',
                    'cwe': 'CWE-400'
                }
            }
        },
        'Nginx': {
            'latest': '1.25.1',
            'outdated_versions': {
                '<1.22.1': {
                    'cves': ['CVE-2023-44487'],
                    'cvss': '7.5',
                    'severity': 'HIGH',
                    'cwe': 'CWE-400'
                }
            }
        },
        'PHP': {
            'latest': '8.2.8',
            'outdated_versions': {
                '<7.4.0': {
                    'cves': ['CVE-2023-0567', 'CVE-2023-0568'],
                    'cvss': '8.8',
                    'severity': 'HIGH',
                    'cwe': 'CWE-787'
                },
                '<8.0.0': {
                    'cves': ['CVE-2023-0662'],
                    'cvss': '7.5',
                    'severity': 'HIGH',
                    'cwe': 'CWE-22'
                }
            }
        },
        'Django': {
            'latest': '4.2.3',
            'outdated_versions': {
                '<3.2.19': {
                    'cves': ['CVE-2023-36053'],
                    'cvss': '6.5',
                    'severity': 'MEDIUM',
                    'cwe': 'CWE-20'
                }
            }
        },
        'Spring Boot': {
            'latest': '3.1.2',
            'outdated_versions': {
                '<2.7.0': {
                    'cves': ['CVE-2022-22965'],
                    'cvss': '9.8',
                    'severity': 'CRITICAL',
                    'cwe': 'CWE-94'
                }
            }
        }
    }
    
    # Check each technology version against known outdated versions
    for tech in technologies:
        base_name = tech.name.split()[0] if ' ' in tech.name else tech.name
        if base_name in outdated_software and tech.version:
            latest_version = outdated_software[base_name]['latest']
            
            if scan_id:
                emit_scan_update(
                    scan_id, 
                    f"Checking if {base_name} version {tech.version} is outdated (latest: {latest_version})...",
                    "debug"
                )
            
            # Check each outdated version range
            for version_range, vuln_info in outdated_software[base_name]['outdated_versions'].items():
                if is_version_in_range(tech.version, version_range):
                    # Create a vulnerability for this outdated software
                    title = f"Outdated {base_name} Version: {tech.version}"
                    
                    # Build CVE list
                    cve_list = vuln_info.get('cves', [])
                    cve_str = ', '.join(cve_list)
                    
                    # Build detailed description
                    description = f"""The site is running an outdated version of {base_name} ({tech.version}).
                    
Latest version: {latest_version}
CVSS Score: {vuln_info.get('cvss', 'N/A')}
CVEs: {cve_str}
CWE: {vuln_info.get('cwe', 'Unknown')}

This version may be vulnerable to known security issues. Consider upgrading to the latest version.
"""
                    
                    # Add as a vulnerability
                    vuln = add_vulnerability(
                        domain,
                        title,
                        description,
                        vuln_info.get('severity', 'MEDIUM'),
                        vuln_info.get('cwe'),
                        cve_list[0] if cve_list else None,
                        domain.url,
                        f"Detected {base_name} version: {tech.version}"
                    )
                    
                    if scan_id:
                        emit_scan_update(
                            scan_id,
                            f"Vulnerable {base_name} version {tech.version} detected (CVE: {cve_str})",
                            vuln_info.get('severity', 'MEDIUM').lower()
                        )

def is_version_in_range(version, version_range):
    """Check if a version is within a specified range"""
    if not version:
        return False
    
    # Parse version string to tuple of integers
    version_parts = parse_version(version)
    
    # Handle different range formats
    if version_range.startswith('<'):
        # Less than a specific version
        max_version = parse_version(version_range[1:])
        return version_parts < max_version
    elif version_range.startswith('<='):
        # Less than or equal to a specific version
        max_version = parse_version(version_range[2:])
        return version_parts <= max_version
    elif version_range.startswith('>'):
        # Greater than a specific version
        min_version = parse_version(version_range[1:])
        return version_parts > min_version
    elif version_range.startswith('>='):
        # Greater than or equal to a specific version
        min_version = parse_version(version_range[2:])
        return version_parts >= min_version
    elif '-' in version_range:
        # Range between two versions
        min_version, max_version = version_range.split('-')
        return parse_version(min_version) <= version_parts <= parse_version(max_version)
    else:
        # Exact version match
        return parse_version(version_range) == version_parts

def parse_version(version_string):
    """
    Parse version string to comparable tuple of integers
    Handles formats like '1.2.3', '1.2', etc.
    """
    # Handle special case for missing version
    if not version_string:
        return (0, 0, 0)
    
    # Extract numeric parts from version string
    parts = re.findall(r'\d+', version_string)
    result = []
    
    # Convert parts to integers
    for part in parts:
        try:
            result.append(int(part))
        except ValueError:
            result.append(0)
    
    # Pad with zeros to ensure comparison works with different version lengths
    while len(result) < 3:
        result.append(0)
    
    return tuple(result[:3])  # Only use major.minor.patch for comparison

# ===== VULNERABILITY SCANNING =====

def find_vulnerabilities(domain, response, url, scan_id=None):
    """Scan for common vulnerabilities and security issues"""
    vulnerabilities = []
    
    # Check for information disclosure in headers
    if scan_id:
        emit_scan_update(scan_id, "Checking for information disclosure in headers...", "info")
    
    header_vulns = check_header_information_disclosure(domain, response.headers, scan_id)
    vulnerabilities.extend(header_vulns)
    
    # Check for sensitive information in page content
    if scan_id:
        emit_scan_update(scan_id, "Checking for sensitive information in page content...", "info")
    
    content_vulns = check_content_information_disclosure(domain, response.text, url, scan_id)
    vulnerabilities.extend(content_vulns)
    
    # Check for misconfiguration issues
    if scan_id:
        emit_scan_update(scan_id, "Checking for misconfiguration issues...", "info")
    
    misconfig_vulns = check_misconfigurations(domain, response, url, scan_id)
    vulnerabilities.extend(misconfig_vulns)
    
    # Return all found vulnerabilities
    return vulnerabilities

def check_header_information_disclosure(domain, headers, scan_id=None):
    """Check for sensitive information disclosure in HTTP headers"""
    vulnerabilities = []
    
    # Headers that may disclose sensitive information
    sensitive_headers = {
        'X-Powered-By': {
            'severity': 'LOW',
            'cwe': 'CWE-200',
            'title': 'Technology Information Disclosure via X-Powered-By Header',
            'description': 'The X-Powered-By header discloses information about the technology stack used by the application.'
        },
        'Server': {
            'severity': 'LOW',
            'cwe': 'CWE-200',
            'title': 'Web Server Information Disclosure via Server Header',
            'description': 'The Server header discloses detailed information about the web server software and version.'
        },
        'X-AspNet-Version': {
            'severity': 'LOW',
            'cwe': 'CWE-200',
            'title': 'ASP.NET Version Disclosure',
            'description': 'The X-AspNet-Version header discloses the version of ASP.NET used by the application.'
        },
        'X-Runtime': {
            'severity': 'LOW',
            'cwe': 'CWE-200',
            'title': 'Ruby on Rails Information Disclosure via X-Runtime Header',
            'description': 'The X-Runtime header discloses that the application is running on Ruby on Rails.'
        },
        'X-Generator': {
            'severity': 'LOW',
            'cwe': 'CWE-200',
            'title': 'Application Generator Disclosure via X-Generator Header',
            'description': 'The X-Generator header discloses information about the framework or CMS used to generate the page.'
        }
    }
    
    # Check each sensitive header
    for header, info in sensitive_headers.items():
        if header in headers:
            # Create vulnerability
            title = info['title']
            description = f"""{info['description']}

Value: {headers[header]}

Recommendation: Configure your web server to omit this header from HTTP responses to reduce information disclosure.
"""
            
            vuln = add_vulnerability(
                domain,
                title,
                description,
                info['severity'],
                info['cwe'],
                None,
                domain.url,
                f"Header: {header}: {headers[header]}"
            )
            
            vulnerabilities.append(vuln)
            
            if scan_id:
                emit_scan_update(
                    scan_id,
                    f"Found information disclosure: {header} header reveals {headers[header]}",
                    "info"
                )
    
    return vulnerabilities

def check_content_information_disclosure(domain, content, url, scan_id=None):
    """Check for sensitive information disclosure in page content"""
    vulnerabilities = []
    
    # Patterns for sensitive information
    sensitive_patterns = [
        {
            'pattern': r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
            'name': 'API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)access[_-]?token["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
            'name': 'Access Token',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)auth[_-]?token["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
            'name': 'Auth Token',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
            'name': 'Secret Key',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
            'name': 'Password',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
            'name': 'AWS Access Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([^"\']{40})["\']',
            'name': 'AWS Secret Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)database[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            'name': 'Database Connection String',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)jdbc:',
            'name': 'JDBC Connection String',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'mongodb://[^"\']+',
            'name': 'MongoDB Connection String',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)-----BEGIN\s+PRIVATE\s+KEY-----',
            'name': 'Private Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----',
            'name': 'RSA Private Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)google_api_key["\']?\s*[:=]\s*["\']([^"\']{30,})["\']',
            'name': 'Google API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)firebase[_-]?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{30,})["\']',
            'name': 'Firebase API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)stripe[_-]?(publishable|secret)[_-]?key["\']?\s*[:=]\s*["\']([^"\']{20,})["\']',
            'name': 'Stripe API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        }
    ]
    
    # Check for each pattern
    for pattern_info in sensitive_patterns:
        matches = re.findall(pattern_info['pattern'], content)
        
        for match in matches:
            # Skip if it's obviously a placeholder
            if isinstance(match, tuple):
                match = match[0]  # Extract the first capture group if it's a tuple
            
            if re.search(r'YOUR_|XXXX|example|placeholder|demo', match, re.IGNORECASE):
                continue
            
            # Create redacted preview
            if len(match) > 8:
                preview = match[:4] + '...' + match[-4:]
            else:
                preview = '[REDACTED]'
            
            title = f"Exposed {pattern_info['name']} in Page Source"
            
            description = f"""The application exposes a {pattern_info['name']} in the page source code.
            
The {pattern_info['name']} was found in the source code of the page. This is a critical security issue that can lead to unauthorized access and account takeover.

Preview: {preview}

Location: {url}

Recommendation: Remove all sensitive credentials from client-side code and source files. Store these values server-side or in secure environment variables.
"""
            
            # Add vulnerability
            vuln = add_vulnerability(
                domain,
                title,
                description,
                pattern_info['severity'],
                pattern_info['cwe'],
                None,
                url,
                f"Found {pattern_info['name']}: {preview}"
            )
            
            vulnerabilities.append(vuln)
            
            if scan_id:
                emit_scan_update(
                    scan_id,
                    f"Found exposed {pattern_info['name']} in source code",
                    pattern_info['severity'].lower()
                )
    
    # Check for comments containing sensitive information
    html_comments = re.findall(r'<!--(.*?)-->', content, re.DOTALL)
    js_comments = re.findall(r'//.*?$|/\*.*?\*/', content, re.MULTILINE | re.DOTALL)
    
    all_comments = html_comments + js_comments
    sensitive_keywords = ['password', 'key', 'token', 'secret', 'api', 'auth', 'todo', 'fix', 'vulnerability', 'hack']
    
    for comment in all_comments:
        comment_lower = comment.lower()
        if any(keyword in comment_lower for keyword in sensitive_keywords):
            # Truncate very long comments
            if len(comment) > 200:
                display_comment = comment[:200] + '...'
            else:
                display_comment = comment
            
            vuln = add_vulnerability(
                domain,
                "Sensitive Information in Comments",
                f"""The application contains comments with potentially sensitive information.
                
Comment: {display_comment}

Location: {url}

Recommendation: Remove comments containing sensitive information, credentials, or development notes from production code.
""",
                'MEDIUM',
                'CWE-200',
                None,
                url,
                f"Comment: {display_comment}"
            )
            
            vulnerabilities.append(vuln)
            
            if scan_id:
                emit_scan_update(
                    scan_id,
                    f"Found potentially sensitive comment in source code",
                    "medium"
                )
    
    return vulnerabilities

def check_misconfigurations(domain, response, url, scan_id=None):
    """Check for common security misconfigurations"""
    vulnerabilities = []
    
    # Check for CORS misconfiguration
    if 'Access-Control-Allow-Origin' in response.headers:
        cors_value = response.headers['Access-Control-Allow-Origin']
        if cors_value == '*':
            vuln = add_vulnerability(
                domain,
                "CORS Misconfiguration - Wildcard Origin",
                f"""The application has a misconfigured CORS policy that allows any origin to make cross-origin requests.
                
Access-Control-Allow-Origin: {cors_value}

This configuration can lead to cross-site request forgery or data theft if combined with other vulnerabilities.

Recommendation: Restrict CORS to specific trusted domains instead of using a wildcard.
""",
                'MEDIUM',
                'CWE-942',
                None,
                url,
                f"Header: Access-Control-Allow-Origin: {cors_value}"
            )
            
            vulnerabilities.append(vuln)
            
            if scan_id:
                emit_scan_update(
                    scan_id,
                    f"Found CORS misconfiguration - wildcard origin allowed",
                    "medium"
                )
    
    # Check for missing Content-Type header
    if 'Content-Type' not in response.headers:
        vuln = add_vulnerability(
            domain,
            "Missing Content-Type Header",
            f"""The application does not set a Content-Type header in its response.
            
This can lead to MIME type sniffing attacks if combined with user-supplied content.

Recommendation: Always set an appropriate Content-Type header for all responses.
""",
            'LOW',
            'CWE-430',
            None,
            url,
            "Content-Type header is missing"
        )
        
        vulnerabilities.append(vuln)
        
        if scan_id:
            emit_scan_update(
                scan_id,
                f"Missing Content-Type header",
                "low"
            )
    
    # Check for insecure cookie flags
    if 'set-cookie' in response.headers:
        cookie_header = response.headers['set-cookie']
        
        # Check for missing HttpOnly flag
        if 'httponly' not in cookie_header.lower():
            vuln = add_vulnerability(
                domain,
                "Cookie Missing HttpOnly Flag",
                f"""One or more cookies are set without the HttpOnly flag.
                
Cookie: {cookie_header}

Cookies without the HttpOnly flag are accessible to JavaScript, which can lead to session hijacking via XSS attacks.

Recommendation: Set the HttpOnly flag on all cookies containing sensitive information, especially session cookies.
""",
                'MEDIUM',
                'CWE-1004',
                None,
                url,
                f"Cookie: {cookie_header}"
            )
            
            vulnerabilities.append(vuln)
            
            if scan_id:
                emit_scan_update(
                    scan_id,
                    f"Cookie missing HttpOnly flag",
                    "medium"
                )
        
        # Check for missing Secure flag
        if 'secure' not in cookie_header.lower() and url.startswith('https://'):
            vuln = add_vulnerability(
                domain,
                "Cookie Missing Secure Flag",
                f"""One or more cookies are set without the Secure flag on an HTTPS connection.
                
Cookie: {cookie_header}

Cookies without the Secure flag can be transmitted over unencrypted HTTP connections, exposing sensitive information.

Recommendation: Set the Secure flag on all cookies when using HTTPS.
""",
                'MEDIUM',
                'CWE-614',
                None,
                url,
                f"Cookie: {cookie_header}"
            )
            
            vulnerabilities.append(vuln)
            
            if scan_id:
                emit_scan_update(
                    scan_id,
                    f"Cookie missing Secure flag on HTTPS site",
                    "medium"
                )
    
    # Check for JavaScript source maps in production
    if re.search(r'\.js\.map$', response.text):
        vuln = add_vulnerability(
            domain,
            "JavaScript Source Maps Exposed",
            f"""The application exposes JavaScript source maps in production.
            
Source maps contain original source code and can expose sensitive logic, API endpoints, or hardcoded credentials.

Recommendation: Remove source maps from production deployments or restrict access to them.
""",
            'MEDIUM',
            'CWE-540',
            None,
            url,
            "Source map files detected in page source"
        )
        
        vulnerabilities.append(vuln)
        
        if scan_id:
            emit_scan_update(
                scan_id,
                f"JavaScript source maps exposed in production",
                "medium"
            )
    
    # Check for form without CSRF protection
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    
    for form in forms:
        # Look for CSRF token in form
        has_csrf_token = False
        
        # Common CSRF token field names
        csrf_field_names = ['csrf', 'xsrf', '_token', '_csrf', 'csrf_token', 'xsrf_token', 'authenticity_token']
        
        for input_field in form.find_all('input', type='hidden'):
            if input_field.get('name') and any(csrf_name in input_field.get('name', '').lower() for csrf_name in csrf_field_names):
                has_csrf_token = True
                break
        
        if not has_csrf_token and form.get('method', '').upper() in ['POST', '']:  # Empty method defaults to POST
            vuln = add_vulnerability(
                domain,
                "Form Without CSRF Protection",
                f"""The application contains a form without CSRF protection.
                
Form action: {form.get('action', '[No action specified]')}
Form method: {form.get('method', 'POST')}

Forms without CSRF protection are vulnerable to Cross-Site Request Forgery attacks, where attackers can trick users into submitting unauthorized requests.

Recommendation: Add CSRF tokens to all forms that modify state or perform sensitive operations.
""",
                'MEDIUM',
                'CWE-352',
                None,
                url,
                f"Form found without CSRF token: {form.get('action', '[No action specified]')}"
            )
            
            vulnerabilities.append(vuln)
            
            if scan_id:
                emit_scan_update(
                    scan_id,
                    f"Form without CSRF protection detected",
                    "medium"
                )
    
    return vulnerabilities

# ===== API ENDPOINT DISCOVERY =====

def discover_endpoints(url, domain, scan_id=None):
    """
    Discover API endpoints and web application routes
    Returns list of discovered Endpoint objects
    """
    if scan_id:
        emit_scan_update(scan_id, f"Starting endpoint discovery for {url}", "info")
    
    discovered_endpoints = []
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    try:
        # Get the main page content
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        
        if response.status_code >= 400:
            if scan_id:
                emit_scan_update(scan_id, f"Error accessing {url}: HTTP {response.status_code}", "error")
            return discovered_endpoints
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Find JavaScript files
        js_files = []
        
        # Look for script tags with src attribute
        for script in soup.find_all('script', src=True):
            script_url = script['src']
            
            # Convert relative URLs to absolute
            if not script_url.startswith(('http://', 'https://')):
                script_url = urljoin(url, script_url)
            
            js_files.append(script_url)
        
        if scan_id:
            emit_scan_update(scan_id, f"Found {len(js_files)} JavaScript files", "info")
        
        # 2. Analyze JavaScript files for endpoints
        endpoint_patterns = [
            r'url:\s*[\'"]([^\'"]*)[\'"]',
            r'path:\s*[\'"]([^\'"]*)[\'"]',
            r'route:\s*[\'"]([^\'"]*)[\'"]',
            r'href=[\'"](/[^\'"]*)[\'"]',
            r'endpoint[\'"]:\s*[\'"]([^\'"]*)[\'"]',
            r'api[\'"]:\s*[\'"]([^\'"]*)[\'"]',
            r'fetch\([\'"]([^\'"]*)[\'"]',
            r'axios\.[a-z]+\([\'"]([^\'"]*)[\'"]',
            r'ajax\([\'"]([^\'"]*)[\'"]'
        ]
        
        for js_url in js_files:
            try:
                if scan_id:
                    emit_scan_update(scan_id, f"Analyzing {js_url}", "debug")
                
                js_response = requests.get(js_url, timeout=5, verify=False)
                if js_response.status_code >= 400:
                    continue
                
                js_content = js_response.text
                
                # Process the JS file with each pattern
                for pattern in endpoint_patterns:
                    matches = re.findall(pattern, js_content)
                    for match in matches:
                        # Filter out non-endpoint patterns
                        if match and len(match) > 1 and not match.startswith(('http', 'www', '{', '#', 'function')):
                            # Normalize the endpoint
                            endpoint = match
                            if not endpoint.startswith('/'):
                                endpoint = '/' + endpoint
                            
                            # Add to discovered endpoints
                            full_url = urljoin(base_url, endpoint)
                            
                            # Check endpoint status
                            status_code, content_type = check_endpoint_status(full_url, scan_id)
                            
                            # Determine if endpoint is interesting based on path and content type
                            is_interesting = any(keyword in endpoint.lower() for keyword in 
                                ['api', 'admin', 'config', 'login', 'user', 'auth', 'token', 'jwt', 'dashboard', 'private'])
                            
                            # Add to the database
                            endpoint_obj = add_endpoint(
                                domain, 
                                full_url, 
                                endpoint, 
                                is_interesting, 
                                status_code, 
                                content_type
                            )
                            
                            discovered_endpoints.append(endpoint_obj)
            
            except Exception as e:
                if scan_id:
                    emit_scan_update(scan_id, f"Error analyzing {js_url}: {str(e)}", "error")
        
        # 3. Check for common API endpoints
        common_api_endpoints = [
            '/api', '/api/v1', '/api/v2', '/api/v3', '/api/v1.0', '/api/v2.0',
            '/graphql', '/graphiql', '/gql', '/swagger', '/swagger-ui', '/api-docs',
            '/api/users', '/api/auth', '/api/login', '/api/token', '/api/data',
            '/rest', '/rest/v1', '/rest/v2', '/api/admin', '/api/products',
            '/api/orders', '/api/customers', '/api/items', '/api/search'
        ]
        
        for endpoint in common_api_endpoints:
            endpoint_url = urljoin(base_url, endpoint)
            
            try:
                # Use HEAD request to minimize data transfer
                head_response = requests.head(
                    endpoint_url, 
                    timeout=3, 
                    verify=False, 
                    allow_redirects=True
                )
                
                # Check if the endpoint exists (any response other than 404)
                if head_response.status_code != 404:
                    # Add to the database
                    endpoint_obj = add_endpoint(
                        domain, 
                        endpoint_url, 
                        endpoint, 
                        True,  # APIs are always interesting
                        head_response.status_code,
                        head_response.headers.get('Content-Type')
                    )
                    
                    discovered_endpoints.append(endpoint_obj)
                    
                    if scan_id:
                        if head_response.status_code < 400:
                            emit_scan_update(
                                scan_id,
                                f"Discovered API endpoint: {endpoint_url} (HTTP {head_response.status_code})",
                                "success"
                            )
                        elif head_response.status_code in [401, 403]:
                            emit_scan_update(
                                scan_id,
                                f"Discovered protected API endpoint: {endpoint_url} (HTTP {head_response.status_code})",
                                "warning"
                            )
                        else:
                            emit_scan_update(
                                scan_id,
                                f"Discovered API endpoint: {endpoint_url} (HTTP {head_response.status_code})",
                                "info"
                            )
            
            except requests.exceptions.RequestException:
                # Ignore connection errors for endpoints that don't exist
                pass
        
        # 4. Extract links from the HTML content
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            # Filter out external links, anchors and javascript
            if not href.startswith(('http', 'https', '#', 'javascript', 'mailto', 'tel')):
                full_url = urljoin(base_url, href)
                
                # Check if it's an internal link
                if parsed_url.netloc in urlparse(full_url).netloc:
                    # Parse the path
                    path = urlparse(full_url).path
                    
                    # Skip if empty path
                    if not path:
                        continue
                    
                    # Check if this looks like an interesting endpoint
                    is_interesting = any(keyword in path.lower() for keyword in 
                        ['api', 'admin', 'config', 'login', 'user', 'auth', 'token', 'dashboard', 'private'])
                    
                    # Skip image, css, js files
                    if any(path.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js']):
                        continue
                    
                    # Add to the database
                    endpoint_obj = add_endpoint(domain, full_url, path, is_interesting)
                    
                    discovered_endpoints.append(endpoint_obj)
        
        # 5. Specific checks for Angular apps
        if is_angular_app(response.text):
            if scan_id:
                emit_scan_update(scan_id, f"Detected Angular application, checking for Angular routes...", "info")
            
            angular_endpoints = detect_angular_routes(response.text)
            
            for route in angular_endpoints:
                # Create full URL for the Angular route
                full_url = urljoin(base_url, route)
                
                # Add to the database
                endpoint_obj = add_endpoint(
                    domain, 
                    full_url, 
                    route, 
                    True,  # Angular routes are usually interesting
                    None,  # We don't check status because Angular is client-side routing
                    'text/html'
                )
                
                discovered_endpoints.append(endpoint_obj)
                
                if scan_id:
                    emit_scan_update(
                        scan_id,
                        f"Discovered Angular route: {route}",
                        "info"
                    )
        
        # 6. Specific checks for React apps (look for React Router)
        if is_react_app(response.text):
            if scan_id:
                emit_scan_update(scan_id, f"Detected React application, checking for React routes...", "info")
            
            react_endpoints = detect_react_routes(js_files, base_url)
            
            for route in react_endpoints:
                # Create full URL for the React route
                full_url = urljoin(base_url, route)
                
                # Add to the database
                endpoint_obj = add_endpoint(
                    domain, 
                    full_url, 
                    route, 
                    True,  # React routes are usually interesting
                    None,  # We don't check status because React is client-side routing
                    'text/html'
                )
                
                discovered_endpoints.append(endpoint_obj)
                
                if scan_id:
                    emit_scan_update(
                        scan_id,
                        f"Discovered React route: {route}",
                        "info"
                    )
        
        if scan_id:
            emit_scan_update(
                scan_id, 
                f"Endpoint discovery completed. Found {len(discovered_endpoints)} endpoints", 
                "success"
            )
    
    except Exception as e:
        if scan_id:
            emit_scan_update(scan_id, f"Error during endpoint discovery: {str(e)}", "error")
    
    return discovered_endpoints

def is_angular_app(html_content):
    """Detect if the site is an Angular application"""
    angular_patterns = [
        r'ng-app',
        r'ng-controller',
        r'ng-model',
        r'ng-repeat',
        r'angular\.js',
        r'angular\.min\.js',
        r'ng-*',
        r'_ng',
        r'ng-version',
        r'ng-pristine'
    ]
    
    return any(re.search(pattern, html_content) for pattern in angular_patterns)

def is_react_app(html_content):
    """Detect if the site is a React application"""
    react_patterns = [
        r'react\.js',
        r'react\.production\.min\.js',
        r'react-dom',
        r'_reactRoot',
        r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
        r'react-app'
    ]
    
    return any(re.search(pattern, html_content) for pattern in react_patterns)

def detect_angular_routes(html_content):
    """Extract potential Angular routes from the application"""
    detected_routes = []
    
    # Look for hardcoded routes in the code
    route_patterns = [
        r'routerLink=["\']([^"\']+)["\']',
        r'path:\s*["\']([^"\']+)["\']',
        r'component:\s*[A-Za-z]+Component'
    ]
    
    for pattern in route_patterns:
        matches = re.findall(pattern, html_content)
        for match in matches:
            if match and not match.startswith(('http', 'https', '#', 'javascript')) and match != '/':
                # Normalize the route
                if not match.startswith('/'):
                    match = '/' + match
                
                if match not in detected_routes:
                    detected_routes.append(match)
    
    return detected_routes

def detect_react_routes(js_files, base_url):
    """Extract potential React routes from JavaScript files"""
    detected_routes = []
    
    # Patterns that might indicate React routes
    route_patterns = [
        r'<Route\s+path=["\']([^"\']+)["\']',
        r'path:\s*["\']([^"\']+)["\'].*?component',
        r'history\.push\(["\']([^"\']+)["\']',
        r'<Link\s+to=["\']([^"\']+)["\']'
    ]
    
    # Check all JS files for React routes
    for js_url in js_files:
        try:
            response = requests.get(js_url, timeout=5, verify=False)
            if response.status_code >= 400:
                continue
            
            js_content = response.text
            
            for pattern in route_patterns:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    if match and not match.startswith(('http', 'https', '#', 'javascript')) and match != '/':
                        # Normalize the route
                        if not match.startswith('/'):
                            match = '/' + match
                        
                        # Filter out template variables like :id
                        if not re.search(r'^/[{:]', match):
                            if match not in detected_routes:
                                detected_routes.append(match)
        
        except Exception:
            # Skip any errors in fetching or parsing JS files
            continue
    
    return detected_routes

def check_endpoint_status(endpoint_url, scan_id=None):
    """Check the HTTP status code and content type of an endpoint"""
    try:
        requests.packages.urllib3.disable_warnings()
        response = requests.head(endpoint_url, timeout=5, verify=False, allow_redirects=True)
        status_code = response.status_code
        content_type = response.headers.get('Content-Type', 'Unknown')
        
        if scan_id:
            status_class = ""
            if status_code < 300:
                status_class = "success"
                message = f"Endpoint accessible: {endpoint_url} (HTTP {status_code})"
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

# ===== JAVASCRIPT ANALYSIS =====

def analyze_javascript(url, domain, scan_id=None):
    """
    Analyze JavaScript files for vulnerabilities and information leakage
    Returns list of discovered vulnerabilities
    """
    vulnerabilities = []
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    try:
        # Get the main page content
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
        
        # Find JavaScript files
        js_files = find_javascript_files(response, url)
        
        if scan_id:
            emit_scan_update(scan_id, f"Found {len(js_files)} JavaScript files to analyze", "info")
        
        # Analyze each JavaScript file
        for js_url in js_files:
            try:
                js_response = requests.get(js_url, timeout=5, verify=False)
                if js_response.status_code >= 400:
                    continue
                
                js_content = js_response.text
                
                # Look for sensitive information in JS
                sensitive_info_vulns = find_sensitive_info_in_js(domain, js_content, js_url, scan_id)
                vulnerabilities.extend(sensitive_info_vulns)
                
                # Check for vulnerable JS libraries
                lib_vulns = check_js_library_vulnerabilities(domain, js_content, js_url, scan_id)
                vulnerabilities.extend(lib_vulns)
                
                # Check for insecure coding practices in JS
                insecure_code_vulns = check_insecure_js_code(domain, js_content, js_url, scan_id)
                vulnerabilities.extend(insecure_code_vulns)
            
            except Exception as e:
                if scan_id:
                    emit_scan_update(scan_id, f"Error analyzing JavaScript file {js_url}: {str(e)}", "error")
    
    except Exception as e:
        if scan_id:
            emit_scan_update(scan_id, f"Error in JavaScript analysis: {str(e)}", "error")
    
    return vulnerabilities

def find_javascript_files(response, url):
    """Find all JavaScript files linked from a page"""
    js_files = []
    
    # Parse HTML
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Look for script tags with src attribute
    for script in soup.find_all('script', src=True):
        script_url = script['src']
        
        # Convert relative URLs to absolute
        if not script_url.startswith(('http://', 'https://')):
            script_url = urljoin(url, script_url)
        
        js_files.append(script_url)
    
    return js_files

def find_sensitive_info_in_js(domain, js_content, js_url, scan_id=None):
    """Find sensitive information in JavaScript files"""
    vulnerabilities = []
    
    # Patterns for sensitive information
    sensitive_patterns = [
        {
            'pattern': r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
            'name': 'API Key',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)access[_-]?token["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
            'name': 'Access Token',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)auth[_-]?token["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
            'name': 'Auth Token',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
            'name': 'Secret Key',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
            'name': 'Password',
            'severity': 'HIGH',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
            'name': 'AWS Access Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-312'
        },
        {
            'pattern': r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([^"\']{40})["\']',
            'name': 'AWS Secret Key',
            'severity': 'CRITICAL',
            'cwe': 'CWE-312'
        }
    ]
    
    # Check each pattern
    for pattern_info in sensitive_patterns:
        matches = re.findall(pattern_info['pattern'], js_content)
        
        for match in matches:
            # Skip if it's obviously a placeholder
            if isinstance(match, tuple):
                match = match[0]  # Extract the first capture group if it's a tuple
            
            if re.search(r'YOUR_|XXXX|example|placeholder|demo', match, re.IGNORECASE):
                continue
            
            # Create a redacted preview
            if len(match) > 8:
                preview = match[:4] + '...' + match[-4:]
            else:
                preview = '[REDACTED]'
            
            # Find the line number
            line_num = find_line_number(js_content, match)
            
            title = f"Exposed {pattern_info['name']} in JavaScript"
            
            description = f"""The application exposes a {pattern_info['name']} in a JavaScript file.
            
The {pattern_info['name']} was found in a JavaScript file. This is a security issue that can lead to unauthorized access.

Preview: {preview}
Location: {js_url} (line {line_num})

Recommendation: Remove all sensitive credentials from client-side code. Store these values server-side or use secure token exchange mechanisms.
"""
            
            # Add vulnerability
            vuln = add_vulnerability(
                domain,
                title,
                description,
                pattern_info['severity'],
                pattern_info['cwe'],
                None,
                js_url,
                f"Found {pattern_info['name']} at line {line_num}: {preview}"
            )
            
            vulnerabilities.append(vuln)
            
            if scan_id:
                emit_scan_update(
                    scan_id,
                    f"Found exposed {pattern_info['name']} in JavaScript file at line {line_num}",
                    pattern_info['severity'].lower()
                )
    
    return vulnerabilities

def check_js_library_vulnerabilities(domain, js_content, js_url, scan_id=None):
    """Check for known vulnerabilities in JavaScript libraries"""
    vulnerabilities = []
    
    # Known vulnerable JS library versions
    vulnerable_libraries = {
        'jquery': [
            {
                'version_pattern': r'jQuery\s+v?([0-9.]+)',
                'vulnerable_range': '<3.0.0',
                'cve': 'CVE-2020-11022',
                'severity': 'MEDIUM',
                'cwe': 'CWE-79',
                'description': 'jQuery before 3.5.0 is vulnerable to XSS due to improper handling of HTML content in DOM manipulation methods.'
            },
            {
                'version_pattern': r'jquery[.-]?(\d+\.\d+\.\d+)',
                'vulnerable_range': '<3.5.0',
                'cve': 'CVE-2020-11022',
                'severity': 'MEDIUM',
                'cwe': 'CWE-79',
                'description': 'jQuery before 3.5.0 is vulnerable to XSS due to improper handling of HTML content in DOM manipulation methods.'
            }
        ],
        'angular': [
            {
                'version_pattern': r'angular[:/](\d+\.\d+\.\d+)',
                'vulnerable_range': '<1.8.0',
                'cve': 'CVE-2020-7676',
                'severity': 'HIGH',
                'cwe': 'CWE-79',
                'description': 'AngularJS before 1.8.0 is vulnerable to XSS due to improper sanitization.'
            },
            {
                'version_pattern': r'angular\.js@(\d+\.\d+\.\d+)',
                'vulnerable_range': '<1.8.0',
                'cve': 'CVE-2020-7676',
                'severity': 'HIGH',
                'cwe': 'CWE-79',
                'description': 'AngularJS before 1.8.0 is vulnerable to XSS due to improper sanitization.'
            }
        ],
        'react': [
            {
                'version_pattern': r'react[:/](\d+\.\d+\.\d+)',
                'vulnerable_range': '<16.13.1',
                'cve': 'CVE-2020-11022',
                'severity': 'MEDIUM',
                'cwe': 'CWE-79',
                'description': 'React before 16.13.1 allows XSS via certain maliciously crafted URLs.'
            }
        ],
        'vue': [
            {
                'version_pattern': r'vue[:/](\d+\.\d+\.\d+)',
                'vulnerable_range': '<2.6.11',
                'cve': 'CVE-2020-7070',
                'severity': 'MEDIUM',
                'cwe': 'CWE-79',
                'description': 'Vue.js before 2.6.11 is vulnerable to XSS in the v-bind directive.'
            }
        ],
        'bootstrap': [
            {
                'version_pattern': r'bootstrap[:/](\d+\.\d+\.\d+)',
                'vulnerable_range': '<3.4.1',
                'cve': 'CVE-2019-8331',
                'severity': 'MEDIUM',
                'cwe': 'CWE-79',
                'description': 'Bootstrap before 3.4.1 is vulnerable to XSS in the tooltip or popover data-template attribute.'
            },
            {
                'version_pattern': r'bootstrap[.-]?(\d+\.\d+\.\d+)',
                'vulnerable_range': '<3.4.1',
                'cve': 'CVE-2019-8331',
                'severity': 'MEDIUM',
                'cwe': 'CWE-79',
                'description': 'Bootstrap before 3.4.1 is vulnerable to XSS in the tooltip or popover data-template attribute.'
            }
        ],
        'prototype': [
            {
                'version_pattern': r'prototype[:/](\d+\.\d+\.\d+)',
                'vulnerable_range': '<1.7.3',
                'cve': 'CVE-2008-7220',
                'severity': 'HIGH',
                'cwe': 'CWE-79',
                'description': 'Prototype.js before 1.7.3 is vulnerable to XSS in the handling of JSON responses.'
            }
        ],
        'moment': [
            {
                'version_pattern': r'moment[:/](\d+\.\d+\.\d+)',
                'vulnerable_range': '<2.19.3',
                'cve': 'CVE-2017-18214',
                'severity': 'MEDIUM',
                'cwe': 'CWE-79',
                'description': 'Moment.js before 2.19.3 is vulnerable to a Regular Expression Denial of Service (ReDoS) when parsing certain dates.'
            }
        ],
        'lodash': [
            {
                'version_pattern': r'lodash[:/](\d+\.\d+\.\d+)',
                'vulnerable_range': '<4.17.12',
                'cve': 'CVE-2019-10744',
                'severity': 'HIGH',
                'cwe': 'CWE-94',
                'description': 'Lodash before 4.17.12 has prototype pollution vulnerability allowing properties to be added to Object.prototype.'
            }
        ]
    }
    
    # Check each library for vulnerable versions
    for library_name, vulnerabilities_list in vulnerable_libraries.items():
        for vuln_info in vulnerabilities_list:
            # Look for version pattern in the JS content
            version_match = re.search(vuln_info['version_pattern'], js_content)
            
            if version_match:
                # Extract and validate the version
                version = version_match.group(1)
                
                # Check if the version is in the vulnerable range
                if is_version_in_range(version, vuln_info['vulnerable_range']):
                    title = f"Vulnerable {library_name.capitalize()} Library: {version}"
                    
                    description = f"""The application is using a vulnerable version of {library_name.capitalize()}.
                    
Library: {library_name.capitalize()}
Version: {version}
Vulnerable Range: {vuln_info['vulnerable_range']}
CVE: {vuln_info['cve']}
CVSS: Varies by implementation
CWE: {vuln_info['cwe']}

Description: {vuln_info['description']}

Location: {js_url}

Recommendation: Update to the latest version of {library_name.capitalize()} to resolve the vulnerability.
"""
                    
                    # Add vulnerability
                    vuln = add_vulnerability(
                        domain,
                        title,
                        description,
                        vuln_info['severity'],
                        vuln_info['cwe'],
                        vuln_info['cve'],
                        js_url,
                        f"Found vulnerable {library_name.capitalize()} version {version}"
                    )
                    
                    vulnerabilities.append(vuln)
                    
                    if scan_id:
                        emit_scan_update(
                            scan_id,
                            f"Found vulnerable {library_name.capitalize()} version {version} ({vuln_info['cve']})",
                            vuln_info['severity'].lower()
                        )
    
    return vulnerabilities

def check_insecure_js_code(domain, js_content, js_url, scan_id=None):
    """Check for insecure coding practices in JavaScript"""
    vulnerabilities = []
    
    # Patterns for insecure coding practices
    insecure_patterns = [
        {
            'pattern': r'eval\s*\(',
            'name': 'Unsafe eval() Usage',
            'severity': 'HIGH',
            'cwe': 'CWE-95',
            'description': 'The application uses the eval() function, which can execute arbitrary code and lead to code injection vulnerabilities.'
        },
        {
            'pattern': r'document\.write\s*\(',
            'name': 'Unsafe document.write() Usage',
            'severity': 'MEDIUM',
            'cwe': 'CWE-79',
            'description': 'The application uses document.write(), which can enable cross-site scripting attacks if user input is improperly handled.'
        },
        {
            'pattern': r'innerHTML\s*=',
            'name': 'Unsafe innerHTML Assignment',
            'severity': 'MEDIUM',
            'cwe': 'CWE-79',
            'description': 'The application assigns content to innerHTML, which can enable cross-site scripting attacks if user input is improperly handled.'
        },
        {
            'pattern': r'localStorage\s*\.\s*setItem\s*\(',
            'name': 'Sensitive Data in localStorage',
            'severity': 'MEDIUM',
            'cwe': 'CWE-312',
            'description': 'The application may be storing sensitive data in localStorage, which is persistent and accessible to any script from the same origin.'
        },
        {
            'pattern': r'sessionStorage\s*\.\s*setItem\s*\(',
            'name': 'Sensitive Data in sessionStorage',
            'severity': 'LOW',
            'cwe': 'CWE-312',
            'description': 'The application may be storing sensitive data in sessionStorage, which is accessible to any script from the same origin during the session.'
        },
        {
            'pattern': r'\.addEventListener\s*\(\s*["\']message["\']',
            'name': 'Unvalidated postMessage Receiver',
            'severity': 'MEDIUM',
            'cwe': 'CWE-346',
            'description': 'The application uses a message event listener without validating the origin of the sender, which can lead to cross-origin data leakage.'
        },
        {
            'pattern': r'new\s+Function\s*\(',
            'name': 'Unsafe Function Constructor',
            'severity': 'HIGH',
            'cwe': 'CWE-95',
            'description': 'The application uses the Function constructor, which evaluates code dynamically and can lead to code injection vulnerabilities.'
        },
        {
            'pattern': r'setTimeout\s*\(\s*["\'][^"\']+["\']',
            'name': 'Unsafe setTimeout Usage',
            'severity': 'MEDIUM',
            'cwe': 'CWE-95',
            'description': 'The application passes a string to setTimeout(), which uses eval() internally and can lead to code injection vulnerabilities.'
        },
        {
            'pattern': r'setInterval\s*\(\s*["\'][^"\']+["\']',
            'name': 'Unsafe setInterval Usage',
            'severity': 'MEDIUM',
            'cwe': 'CWE-95',
            'description': 'The application passes a string to setInterval(), which uses eval() internally and can lead to code injection vulnerabilities.'
        }
    ]
    
    # Check each pattern
    for pattern_info in insecure_patterns:
        matches = re.finditer(pattern_info['pattern'], js_content)
        
        for match in matches:
            # Find the line number
            line_num = find_line_number(js_content, match.group(0))
            
            # Get some context around the match
            line = get_line_context(js_content, line_num)
            
            title = pattern_info['name']
            
            description = f"""{pattern_info['description']}

Location: {js_url} (line {line_num})
Context: {line}

CWE: {pattern_info['cwe']}

Recommendation: Avoid using {match.group(0).strip()} and use safer alternatives. Validate and sanitize all data before using it in JavaScript execution contexts.
"""
            
            # Add vulnerability
            vuln = add_vulnerability(
                domain,
                title,
                description,
                pattern_info['severity'],
                pattern_info['cwe'],
                None,
                js_url,
                f"Found {pattern_info['name']} at line {line_num}: {line}"
            )
            
            vulnerabilities.append(vuln)
            
            if scan_id:
                emit_scan_update(
                    scan_id,
                    f"Found {pattern_info['name']} in JavaScript at line {line_num}",
                    pattern_info['severity'].lower()
                )
    
    return vulnerabilities

def find_line_number(content, substring):
    """Find the line number where a substring appears in content"""
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if substring in line:
            return i + 1
    return 1  # Default to first line if not found

def get_line_context(content, line_num, context_lines=0):
    """Get a line with some context lines around it"""
    lines = content.split('\n')
    if line_num <= 0 or line_num > len(lines):
        return ''
    
    start = max(0, line_num - 1 - context_lines)
    end = min(len(lines), line_num + context_lines)
    
    if context_lines > 0:
        return '\n'.join(lines[start:end])
    else:
        return lines[line_num - 1]

# ===== AUTHENTICATION BYPASS TESTING =====

def test_auth_bypass(url, domain, scan_id=None):
    """
    Test for authentication bypass vulnerabilities on protected endpoints
    Returns list of discovered bypass vulnerabilities
    """
    bypass_results = []
    
    # Only run auth bypass tests if we have 403 endpoints
    protected_endpoints = Endpoint.query.filter_by(domain_id=domain.id, status_code=403).all()
    
    if not protected_endpoints:
        if scan_id:
            emit_scan_update(scan_id, f"No protected endpoints found for authentication bypass testing", "info")
        return bypass_results
    
    if scan_id:
        emit_scan_update(
            scan_id, 
            f"Testing {len(protected_endpoints)} protected endpoints for authentication bypass vulnerabilities", 
            "info"
        )
    
    # Authentication bypass techniques to test
    bypass_techniques = [
        {
            'name': 'X-Original-URL Header',
            'headers': {'X-Original-URL': '/'},
            'method': 'GET',
            'description': 'This technique uses the X-Original-URL header to bypass access controls by specifying a different path.'
        },
        {
            'name': 'X-Rewrite-URL Header',
            'headers': {'X-Rewrite-URL': '/'},
            'method': 'GET',
            'description': 'This technique uses the X-Rewrite-URL header to bypass access controls by specifying a different path.'
        },
        {
            'name': 'X-Forwarded-For Header',
            'headers': {'X-Forwarded-For': '127.0.0.1'},
            'method': 'GET',
            'description': 'This technique attempts to bypass IP-based restrictions by pretending to be a local request.'
        },
        {
            'name': 'HTTP Method Override',
            'headers': {'X-HTTP-Method-Override': 'GET'},
            'method': 'POST',
            'description': 'This technique attempts to bypass method-based restrictions by using a different HTTP method.'
        },
        {
            'name': 'Content-Length: 0 Header',
            'headers': {'Content-Length': '0'},
            'method': 'POST',
            'description': 'This technique attempts to bypass restrictions by sending a POST request with no body.'
        },
        {
            'name': 'X-Forwarded-Host Header',
            'headers': {'X-Forwarded-Host': '127.0.0.1'},
            'method': 'GET',
            'description': 'This technique attempts to bypass host-based restrictions by spoofing the host.'
        },
        {
            'name': 'X-Host Header',
            'headers': {'X-Host': '127.0.0.1'},
            'method': 'GET',
            'description': 'This technique attempts to bypass host-based restrictions by spoofing the host.'
        },
        {
            'name': 'Path trailing slash',
            'path_suffix': '/',
            'method': 'GET',
            'description': 'This technique attempts to bypass restrictions by adding a trailing slash to the path.'
        },
        {
            'name': 'Path URL-encoded slash',
            'path_suffix': '%2f',
            'method': 'GET',
            'description': 'This technique attempts to bypass restrictions by adding an encoded slash to the path.'
        },
        {
            'name': 'Path dot-slash',
            'path_suffix': './/',
            'method': 'GET',
            'description': 'This technique attempts to bypass restrictions by adding dot-slash sequences to the path.'
        },
        {
            'name': 'Query parameter',
            'path_suffix': '?anything=1',
            'method': 'GET',
            'description': 'This technique attempts to bypass restrictions by adding query parameters to the path.'
        },
        {
            'name': 'URL fragment',
            'path_suffix': '#',
            'method': 'GET',
            'description': 'This technique attempts to bypass restrictions by adding a URL fragment to the path.'
        },
        {
            'name': 'TRACE Method',
            'method': 'TRACE',
            'description': 'This technique attempts to bypass restrictions by using the TRACE HTTP method.'
        }
    ]
    
    for endpoint in protected_endpoints:
        if scan_id:
            emit_scan_update(scan_id, f"Testing endpoint: {endpoint.url}", "info")
        
        # Test each bypass technique
        for technique in bypass_techniques:
            try:
                # Prepare request parameters
                request_kwargs = {
                    'timeout': 5,
                    'verify': False,
                    'allow_redirects': True,
                    'method': technique.get('method', 'GET')
                }
                
                # Add custom headers if defined
                if 'headers' in technique:
                    request_kwargs['headers'] = technique['headers']
                
                # Modify endpoint URL if needed
                if 'path_suffix' in technique:
                    test_url = endpoint.url + technique['path_suffix']
                else:
                    test_url = endpoint.url
                
                # Make the request
                response = requests.request(
                    url=test_url,
                    **request_kwargs
                )
                
                # Check if bypass was successful (got 200 OK)
                if response.status_code == 200:
                    # Create a successful bypass result
                    bypass_info = {
                        'title': f"Authentication Bypass: {technique['name']}",
                        'description': f"""Successfully bypassed authentication on a protected endpoint using the {technique['name']} technique.
                        
Protected Endpoint: {endpoint.url}
Bypass Technique: {technique['name']}
Original Status Code: 403 Forbidden
Bypassed Status Code: 200 OK

{technique['description']}

Recommendation: Fix the authentication controls to properly validate access to protected resources regardless of the request method or headers.
""",
                        'severity': 'HIGH',
                        'cwe': 'CWE-287',
                        'url': endpoint.url,
                        'technique': technique['name'],
                        'evidence': f"Request to {test_url} with {technique.get('method', 'GET')} method and {technique.get('headers', {})} headers returned 200 OK"
                    }
                    
                    # Add to results
                    bypass_results.append(bypass_info)
                    
                    # Add vulnerability to database
                    vuln = add_vulnerability(
                        domain,
                        bypass_info['title'],
                        bypass_info['description'],
                        'HIGH',
                        'CWE-287',
                        None,
                        endpoint.url,
                        bypass_info['evidence']
                    )
                    
                    if scan_id:
                        emit_scan_update(
                            scan_id,
                            f"Authentication bypass successful using {technique['name']} on {endpoint.url}",
                            "high"
                        )
            
            except Exception as e:
                if scan_id:
                    emit_scan_update(
                        scan_id, 
                        f"Error testing {technique['name']} on {endpoint.url}: {str(e)}", 
                        "error"
                    )
    
    return bypass_results

# ===== CORS TESTING =====

def test_cors_configuration(url, domain, scan_id=None):
    """
    Test for CORS misconfigurations
    Returns list of discovered vulnerabilities
    """
    vulnerabilities = []
    
    try:
        # Test with a common malicious origin
        test_origin = 'https://evil.example.com'
        
        # Prepare headers
        headers = {
            'Origin': test_origin,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Make the request
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Check for CORS misconfigurations
        acao_header = response.headers.get('Access-Control-Allow-Origin')
        acac_header = response.headers.get('Access-Control-Allow-Credentials')
        
        if acao_header:
            if scan_id:
                emit_scan_update(
                    scan_id, 
                    f"CORS header found: Access-Control-Allow-Origin: {acao_header}", 
                    "info"
                )
            
            # Check for dangerous wildcard origin
            if acao_header == '*':
                # Wildcard origin without credentials is less severe
                if not acac_header or acac_header.lower() != 'true':
                    vuln = add_vulnerability(
                        domain,
                        "CORS Misconfiguration: Wildcard Origin",
                        f"""The application allows requests from any origin using a wildcard Access-Control-Allow-Origin header.
                        
Access-Control-Allow-Origin: *

While not directly exploitable without credentials, this permissive configuration could potentially be used in combination with other vulnerabilities.

Recommendation: Restrict CORS to specific trusted domains instead of using a wildcard.
""",
                        'LOW',
                        'CWE-942',
                        None,
                        url,
                        f"Header: Access-Control-Allow-Origin: {acao_header}"
                    )
                    
                    vulnerabilities.append(vuln)
                    
                    if scan_id:
                        emit_scan_update(
                            scan_id,
                            f"CORS misconfiguration: Wildcard origin without credentials",
                            "low"
                        )
            # Check if the malicious origin was reflected
            elif acao_header == test_origin:
                # Reflected origin with credentials is very severe
                if acac_header and acac_header.lower() == 'true':
                    vuln = add_vulnerability(
                        domain,
                        "Critical CORS Misconfiguration: Origin Reflection with Credentials",
                        f"""The application dangerously reflects any origin in the Access-Control-Allow-Origin header while allowing credentials.
                        
Access-Control-Allow-Origin: {acao_header}
Access-Control-Allow-Credentials: {acac_header}

This is a critical vulnerability that allows attackers to perform authenticated CORS requests from malicious domains, potentially leading to account takeover or data theft.

Recommendation: Validate and whitelist allowed origins instead of reflecting any origin, and avoid combining origin reflection with Access-Control-Allow-Credentials: true.
""",
                        'CRITICAL',
                        'CWE-942',
                        None,
                        url,
                        f"Headers: Access-Control-Allow-Origin: {acao_header}, Access-Control-Allow-Credentials: {acac_header}"
                    )
                    
                    vulnerabilities.append(vuln)
                    
                    if scan_id:
                        emit_scan_update(
                            scan_id,
                            f"Critical CORS misconfiguration: Origin reflection with credentials",
                            "critical"
                        )
                else:
                    # Reflected origin without credentials is still concerning
                    vuln = add_vulnerability(
                        domain,
                        "CORS Misconfiguration: Origin Reflection",
                        f"""The application reflects any origin in the Access-Control-Allow-Origin header.
                        
Access-Control-Allow-Origin: {acao_header}

This configuration could potentially be used in combination with other vulnerabilities, though it's less severe without credentials.

Recommendation: Validate and whitelist allowed origins instead of reflecting any origin.
""",
                        'MEDIUM',
                        'CWE-942',
                        None,
                        url,
                        f"Header: Access-Control-Allow-Origin: {acao_header}"
                    )
                    
                    vulnerabilities.append(vuln)
                    
                    if scan_id:
                        emit_scan_update(
                            scan_id,
                            f"CORS misconfiguration: Origin reflection without credentials",
                            "medium"
                        )
        
        # Test for more unusual CORS misconfigurations if initial test didn't find issues
        if not vulnerabilities:
            # Try null origin
            null_headers = {
                'Origin': 'null',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            null_response = requests.get(url, headers=null_headers, timeout=10, verify=False)
            null_acao = null_response.headers.get('Access-Control-Allow-Origin')
            
            # Check for null origin acceptance
            if null_acao == 'null':
                vuln = add_vulnerability(
                    domain,
                    "CORS Misconfiguration: Null Origin Allowed",
                    f"""The application allows the 'null' origin in CORS, which can be exploited in certain scenarios.
                    
Access-Control-Allow-Origin: null

The 'null' origin can be sent by browser features like sandboxed iframes, data URLs, or file URLs, which can be used by attackers in some scenarios.

Recommendation: Validate and whitelist specific legitimate origins instead of allowing the 'null' origin.
""",
                    'MEDIUM',
                    'CWE-942',
                    None,
                    url,
                    f"Header: Access-Control-Allow-Origin: {null_acao}"
                )
                
                vulnerabilities.append(vuln)
                
                if scan_id:
                    emit_scan_update(
                        scan_id,
                        f"CORS misconfiguration: Null origin allowed",
                        "medium"
                    )
    
    except Exception as e:
        if scan_id:
            emit_scan_update(scan_id, f"Error during CORS testing: {str(e)}", "error")
    
    return vulnerabilities

# ===== HELPER FUNCTIONS =====

def add_technology(domain, tech_name, version=''):
    """Add technology to domain if it doesn't exist"""
    # Clean tech name
    tech_name = tech_name.strip()
    if not tech_name:
        return None
        
    tech = Technology.query.filter_by(name=tech_name).first()
    if not tech:
        tech = Technology(name=tech_name, version=version)
        db.session.add(tech)
    elif not tech.version and version:
        tech.version = version
    
    if tech not in domain.technologies:
        domain.technologies.append(tech)
        db.session.commit()
    
    return tech

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
    # Truncate URL if too long (database field limit)
    if len(url) > 512:
        url = url[:512]
    
    # Truncate path if too long
    if len(path) > 255:
        path = path[:255]
    
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
    elif existing_endpoint.status_code != status_code or existing_endpoint.content_type != content_type:
        # Update existing endpoint if needed
        existing_endpoint.status_code = status_code
        existing_endpoint.content_type = content_type
        existing_endpoint.is_interesting = is_interesting or existing_endpoint.is_interesting
        existing_endpoint.last_checked = datetime.utcnow()
        db.session.commit()
    
    return existing_endpoint

# ===== BATCH SCANNING =====

def scan_multiple_domains(urls, batch_size=10, scan_id=None, options=None):
    """
    Scan multiple domains with optimized concurrency and resource usage
    
    Args:
        urls (list): List of URLs to scan
        batch_size (int): Number of domains to scan in parallel
        scan_id (str): Base scan ID to use
        options (dict): Scan options
        
    Returns:
        list: List of scan results
    """
    all_results = []
    
    # Generate base scan ID if none provided
    if scan_id is None:
        scan_id = f"batch_scan_{int(time.time())}"
    
    # Group URLs into batches
    batches = [urls[i:i+batch_size] for i in range(0, len(urls), batch_size)]
    
    if socketio:
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'message': f"Starting batch scan for {len(urls)} domains in {len(batches)} batches",
            'status': "info",
            'timestamp': datetime.now().isoformat()
        })
    
    # Process each batch
    for batch_index, batch in enumerate(batches):
        batch_results = []
        threads = []
        batch_scan_id = f"{scan_id}_batch_{batch_index}"
        
        if socketio:
            socketio.emit('scan_update', {
                'scan_id': scan_id,
                'message': f"Processing batch {batch_index+1}/{len(batches)} ({len(batch)} domains)",
                'status': "info",
                'timestamp': datetime.now().isoformat()
            })
        
        # Create a thread for each domain in the batch
        for domain_index, url in enumerate(batch):
            domain_scan_id = f"{batch_scan_id}_domain_{domain_index}"
            
            # Queue the scan in a thread
            thread = threading.Thread(
                target=scan_domain_thread,
                args=(url, domain_scan_id, batch_results, options)
            )
            thread.daemon = True
            threads.append(thread)
        
        # Start all threads
        for thread in threads:
            thread.start()
            # Small delay to avoid hammering the same server with many requests
            time.sleep(0.5)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Add batch results to all results
        all_results.extend(batch_results)
        
        # Add a delay between batches to be nice to servers
        if batch_index < len(batches) - 1:
            time.sleep(2)
    
    if socketio:
        socketio.emit('scan_update', {
            'scan_id': scan_id,
            'message': f"Completed batch scan for {len(urls)} domains. Found {sum(1 for r in all_results if r.get('vulnerabilities'))} domains with vulnerabilities.",
            'status': "success",
            'timestamp': datetime.now().isoformat()
        })
    
    return all_results

def scan_domain_thread(url, scan_id, results_list, options=None):
    """Thread worker function to scan a domain and add results to a shared list"""
    try:
        # Run the enhanced scan
        result = enhanced_scan(url, scan_id, options)
        
        # Add to results list (thread-safe append)
        results_list.append(result)
    except Exception as e:
        # Log the error
        print(f"Error scanning {url}: {str(e)}")
        
        # Add error result
        results_list.append({
            'domain': url,
            'status': 'ERROR',
            'error': str(e),
            'technologies': [],
            'vulnerabilities': [],
            'endpoints': []
        })
        
        # Emit error if socketio is available
        if socketio:
            socketio.emit('scan_update', {
                'scan_id': scan_id,
                'message': f"Error scanning {url}: {str(e)}",
                'status': "error",
                'timestamp': datetime.now().isoformat()
            })

# ===== MAIN ENTRY POINT =====

def basic_scan(url, scan_id=None):
    """
    Main entry point for basic scanning (replaces the old basic_scanner.py function)
    This function calls the enhanced scanner with default options
    """
    return enhanced_scan(url, scan_id)  