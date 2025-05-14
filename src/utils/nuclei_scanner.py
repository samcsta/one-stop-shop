"""
Nuclei Scanner implementation for vulnerability detection.

This module focuses solely on running Nuclei scans for vulnerability detection,
separate from the basic scanning functionality.
"""

import os
import json
import subprocess
import tempfile
import re
import time
from datetime import datetime
from urllib.parse import urlparse
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

def nuclei_scan(url, scan_id=None, scan_options=None, severity_levels=None):
    """
    Perform a nuclei scan with options
    """
    # Default values
    if scan_options is None or not scan_options[0]:
        scan_options = ['cves', 'vulnerabilities', 'misconfiguration', 'exposures', 'technologies']
    
    if severity_levels is None or not severity_levels[0]:
        severity_levels = ['critical', 'high', 'medium']
    
    # Generate a scan ID if none provided
    if scan_id is None:
        scan_id = f"nuclei_scan_{int(time.time())}"
    
    # Normalize URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    domain_name = url.split('//')[-1].split('/')[0]
    
    emit_scan_update(scan_id, f"Starting nuclei scan for {url}", "info")
    emit_scan_update(scan_id, f"Using options: {', '.join(scan_options)}", "info")
    emit_scan_update(scan_id, f"Severity levels: {', '.join(severity_levels)}", "info")
    
    # Check if domain exists in database
    domain = Domain.query.filter_by(url=domain_name).first()
    if not domain:
        domain = Domain(url=domain_name)
        db.session.add(domain)
        db.session.commit()
        emit_scan_update(scan_id, f"Added new domain {domain_name} to database", "info")
    
    # Initialize results
    result = {
        'domain': domain_name,
        'status': 'UNKNOWN',
        'technologies': [],
        'vulnerabilities': []
    }
    
    # First check if site is active
    is_active = check_site_active(url, scan_id)
    
    domain.status = 'ACTIVE' if is_active else 'INACTIVE'
    domain.last_scanned = datetime.utcnow()
    db.session.commit()
    
    result['status'] = domain.status
    
    if not is_active:
        emit_scan_update(scan_id, f"Site is inactive. Nuclei scan aborted.", "warning")
        return result
    
    # Run nuclei scan
    emit_scan_update(scan_id, f"Running nuclei scan...", "info")
    nuclei_results = run_nuclei_scanning(domain, url, scan_id, scan_options, severity_levels)
    
    result['technologies'] = [t.name for t in domain.technologies]
    result['vulnerabilities'] = [v.title for v in domain.vulnerabilities]
    
    emit_scan_update(scan_id, f"Nuclei scan completed for {url}", "success")
    return result

def check_site_active(url, scan_id):
    """Check if a site is active by making HTTP requests"""
    emit_scan_update(scan_id, f"Testing connection to {url}...", "info")
    
    try:
        # Disable SSL warnings
        import requests
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

def run_nuclei_scanning(domain, url, scan_id, scan_options, severity_levels):
    """Run Nuclei scan for vulnerabilities and technologies"""
    # Create temp file for Nuclei output
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_output:
        temp_output_path = temp_output.name
    
    results = {'vulnerabilities': [], 'technologies': []}
    
    try:
        # First, detect technologies
        if 'technologies' in scan_options:
            emit_scan_update(scan_id, f"Detecting technologies...", "info")
            detect_technologies(url, domain, scan_id)
            emit_scan_update(
                scan_id, 
                f"Technologies detected: {', '.join([t.name for t in domain.technologies]) or 'None'}", 
                "info"
            )
        
        # Then, run vulnerability scan with selected options
        scan_template_options = []
        for option in scan_options:
            if option != 'technologies':  # Skip technologies as we handle it separately
                scan_template_options.append(option)
        
        if scan_template_options:
            emit_scan_update(
                scan_id, 
                f"Running nuclei scan with options: {', '.join(scan_template_options)}", 
                "info"
            )
            
            # Run nuclei scan
            run_nuclei_scan(url, temp_output_path, scan_template_options, severity_levels, scan_id)
            
            # Process nuclei results
            emit_scan_update(scan_id, f"Processing scan results...", "info")
            vulnerabilities = process_nuclei_results(temp_output_path, domain.id, scan_id)
            
            if vulnerabilities:
                emit_scan_update(
                    scan_id, 
                    f"Found {len(vulnerabilities)} vulnerabilities", 
                    "warning" if vulnerabilities else "info"
                )
                for vuln in vulnerabilities:
                    severity_class = "critical" if vuln.severity == "CRITICAL" else vuln.severity.lower()
                    emit_scan_update(
                        scan_id, 
                        f"{vuln.severity}: {vuln.title} - {vuln.location}", 
                        severity_class
                    )
                
                results['vulnerabilities'] = vulnerabilities
            else:
                emit_scan_update(scan_id, f"No vulnerabilities found", "info")
    
    except Exception as e:
        emit_scan_update(scan_id, f"Error during nuclei scan: {str(e)}", "error")
    
    finally:
        # Clean up temp file
        if os.path.exists(temp_output_path):
            try:
                os.unlink(temp_output_path)
            except:
                pass
    
    domain.last_scanned = datetime.utcnow()
    db.session.commit()
    
    return results

def detect_technologies(url, domain, scan_id=None):
    """Detect technologies using nuclei tech-detect templates"""
    # Create temp file for technology detection output
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as temp_output:
        temp_output_path = temp_output.name
    
    try:
        if scan_id:
            emit_scan_update(scan_id, f"Running technology detection...", "info")
        
        nuclei_cmd = 'nuclei'  # assuming nuclei is installed and in PATH
        
        # Run Nuclei with tech-detect templates
        try:
            cmd_list = [
                nuclei_cmd, 
                '-u', url, 
                '-t', 'technologies',
                '-o', temp_output_path,
                '-j',
                '-s', 'info',
                '-no-interactsh',  # Speed improvement
                '-c', '25',        # Speed improvement
                '-rl', '150',      # Speed improvement
                '-timeout', '3'    # Speed improvement
            ]
            
            if scan_id:
                emit_scan_update(scan_id, f"Executing: {' '.join(cmd_list)}", "debug")
            
            process = subprocess.Popen(
                cmd_list,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Stream output for real-time updates
            for line in process.stdout:
                line = line.strip()
                if scan_id and line:
                    emit_scan_update(scan_id, f"nuclei-tech: {line}", "debug")
                    # Also print to console
                    print(f"[{scan_id}] {line}")
            
            # Wait for process to complete
            process.wait()
            
            # Process technology detection results
            if os.path.exists(temp_output_path) and os.path.getsize(temp_output_path) > 0:
                tech_count = 0
                with open(temp_output_path, 'r') as f:
                    for line in f:
                        try:
                            result = json.loads(line)
                            if 'info' in result and 'name' in result['info']:
                                tech_name = result['info']['name']
                                tech_version = result['info'].get('version', '')
                                
                                # Clean up tech name
                                tech_name = tech_name.replace('tech-detect:', '').strip()
                                
                                # Add technology to domain
                                add_technology(domain, tech_name, tech_version)
                                tech_count += 1
                                
                                if scan_id:
                                    emit_scan_update(
                                        scan_id, 
                                        f"Detected technology: {tech_name}{' ' + tech_version if tech_version else ''}", 
                                        "info"
                                    )
                        except json.JSONDecodeError:
                            continue
                
                if tech_count == 0 and scan_id:
                    emit_scan_update(scan_id, f"No technologies detected by nuclei", "info")
                
        except Exception as e:
            if scan_id:
                emit_scan_update(scan_id, f"Error running nuclei for technology detection: {str(e)}", "error")
        
        # Clean up temp file
        if os.path.exists(temp_output_path):
            try:
                os.unlink(temp_output_path)
            except:
                pass
        
        # Fallback to HTTP headers for basic tech detection if no technologies found
        if not domain.technologies:
            if scan_id:
                emit_scan_update(scan_id, f"No technologies detected by nuclei, falling back to basic detection", "info")
            
            try:
                import requests
                requests.packages.urllib3.disable_warnings()
                response = requests.get(url, timeout=10, verify=False)
                
                # Basic detection from headers
                if 'Server' in response.headers:
                    server = response.headers['Server']
                    add_technology(domain, server)
                    if scan_id:
                        emit_scan_update(scan_id, f"Detected server from headers: {server}", "info")
                
                if 'X-Powered-By' in response.headers:
                    powered_by = response.headers['X-Powered-By']
                    add_technology(domain, powered_by)
                    if scan_id:
                        emit_scan_update(scan_id, f"Detected X-Powered-By from headers: {powered_by}", "info")
                
            except Exception as e:
                if scan_id:
                    emit_scan_update(scan_id, f"Error in basic technology detection: {str(e)}", "error")
        
    except Exception as e:
        if scan_id:
            emit_scan_update(scan_id, f"Error detecting technologies: {str(e)}", "error")
    
    db.session.commit()

def run_nuclei_scan(url, output_path, scan_options, severity_levels, scan_id=None):
    """Run Nuclei scanner against a domain with optimized settings for speed"""
    nuclei_cmd = 'nuclei'  # assuming nuclei is installed and in PATH
    
    try:
        # Join the template options with comma
        templates_arg = ','.join(scan_options)
        severity_arg = ','.join(severity_levels)
        
        # Add custom templates directory if it exists
        template_paths = [templates_arg]
        custom_dir = os.path.join(os.getcwd(), 'custom-templates')
        if os.path.exists(custom_dir) and os.path.isdir(custom_dir):
            template_paths.append(custom_dir)
        
        templates_arg = ','.join(template_paths)
        
        # Set up Nuclei command with optimized settings for speed
        nuclei_cmd_list = [
            nuclei_cmd,
            '-u', url,
            '-t', templates_arg,
            '-s', severity_arg,  
            '-o', output_path,
            '-j',  # Output in JSON format
            '-rl', '150',  # Increased rate limit (default was 50)
            '-c', '25',  # Increased concurrency (default was 10)
            '-timeout', '3',  # Reduced timeout (default was 5)
            '-max-host-error', '20',  # Increased max host errors
            '-no-interactsh',  # Disable interactsh polling to speed up scanning
            '-no-color',  # Disable color to avoid ANSI codes in output
            '-bs', '100',  # Bulk size increased for faster scanning
            '-stats'  # Show statistics (helpful to see progress)
        ]
        
        if scan_id:
            # Use both print and emit to ensure logs appear in both terminals
            command_str = ' '.join(nuclei_cmd_list)
            print(f"[{scan_id}] Executing: {command_str}")
            emit_scan_update(scan_id, f"Executing: {command_str}", "debug")
        
        # Run Nuclei scan with streaming output to both terminals
        process = subprocess.Popen(
            nuclei_cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered for real-time output
            universal_newlines=True
        )
        
        # Stream output in real-time to both terminals
        for line in process.stdout:
            line = line.strip()
            if line:
                # Print to VSCode terminal
                print(f"[{scan_id}] {line}")
                
                # Send to browser terminal via Socket.IO
                if scan_id:
                    # Determine message type based on content
                    if "[critical]" in line.lower():
                        status = "critical"
                    elif "[high]" in line.lower():
                        status = "high"
                    elif "[medium]" in line.lower():
                        status = "medium"
                    elif "[low]" in line.lower():
                        status = "low"
                    elif "[info]" in line.lower():
                        status = "info"
                    elif "[warning]" in line.lower() or "[warn]" in line.lower():
                        status = "warning"
                    elif "[debug]" in line.lower():
                        status = "debug"
                    elif "[error]" in line.lower():
                        status = "error"
                    else:
                        status = "info"
                    
                    emit_scan_update(scan_id, f"nuclei: {line}", status)
        
        # Wait for the process to complete and get return code
        returncode = process.wait()
        
        # Read any error output
        stderr = process.stderr.read()
        
        if returncode != 0 and stderr:
            print(f"[{scan_id}] Nuclei scan warning/error: {stderr}")
            if scan_id:
                emit_scan_update(scan_id, f"Nuclei scan warning/error: {stderr}", "warning")
    
    except Exception as e:
        print(f"[{scan_id}] Error running Nuclei scan: {str(e)}")
        if scan_id:
            emit_scan_update(scan_id, f"Error running Nuclei scan: {str(e)}", "error")
        raise

def process_nuclei_results(output_path, domain_id, scan_id=None):
    """Process Nuclei scan results and add vulnerabilities to the database"""
    vulnerabilities = []
    
    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        if scan_id:
            emit_scan_update(scan_id, f"No Nuclei results found in output file", "info")
        return vulnerabilities
    
    try:
        with open(output_path, 'r') as f:
            line_count = 0
            for line in f:
                line_count += 1
                try:
                    result = json.loads(line)
                    
                    if scan_id:
                        emit_scan_update(
                            scan_id, 
                            f"Processing result {line_count}: {result.get('info', {}).get('name', 'Unknown')}", 
                            "debug"
                        )
                    
                    # Map Nuclei finding to our vulnerability model
                    vuln_title = result.get('info', {}).get('name', 'Unknown Vulnerability')
                    vuln_description = result.get('info', {}).get('description', '')
                    vuln_severity = map_severity(result.get('info', {}).get('severity', 'unknown'))
                    
                    # Extract CWE and CVE
                    cwe = None
                    cve = None
                    
                    # Check for CVE in the name or matcher_name
                    cve_pattern = r'CVE-\d{4}-\d{4,7}'
                    cve_match = re.search(cve_pattern, vuln_title)
                    if not cve_match and 'matcher_name' in result:
                        cve_match = re.search(cve_pattern, result.get('matcher_name', ''))
                    if cve_match:
                        cve = cve_match.group(0)
                    
                    # Check for CWE in the description
                    cwe_pattern = r'CWE-\d{1,4}'
                    cwe_match = re.search(cwe_pattern, vuln_description)
                    if cwe_match:
                        cwe = cwe_match.group(0)
                    
                    # Extract location and evidence
                    location = result.get('matched-at', result.get('host', ''))
                    
                    # Gather detailed evidence
                    evidence_parts = []
                    
                    # Add request information if available
                    if 'request' in result and isinstance(result['request'], dict):
                        req = result['request']
                        if 'method' in req:
                            evidence_parts.append(f"Method: {req['method']}")
                        if 'path' in req:
                            evidence_parts.append(f"Path: {req['path']}")
                        if 'headers' in req and isinstance(req['headers'], dict):
                            evidence_parts.append("Request Headers:")
                            for key, value in req['headers'].items():
                                evidence_parts.append(f"  {key}: {value}")
                        if 'body' in req and req['body']:
                            evidence_parts.append(f"Request Body: {req['body']}")
                    
                    # Add response information if available
                    if 'response' in result and isinstance(result['response'], dict):
                        resp = result['response']
                        if 'status_code' in resp:
                            evidence_parts.append(f"Response Status: {resp['status_code']}")
                        if 'headers' in resp and isinstance(resp['headers'], dict):
                            evidence_parts.append("Response Headers:")
                            for key, value in resp['headers'].items():
                                evidence_parts.append(f"  {key}: {value}")
                        if 'body' in resp and resp['body']:
                            # Truncate body if too long
                            body = resp['body']
                            if len(body) > 1000:
                                body = body[:1000] + "... [truncated]"
                            evidence_parts.append(f"Response Body:\n{body}")
                    
                    # Add matcher information
                    if 'matcher_name' in result:
                        evidence_parts.append(f"Matcher: {result['matcher_name']}")
                    
                    # Add extracted results
                    if 'extracted-results' in result and result['extracted-results']:
                        evidence_parts.append("Extracted results:")
                        for er in result['extracted-results']:
                            evidence_parts.append(f"- {er}")
                    
                    # Add curl command for reproducibility
                    if 'curl-command' in result:
                        evidence_parts.append(f"CURL command: {result['curl-command']}")
                    
                    evidence = "\n".join(evidence_parts)
                    
                    # Add the vulnerability
                    vuln = add_vulnerability(
                        Domain.query.get(domain_id),
                        vuln_title,
                        vuln_description,
                        vuln_severity,
                        cwe,
                        cve,
                        location,
                        evidence
                    )
                    
                    vulnerabilities.append(vuln)
                    
                    if scan_id:
                        emit_scan_update(
                            scan_id, 
                            f"Added vulnerability: {vuln_title} ({vuln_severity})", 
                            "warning" if vuln_severity in ['CRITICAL', 'HIGH'] else "info"
                        )
                
                except json.JSONDecodeError:
                    if scan_id:
                        emit_scan_update(scan_id, f"Error parsing JSON result", "warning")
                    continue
                except Exception as e:
                    if scan_id:
                        emit_scan_update(scan_id, f"Error processing result: {str(e)}", "error")
                
        db.session.commit()
        return vulnerabilities
    
    except Exception as e:
        if scan_id:
            emit_scan_update(scan_id, f"Error processing Nuclei results: {str(e)}", "error")
        return vulnerabilities

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

def map_severity(nuclei_severity):
    """Map severity levels to our database schema severity levels"""
    severity_mapping = {
        'info': 'LOW',
        'low': 'LOW',
        'medium': 'MEDIUM',
        'high': 'HIGH',
        'critical': 'CRITICAL',
        'unknown': 'MEDIUM'  # Default
    }
    return severity_mapping.get(nuclei_severity.lower(), 'MEDIUM')