import os
import json
import subprocess
import shutil
import random
import time
import threading
import re
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, current_app # Added current_app
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename
from bs4 import BeautifulSoup
from config import Config
from models import db, Domain, Technology, Vulnerability, Endpoint, Screenshot, APIBypass

# Import scanner utilities
import utils.basic_scanner as basic_scanner
import utils.nuclei_scanner as nuclei_scanner
import utils.api_bypass as api_bypass

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

# Initialize SocketIO AFTER app and config are set
socketio = SocketIO(app)

# Initialize scanner utilities with SocketIO instance
basic_scanner.init_socketio(socketio)
nuclei_scanner.init_socketio(socketio)
# api_bypass doesn't seem to use socketio directly based on the provided code

# Ensure upload/wordlist/template directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['WORDLISTS_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(os.getcwd(), 'custom-templates'), exist_ok=True)

# Constants (Consider moving to config if they grow)
MAIN_JS_PATTERNS = [
    r'main\.[0-9a-f]+\.js',
    r'main[-_]bundle.*\.js',
    r'main\.js$',
    r'app\.[0-9a-f]+\.js',
    r'app[-_]bundle.*\.js',
    r'app\.js$',
    r'runtime\.[0-9a-f]+\.js',
    r'polyfills\.[0-9a-f]+\.js'
]

# Create database tables if they don't exist
# This needs the app context
with app.app_context():
    db.create_all()

# --- Helper Functions ---
def ensure_protocol(url):
    """Adds https:// if no protocol is present."""
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url

def normalize_domain_name(url_or_domain):
    """Extracts and normalizes the domain name (lowercase, no www)."""
    if not url_or_domain:
        return None
    try:
        # Ensure protocol for parsing
        full_url = ensure_protocol(url_or_domain)
        parsed_uri = urlparse(full_url)
        domain_name = parsed_uri.hostname
        if not domain_name:
             # Fallback for simple domains without protocol
             domain_name = (parsed_uri.netloc or parsed_uri.path.split('/')[0])
        
        if domain_name:
             # Remove port and convert to lowercase
             domain_name = domain_name.split(':')[0].lower()
             # Remove www.
             if domain_name.startswith('www.'):
                 domain_name = domain_name[4:]
             return domain_name
        else:
             return None # Failed to extract domain
             
    except Exception as e:
        print(f"Error normalizing domain '{url_or_domain}': {e}")
        return None

def run_scan_in_thread(target_function, *args):
    """Starts a function in a background thread with app context."""
    # Create a copy of the app context
    app_context = current_app.app_context()
    
    def thread_target():
        # Activate the app context within the thread
        with app_context:
            try:
                target_function(*args)
            except Exception as e:
                # Log any exception that occurs within the thread
                scan_id = args[1] if len(args) > 1 else 'unknown_scan' # Assuming scan_id is the second arg
                error_message = f"Error in background thread for scan '{scan_id}': {e}"
                print(error_message)
                # Optionally emit an error via SocketIO if possible
                if 'basic_scanner' in str(target_function):
                    basic_scanner.emit_scan_update(scan_id, error_message, "error")
                elif 'nuclei_scanner' in str(target_function):
                     nuclei_scanner.emit_scan_update(scan_id, error_message, "error")
                # Handle other scanner types if needed
                
    thread = threading.Thread(target=thread_target)
    thread.daemon = True
    thread.start()
    return thread # Optionally return the thread object


# --- Routes ---

@app.route('/')
def dashboard():
    try:
        total_domains = Domain.query.count()
        active_domains = Domain.query.filter_by(status='ACTIVE').count()
        inactive_domains = Domain.query.filter_by(status='INACTIVE').count()
        
        vulnerabilities = Vulnerability.query.all()
        total_vulnerabilities = len(vulnerabilities)
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1
        
        domains_by_status = {
            'NEW': Domain.query.filter_by(assessment_status='NEW').count(),
            'IN PROGRESS': Domain.query.filter_by(assessment_status='IN PROGRESS').count(),
            'FINISHED': Domain.query.filter_by(assessment_status='FINISHED').count(),
            'FALSE ALARM': Domain.query.filter_by(assessment_status='FALSE ALARM').count()
        }
        
        recent_vulnerabilities = Vulnerability.query.order_by(Vulnerability.date_discovered.desc()).limit(5).all()
        
        return render_template('dashboard.html', 
                              total_domains=total_domains,
                              active_domains=active_domains,
                              inactive_domains=inactive_domains,
                              total_vulnerabilities=total_vulnerabilities,
                              severity_counts=severity_counts,
                              domains_by_status=domains_by_status,
                              recent_vulnerabilities=recent_vulnerabilities)
    except Exception as e:
        print(f"Error loading dashboard: {e}")
        flash("Error loading dashboard data.", "danger")
        # Provide default values or render an error template
        return render_template('dashboard.html', 
                              total_domains=0, active_domains=0, inactive_domains=0, total_vulnerabilities=0,
                              severity_counts={'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                              domains_by_status={'NEW': 0, 'IN PROGRESS': 0, 'FINISHED': 0, 'FALSE ALARM': 0},
                              recent_vulnerabilities=[])


@app.route('/domains')
def domains():
    try:
        query = Domain.query
        
        tech_filter = request.args.get('technology')
        status_filter = request.args.get('status')
        assessment_filter = request.args.get('assessment')
        
        if tech_filter:
            # Ensure filtering by technology name associated with the domain
            query = query.join(Domain.technologies).filter(Technology.name == tech_filter)
        
        if status_filter:
            query = query.filter(Domain.status == status_filter)
        
        if assessment_filter:
            query = query.filter(Domain.assessment_status == assessment_filter)
        
        domains = query.order_by(Domain.last_scanned.desc()).all()
        technologies = Technology.query.order_by(Technology.name).all()
        
        return render_template('domains.html', domains=domains, technologies=technologies)
    except Exception as e:
         print(f"Error loading domains page: {e}")
         flash("Error loading domains list.", "danger")
         return render_template('domains.html', domains=[], technologies=[])


@app.route('/domain/<int:id>')
def domain_details(id):
    domain = db.get_or_404(Domain, id) # Use newer get_or_404
    return render_template('domain_details.html', domain=domain)


@app.route('/domain/<int:id>/update', methods=['POST'])
def update_domain(id):
    domain = db.get_or_404(Domain, id)
    
    try:
        if 'status' in request.form:
            new_status = request.form['status']
            # Basic validation for assessment status
            if new_status in ['NEW', 'IN PROGRESS', 'FINISHED', 'FALSE ALARM']:
                domain.assessment_status = new_status
            else:
                 flash(f"Invalid assessment status '{new_status}' ignored.", "warning")

        if 'notes' in request.form:
            domain.notes = request.form['notes']
        
        if 'claim' in request.form:
            # Replace with actual user later if auth is added
            domain.assigned_to = "Current User" 
        
        if 'unclaim' in request.form:
            domain.assigned_to = None
        
        db.session.commit()
        flash(f'Domain {domain.url} updated successfully!', 'success')
    except Exception as e:
         db.session.rollback()
         flash(f'Error updating domain: {str(e)}', 'danger')
         print(f"Error updating domain {id}: {e}")

    return redirect(url_for('domain_details', id=domain.id))


@app.route('/domain/<int:id>/delete', methods=['POST'])
def delete_domain(id):
    domain = db.get_or_404(Domain, id)
    domain_url = domain.url # Store url before deleting
    
    try:
        # Delete related records first (cascade might handle this depending on DB setup)
        # Explicit deletion is safer across different DBs
        Vulnerability.query.filter_by(domain_id=id).delete()
        
        screenshots = Screenshot.query.filter_by(domain_id=id).all()
        for screenshot in screenshots:
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], screenshot.filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception as file_err:
                # Log error but continue deletion
                print(f'Error deleting screenshot file {screenshot.filename}: {str(file_err)}')
                flash(f'Warning: Could not delete screenshot file: {screenshot.filename}', 'warning')
        
        Screenshot.query.filter_by(domain_id=id).delete()
        Endpoint.query.filter_by(domain_id=id).delete()
        APIBypass.query.filter_by(domain_id=id).delete()
        
        # Remove associations in the tags table
        domain.technologies = []
        db.session.commit() # Commit removal of associations

        # Delete the domain itself
        db.session.delete(domain)
        db.session.commit() # Commit domain deletion
        
        flash(f'Domain {domain_url} and all its data have been deleted successfully!', 'success')
    except Exception as e:
         db.session.rollback()
         flash(f'Error deleting domain and its data: {str(e)}', 'danger')
         print(f"Error deleting domain {id}: {e}")

    return redirect(url_for('domains'))


@app.route('/domain/<int:id>/upload', methods=['POST'])
def upload_screenshot(id):
    domain = db.get_or_404(Domain, id)
    
    if 'screenshot' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('domain_details', id=id))
    
    file = request.files['screenshot']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('domain_details', id=id))
    
    # Optional: Add file type validation here
    # allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    # if '.' not in file.filename or file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
    #     flash('Invalid file type. Allowed types: png, jpg, jpeg, gif', 'danger')
    #     return redirect(url_for('domain_details', id=id))
        
    if file:
        try:
            filename = secure_filename(file.filename)
            # Add timestamp to prevent filename conflicts
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            # Optional: Add file size validation from app.config['MAX_CONTENT_LENGTH']
            # file.seek(0, os.SEEK_END)
            # file_length = file.tell()
            # file.seek(0, 0) # Reset file pointer
            # if file_length > app.config['MAX_CONTENT_LENGTH']:
            #     flash(f'File size exceeds limit ({app.config["MAX_CONTENT_LENGTH"] / 1024 / 1024} MB)', 'danger')
            #     return redirect(url_for('domain_details', id=id))
                
            file.save(file_path)
            
            screenshot = Screenshot(
                domain_id=domain.id,
                filename=unique_filename, # Save the unique filename
                description=request.form.get('description', '')
            )
            
            db.session.add(screenshot)
            db.session.commit()
            
            flash('Screenshot uploaded successfully!', 'success')
        except Exception as e:
             db.session.rollback()
             flash(f'Error uploading or saving screenshot: {str(e)}', 'danger')
             print(f"Error uploading screenshot for domain {id}: {e}")
    
    return redirect(url_for('domain_details', id=id))


@app.route('/workspace')
def workspace():
    try:
        # Assuming "Current User" for now, replace with actual user ID if implementing auth
        assigned_user = "Current User" 
        domains = Domain.query.filter_by(assigned_to=assigned_user).order_by(Domain.last_scanned.desc()).all()
        return render_template('workspace.html', domains=domains)
    except Exception as e:
         print(f"Error loading workspace: {e}")
         flash("Error loading workspace data.", "danger")
         return render_template('workspace.html', domains=[])


@app.route('/basic-scanner')
def basic_scanner_page():
    domain_to_scan = request.args.get('domain', '')
    autorun = request.args.get('autorun', 'false').lower() == 'true'
    return render_template('basic_scanner.html', 
                          domain_to_scan=domain_to_scan,
                          autorun=autorun)


@app.route('/nuclei-scanner')
def nuclei_scanner_page():
    domain_to_scan = request.args.get('domain', '')
    autorun = request.args.get('autorun', 'false').lower() == 'true'
    return render_template('nuclei_scanner.html', 
                          domain_to_scan=domain_to_scan,
                          autorun=autorun)

# --- Scanner Routes ---

# Modified route to handle single or list input
@app.route('/run-basic-scan', methods=['POST'])
def run_basic_scan():
    single_domain = request.form.get('domain', '').strip()
    domain_list_str = request.form.get('domain_list', '').strip() # New field for list

    domains_to_scan = []
    if single_domain:
        domains_to_scan.append(single_domain)
    elif domain_list_str:
        domains_to_scan = [d.strip() for d in domain_list_str.splitlines() if d.strip()]
    
    if not domains_to_scan:
        return jsonify({"error": "No domain(s) provided"}), 400

    scan_group_id = f"basic_scan_group_{int(time.time())}"
    started_scans = 0
    
    # Loop through domains and start a thread for each
    for i, domain_url in enumerate(domains_to_scan):
        if not domain_url:
            continue

        # Use a unique scan ID for each domain in the list/batch
        scan_id = f"{scan_group_id}_{i}" 
        print(f"Initiating basic scan for: {domain_url} with scan_id: {scan_id}")
        
        # Use the helper to run in thread with context
        run_scan_in_thread(basic_scanner.basic_scan, domain_url, scan_id)
        started_scans += 1
        # Optional: Add a small delay between starting threads if needed
        # time.sleep(0.1) 

    if started_scans == 0:
         return jsonify({"error": "No valid domains found to scan"}), 400
         
    # Return a response indicating scans have started
    return jsonify({
        "message": f"Basic scan started for {started_scans} domain(s).", 
        "scan_group_id": scan_group_id
    })

# Kept the batch route, but the main route now handles lists too. 
# Consider consolidating or differentiating functionality.
@app.route('/run-basic-scan-batch', methods=['POST'])
def run_basic_scan_batch():
    data = request.get_json()
    if not data or 'domains' not in data:
        return jsonify({"error": "No domains list provided in JSON body"}), 400
    
    domains = data.get('domains', [])
    batch_size = data.get('batch_size', 10) # This doesn't do much if we start threads individually
    delay = data.get('delay', 0.1) # Delay between starting threads
    
    domains_to_scan = [d.strip() for d in domains if isinstance(d, str) and d.strip()]
    
    if not domains_to_scan:
        return jsonify({"error": "No valid domains found in the list"}), 400
        
    batch_id = f"batch_scan_{int(time.time())}"
    started_scans = 0
    
    print(f"Starting batch scan (ID: {batch_id}) for {len(domains_to_scan)} domains...")

    for i, domain_url in enumerate(domains_to_scan):
        scan_id = f"{batch_id}_{i}"
        print(f"Initiating scan for {domain_url} (Scan ID: {scan_id})")
        run_scan_in_thread(basic_scanner.basic_scan, domain_url, scan_id)
        started_scans += 1
        if delay > 0:
             time.sleep(delay)
             
    return jsonify({
        "message": f"Batch scan initiated for {started_scans} domains.",
        "batch_id": batch_id
    })


@app.route('/run-nuclei-scan', methods=['POST'])
def run_nuclei_scan():
    domain_url = request.form.get('domain', '').strip()
    scan_options_str = request.form.get('scan_options', '')
    severity_levels_str = request.form.get('severity_levels', '')
    
    scan_options = [opt for opt in scan_options_str.split(',') if opt]
    severity_levels = [lvl for lvl in severity_levels_str.split(',') if lvl]
    
    if not domain_url:
        return jsonify({"error": "No domain provided"}), 400
    
    # Default options if none provided (consider if this is desired)
    if not scan_options:
         scan_options = ['cves', 'vulnerabilities', 'misconfiguration', 'exposures', 'technologies']
    if not severity_levels:
         severity_levels = ['critical', 'high', 'medium']
         
    scan_id = f"nuclei_scan_{int(time.time())}"
    print(f"Initiating Nuclei scan for: {domain_url} with scan_id: {scan_id}")
    
    # Use helper to run in thread with context
    run_scan_in_thread(nuclei_scanner.nuclei_scan, domain_url, scan_id, scan_options, severity_levels)
    
    # Find domain ID immediately if possible (domain might be created by scanner)
    # Note: Domain might not exist *yet* when this runs, scanner thread handles creation
    domain_id = None
    normalized_domain = normalize_domain_name(domain_url)
    if normalized_domain:
        temp_domain = Domain.query.filter_by(url=normalized_domain).first()
        domain_id = temp_domain.id if temp_domain else None
    
    return jsonify({
        "message": "Nuclei scan started", 
        "scan_id": scan_id,
        "domain": domain_url,
        "domain_id": domain_id # Include domain_id if found *at this moment*
    })

# --- Main.js Analyzer Routes ---

@app.route('/mainjs-analyzer')
def mainjs_analyzer_page():
    domains_with_mainjs = []
    selected_domain = None
    try:
        # Query domains that have at least one endpoint matching known patterns
        # This uses SQLAlchemy's relationship features
        domains_query = Domain.query.join(Endpoint).filter(
            # Combine patterns into a single OR condition for efficiency
            db.or_(*[Endpoint.url.like(f"%{pattern.replace('.*', '%').replace('.js', '%.js')}%") for pattern in MAIN_JS_PATTERNS])
        ).distinct().all()
        
        # Get all domain objects found by the query
        domains_with_mainjs = domains_query

        selected_domain_id = request.args.get('domain_id')
        if selected_domain_id:
            try:
                selected_domain = db.get_or_404(Domain, int(selected_domain_id))
            except (ValueError, TypeError):
                flash("Invalid Domain ID format provided.", "warning")
    except Exception as e:
         print(f"Error loading main.js analyzer page data: {e}")
         flash("Error loading data for Main.js Analyzer.", "danger")

    return render_template('mainjs_analyzer.html', 
                          domains=domains_with_mainjs,
                          selected_domain=selected_domain)


@app.route('/get-mainjs-content/<int:domain_id>')
def get_mainjs_content(domain_id):
    domain = db.get_or_404(Domain, domain_id)
    mainjs_endpoint = find_mainjs_in_endpoints(domain_id)
    
    if not mainjs_endpoint:
        return jsonify({"error": "No main.js file found for this domain"}), 404
    
    # Use a consistent session for requests
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'}) # Basic user agent
    requests.packages.urllib3.disable_warnings() # Disable SSL warnings
    
    try:
        response = session.get(mainjs_endpoint.url, timeout=20, verify=False, stream=True)
        response.raise_for_status()

        content_type = response.headers.get('Content-Type', '').lower()
        if 'javascript' not in content_type and 'text/plain' not in content_type:
             print(f"Warning: Unexpected content type '{content_type}' for {mainjs_endpoint.url}")

        # Read content efficiently
        content = "".join(chunk.decode('utf-8', errors='ignore') for chunk in response.iter_content(chunk_size=8192))

        return jsonify({"url": mainjs_endpoint.url, "content": content})
        
    except requests.exceptions.RequestException as e:
        print(f"Error fetching main.js ({mainjs_endpoint.url}): {e}")
        return jsonify({"error": f"Error fetching main.js: {str(e)}"}), 500
    except Exception as e:
        print(f"Unexpected error fetching main.js ({mainjs_endpoint.url}): {e}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400
    
    url = ensure_protocol(data['url'])
    main_js_url = None
    main_js_content = None
    error_message = None
    
    # Use a consistent session
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    requests.packages.urllib3.disable_warnings()
    
    try:
        main_js_url = find_mainjs_in_html(url, session) # Pass session
        
        if main_js_url:
            try:
                response = session.get(main_js_url, timeout=20, verify=False, stream=True)
                response.raise_for_status()
                
                content_type = response.headers.get('Content-Type', '').lower()
                if 'javascript' not in content_type and 'text/plain' not in content_type:
                    print(f"Warning: Unexpected content type '{content_type}' for {main_js_url}")

                main_js_content = "".join(chunk.decode('utf-8', errors='ignore') for chunk in response.iter_content(chunk_size=8192))
                
            except requests.exceptions.RequestException as e:
                 error_message = f"Found main.js URL but failed to fetch content: {str(e)}"
                 print(f"Error fetching content for {main_js_url}: {error_message}")
            except Exception as e:
                 error_message = f"An unexpected error occurred fetching content for {main_js_url}: {e}"
                 print(f"Error fetching content for {main_js_url}: {error_message}")
                 
            return jsonify({
                "success": True,
                "mainjs_url": main_js_url,
                "mainjs_content": main_js_content, # Will be None if fetch failed
                "error": error_message # Include error if fetch failed
            })
        else:
            return jsonify({
                "success": False,
                "error": "No main.js file found linked directly in the HTML source."
            })
            
    except Exception as e:
        print(f"Error analyzing URL {url}: {e}")
        return jsonify({"success": False, "error": f"Error analyzing URL: {str(e)}"}), 500


@app.route('/api/advanced-mainjs-detection/<int:domain_id>', methods=['POST'])
def advanced_mainjs_detection(domain_id):
    domain = db.get_or_404(Domain, domain_id)
    url = ensure_protocol(domain.url)
    main_js_url = None
    main_js_content = None
    error_message = None
    endpoint_added_or_updated = False
    
    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'})
    requests.packages.urllib3.disable_warnings()
    
    try:
        # 1. Try finding in HTML source first
        print(f"Advanced detection: Checking HTML source for {url}")
        main_js_url = find_mainjs_in_html(url, session)
        
        if main_js_url:
            print(f"Advanced detection: Found potential main.js in HTML: {main_js_url}")
            try:
                response = session.get(main_js_url, timeout=20, verify=False, stream=True)
                response.raise_for_status()
                main_js_content = "".join(chunk.decode('utf-8', errors='ignore') for chunk in response.iter_content(chunk_size=8192))
                print(f"Advanced detection: Successfully fetched content for {main_js_url}")
            except requests.exceptions.RequestException as e:
                error_message = f"Found main.js URL ({main_js_url}) in HTML, but failed to fetch content: {e}"
                print(f"Advanced detection error: {error_message}")
            except Exception as e:
                error_message = f"An unexpected error occurred fetching content for {main_js_url}: {e}"
                print(f"Advanced detection error: {error_message}")

        # 2. If not found or fetch failed, try finding in stored endpoints
        if not main_js_url or (main_js_url and main_js_content is None):
            print(f"Advanced detection: Checking stored endpoints for domain ID {domain_id}")
            main_js_endpoint = find_mainjs_in_endpoints(domain_id)
            if main_js_endpoint:
                if not main_js_url: # Only update URL if not found in HTML
                    main_js_url = main_js_endpoint.url
                print(f"Advanced detection: Found potential main.js in endpoints: {main_js_url}")
                if main_js_content is None: # Only fetch if we didn't get it before
                    try:
                        response = session.get(main_js_url, timeout=20, verify=False, stream=True)
                        response.raise_for_status()
                        main_js_content = "".join(chunk.decode('utf-8', errors='ignore') for chunk in response.iter_content(chunk_size=8192))
                        print(f"Advanced detection: Successfully fetched content for {main_js_url} from endpoint.")
                        error_message = None # Clear previous error if fetch successful now
                    except requests.exceptions.RequestException as e:
                        if not error_message: error_message = f"Found main.js URL ({main_js_url}) in endpoints, but failed to fetch content: {e}"
                        print(f"Advanced detection error: {error_message}")
                    except Exception as e:
                         if not error_message: error_message = f"An unexpected error occurred fetching content for {main_js_url} from endpoint: {e}"
                         print(f"Advanced detection error: {error_message}")
            else:
                 print(f"Advanced detection: No main.js found in stored endpoints either.")
                 if not error_message: error_message = "No main.js file could be located via HTML parsing or stored endpoints."

        # 3. Update or add endpoint if URL was found
        if main_js_url:
            try:
                parsed = urlparse(main_js_url)
                path = parsed.path or '/' # Ensure path is not empty
                
                existing_endpoint = Endpoint.query.filter_by(domain_id=domain.id, url=main_js_url).first()
                
                if not existing_endpoint:
                    endpoint = Endpoint(
                        domain_id=domain.id, url=main_js_url[:511], path=path[:254], # Truncate
                        status_code=200 if main_js_content else None, 
                        content_type='application/javascript', is_interesting=True,
                        notes="Detected main.js file via advanced scan"
                    )
                    db.session.add(endpoint)
                    print(f"Advanced detection: Added new endpoint record for {main_js_url}")
                elif not existing_endpoint.is_interesting:
                     existing_endpoint.is_interesting = True
                     existing_endpoint.last_checked = datetime.utcnow()
                     if main_js_content and not existing_endpoint.status_code:
                          existing_endpoint.status_code = 200
                     print(f"Advanced detection: Marked existing endpoint {main_js_url} as interesting.")
                     
                db.session.commit()
                endpoint_added_or_updated = True
            except Exception as db_err:
                 db.session.rollback()
                 print(f"Advanced detection DB error: {db_err}")
                 # Append DB error to existing message if any
                 error_message = (error_message + "; " if error_message else "") + f"Database error updating endpoint: {db_err}"

        # 4. Return result
        return jsonify({
            "success": bool(main_js_url),
            "mainjs_url": main_js_url,
            "mainjs_content": main_js_content,
            "endpoint_added_or_updated": endpoint_added_or_updated,
            "error": error_message
        })

    except Exception as e:
        print(f"Error during advanced main.js detection for domain {domain_id}: {str(e)}")
        return jsonify({"success": False, "error": f"An unexpected error occurred during detection: {str(e)}"}), 500

# Helper to find main.js in HTML source using a session
def find_mainjs_in_html(url, session):
    try:
        response = session.get(url, timeout=15, verify=False, allow_redirects=True)
        response.raise_for_status()
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        
        found_scripts = []
        for script in soup.find_all('script', src=True):
            script_url = script['src']
            script_url = urljoin(response.url, script_url)
            found_scripts.append(script_url)

        for pattern in MAIN_JS_PATTERNS:
             compiled_pattern = re.compile(pattern, re.IGNORECASE)
             for script_url in found_scripts:
                 if compiled_pattern.search(script_url):
                     return script_url
        return None
    except requests.exceptions.RequestException as e:
        print(f"HTML fetch error in find_mainjs_in_html ({url}): {e}")
        return None
    except Exception as e:
        print(f"HTML parsing error in find_mainjs_in_html ({url}): {e}")
        return None

# Helper to find main.js in stored endpoints
def find_mainjs_in_endpoints(domain_id):
    try:
        # Combine patterns into a single efficient query if possible (DB dependent)
        # Using multiple LIKEs as a fallback for broader compatibility
        conditions = [Endpoint.url.like(f"%{pattern.replace('.*', '%').replace('.js', '%.js')}%") for pattern in MAIN_JS_PATTERNS]
        endpoint = Endpoint.query.filter(
            Endpoint.domain_id == domain_id,
            db.or_(*conditions)
        ).order_by(Endpoint.is_interesting.desc(), Endpoint.date_discovered.desc()).first() # Prioritize interesting/recent
        
        return endpoint
    except Exception as e:
        print(f"DB error querying endpoints for main.js (domain {domain_id}): {e}")
        return None

# --- Scan Link Route ---
@app.route('/scan-link/<int:domain_id>')
def scan_link(domain_id):
    domain = db.get_or_404(Domain, domain_id)
    scan_type = request.args.get('type', 'basic')
    domain_name_only = domain.url # Assumes domain.url doesn't have protocol

    if scan_type == 'nuclei':
        return redirect(url_for('nuclei_scanner_page', domain=domain_name_only, autorun='true'))
    elif scan_type == 'mainjs':
        if find_mainjs_in_endpoints(domain_id):
             return redirect(url_for('mainjs_analyzer_page', domain_id=domain_id))
        else:
             flash(f"No main.js file associated with {domain.url}. Run a basic scan first.", "warning")
             return redirect(url_for('domain_details', id=domain_id))
    elif scan_type == 'api_bypass':
         return redirect(url_for('api_bypass_page', domain=ensure_protocol(domain.url), domain_id=domain.id))
    else: # Default to basic scan
        return redirect(url_for('basic_scanner_page', domain=domain_name_only, autorun='true'))

# --- API Bypass Routes ---

@app.route('/api-bypass')
def api_bypass_page():
    wordlists = []
    try:
        wordlists_dir = app.config['WORDLISTS_FOLDER']
        if os.path.isdir(wordlists_dir):
            wordlists = sorted([f for f in os.listdir(wordlists_dir) if os.path.isfile(os.path.join(wordlists_dir, f))])
        else:
            print(f"Warning: Wordlists directory not found at {wordlists_dir}")
            flash(f"Wordlists directory not found: {wordlists_dir}", "warning")
    except Exception as e:
        print(f"Error listing wordlists: {e}")
        flash("Error loading wordlists.", "danger")

    domain_to_test = request.args.get('domain', '')
    domain_id = request.args.get('domain_id', type=int) # Use type=int for auto-conversion/validation

    # Verify domain_id if provided
    if domain_id:
        domain_check = db.session.get(Domain, domain_id) # Use newer db.session.get
        if not domain_check:
             flash(f"Invalid Domain ID {domain_id} provided.", "warning")
             domain_id = None 
        elif not domain_to_test: 
             domain_to_test = ensure_protocol(domain_check.url)
    
    if domain_to_test:
        domain_to_test = ensure_protocol(domain_to_test)
    
    return render_template('api_bypass.html', 
                          wordlists=wordlists, 
                          domain_to_test=domain_to_test,
                          domain_id=domain_id)


@app.route('/run-bypass', methods=['POST'])
def run_bypass_route():
    domain = request.form.get('domain')
    wordlist_name = request.form.get('wordlist')
    domain_id = request.form.get('domain_id', type=int) # Get as int

    if not domain or not wordlist_name:
        return jsonify({"error": "Domain and wordlist are required"}), 400
    
    wordlist_path = os.path.join(app.config['WORDLISTS_FOLDER'], wordlist_name)
    if not os.path.isfile(wordlist_path):
         return jsonify({"error": f"Wordlist '{wordlist_name}' not found."}), 400

    domain = ensure_protocol(domain)
    print(f"Running bypass for {domain} with wordlist {wordlist_name} and domain_id {domain_id}")

    try:
        result = api_bypass.run_bypass(domain, wordlist_path, domain_id) 
        
        # Automatic domain ID lookup if needed (and if bypass was successful)
        if not domain_id and result.get('successful_bypasses') and 'error' not in result:
            print("Attempting automatic domain ID lookup...")
            normalized_domain = normalize_domain_name(domain)
            if normalized_domain:
                 domain_obj = Domain.query.filter(Domain.url == normalized_domain).first()
                 if domain_obj:
                     domain_id = domain_obj.id
                     print(f"Automatically found domain ID: {domain_id}")
                     # Re-call storage function with the found ID
                     api_bypass.store_successful_bypasses(
                         domain_id, domain, result.get('successful_bypasses', []), result.get('recommendations', '')
                     )
                     result['message'] = "Scan complete. Results automatically associated with domain."
                     result['domain_id'] = domain_id # Add found ID to result
                 else:
                      print(f"Automatic lookup failed: No domain found matching '{normalized_domain}'")
            else:
                 print("Automatic lookup failed: Could not extract base domain.")
        
        # Add domain_id to the result if it was determined
        elif domain_id:
            result['domain_id'] = domain_id

        return jsonify(result)
        
    except Exception as e:
         # Catch errors from the bypass function itself
         print(f"Error during API bypass execution: {e}")
         return jsonify({"error": f"Error running bypass: {str(e)}"}), 500


# Route for explicit storage (might be less used now)
@app.route('/api-bypass/store/<int:domain_id>', methods=['POST'])
def store_api_bypass(domain_id):
    domain = db.get_or_404(Domain, domain_id) # Ensure domain exists
    data = request.get_json()
    if not data: return jsonify({"error": "No data provided"}), 400
    
    bypasses_data = data.get('successful_bypasses', [])
    recommendations = data.get('recommendations', '')
    target_domain_url = data.get('domain', ensure_protocol(domain.url)) 
    stored_count = 0
    
    try:
        success = api_bypass.store_successful_bypasses(domain_id, target_domain_url, bypasses_data, recommendations)
        message = f"API bypass results {'processed' if success else 'failed to process'} for domain ID {domain_id}."
        if success: stored_count = len(bypasses_data) # Rough count
        return jsonify({"success": success, "message": message, "stored_count": stored_count})
    except Exception as e:
         print(f"Error in /api-bypass/store/{domain_id}: {e}")
         return jsonify({"success": False, "error": f"Server error storing results: {str(e)}"}), 500


# --- Vulnerability/Endpoint/Screenshot Management --- (Simplified for brevity, keep existing logic)

@app.route('/vulnerability/<int:id>/delete', methods=['POST'])
def delete_vulnerability(id):
    vuln = db.get_or_404(Vulnerability, id)
    domain_id = vuln.domain_id
    try:
        db.session.delete(vuln)
        db.session.commit()
        flash('Vulnerability deleted successfully!', 'success')
    except Exception as e:
         db.session.rollback()
         flash(f'Error deleting vulnerability: {str(e)}', 'danger')
    return redirect(url_for('domain_details', id=domain_id))

@app.route('/vulnerability/<int:id>/update', methods=['POST'])
def update_vulnerability(id):
    vuln = db.get_or_404(Vulnerability, id)
    updated = False
    try:
        if 'severity' in request.form:
            new_severity = request.form['severity'].upper()
            if new_severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                vuln.severity = new_severity
                updated = True
        if 'notes' in request.form:
            vuln.description = request.form['notes']
            updated = True
        
        if updated:
             vuln.last_updated = datetime.utcnow()
             db.session.commit()
             flash('Vulnerability updated successfully!', 'success')
    except Exception as e:
         db.session.rollback()
         flash(f'Error updating vulnerability: {str(e)}', 'danger')
    return redirect(url_for('domain_details', id=vuln.domain_id))

@app.route('/vulnerability/<int:id>/classify', methods=['POST'])
def classify_vulnerability_route(id):
    vuln = db.get_or_404(Vulnerability, id)
    is_true_positive = request.form.get('is_true_positive', 'false').lower() == 'true'
    try:
        new_status = 'CONFIRMED' if is_true_positive else 'DISMISSED'
        if vuln.status != new_status:
            vuln.status = new_status
            vuln.last_updated = datetime.utcnow()
            db.session.commit()
            flash(f"Vulnerability classified as {'TRUE POSITIVE' if is_true_positive else 'FALSE POSITIVE'}", 'success')
    except Exception as e:
         db.session.rollback()
         flash(f"Error classifying vulnerability: {str(e)}", 'danger')
    return redirect(url_for('domain_details', id=vuln.domain_id))

@app.route('/endpoint/<int:id>/delete', methods=['POST'])
def delete_endpoint(id):
    endpoint = db.get_or_404(Endpoint, id)
    domain_id = endpoint.domain_id
    try:
        db.session.delete(endpoint)
        db.session.commit()
        flash('Endpoint deleted successfully!', 'success')
    except Exception as e:
         db.session.rollback()
         flash(f'Error deleting endpoint: {str(e)}', 'danger')
    return redirect(url_for('domain_details', id=domain_id))

@app.route('/endpoint/<int:id>/update', methods=['POST'])
def update_endpoint(id):
    endpoint = db.get_or_404(Endpoint, id)
    try:
        endpoint.notes = request.form.get('notes', endpoint.notes)
        endpoint.is_interesting = 'is_interesting' in request.form 
        endpoint.last_checked = datetime.utcnow()
        db.session.commit()
        flash('Endpoint updated successfully!', 'success')
    except Exception as e:
         db.session.rollback()
         flash(f'Error updating endpoint: {str(e)}', 'danger')
    return redirect(url_for('domain_details', id=endpoint.domain_id))

@app.route('/screenshot/<int:id>/delete', methods=['POST'])
def delete_screenshot(id):
    screenshot = db.get_or_404(Screenshot, id)
    domain_id = screenshot.domain_id
    filename = screenshot.filename
    try:
        db.session.delete(screenshot)
        db.session.commit()
        flash('Screenshot record deleted successfully!', 'success')
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path): os.remove(file_path)
        except Exception as file_err:
            flash(f'Warning: Could not delete screenshot file: {filename}', 'warning')
            print(f"File deletion error: {file_err}")
    except Exception as e:
         db.session.rollback()
         flash(f'Error deleting screenshot record: {str(e)}', 'danger')
    return redirect(url_for('domain_details', id=domain_id))

# --- Error Handlers & SocketIO ---

@app.errorhandler(404)
def page_not_found(e):
    print(f"404 Error: Path '{request.path}' not found.")
    return render_template('error.html', error_code=404, error_message="Page Not Found"), 404

@app.errorhandler(500)
def server_error(e):
    print(f"500 Server Error: Path '{request.path}'. Error: {e}")
    try: db.session.rollback()
    except Exception as db_err: print(f"Error rolling back DB session on 500: {db_err}")
    return render_template('error.html', error_code=500, error_message="Internal Server Error"), 500

@app.errorhandler(Exception)
def handle_exception(e):
    print(f"Unhandled Exception: Path '{request.path}'. Error: {str(e)}")
    try: db.session.rollback()
    except Exception as db_err: print(f"Error rolling back DB session on exception: {db_err}")
    return render_template('error.html', error_code=500, error_message="An unexpected error occurred."), 500

@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')

# --- Main Execution ---
if __name__ == '__main__':
    print("Starting Flask app with SocketIO...")
    # Use debug=True only for development
    socketio.run(app, debug=True, host='127.0.0.1', port=5000, use_reloader=False) # use_reloader=False often helps with threads