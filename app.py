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
from urllib.parse import urljoin, urlparse, unquote # Added unquote
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, current_app
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
# api_bypass doesn't seem to use socketio directly

# Ensure upload/wordlist/template directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['WORDLISTS_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(os.getcwd(), 'custom-templates'), exist_ok=True)

# Create database tables if they don't exist
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
        full_url = ensure_protocol(url_or_domain)
        parsed_uri = urlparse(full_url)
        domain_name = parsed_uri.hostname
        if not domain_name:
             domain_name = (parsed_uri.netloc or parsed_uri.path.split('/')[0])
        if domain_name:
             domain_name = domain_name.split(':')[0].lower()
             if domain_name.startswith('www.'):
                 domain_name = domain_name[4:]
             return domain_name
        else:
             return None
    except Exception as e:
        print(f"Error normalizing domain '{url_or_domain}': {e}")
        return None

def run_scan_in_thread(target_function, *args):
    """Starts a function in a background thread with app context."""
    app_context = current_app.app_context()
    def thread_target():
        with app_context:
            try:
                target_function(*args)
            except Exception as e:
                scan_id = args[1] if len(args) > 1 else 'unknown_scan'
                error_message = f"Error in background thread for scan '{scan_id}': {e}"
                print(error_message)
                # Error emission needs specific context, handled within scanners
    thread = threading.Thread(target=thread_target)
    thread.daemon = True
    thread.start()
    return thread


# --- Routes ---

# (Keep dashboard, domains, domain_details, update_domain, delete_domain, upload_screenshot, workspace, scanner pages, scanner execution routes, vulnerability/endpoint/screenshot management routes, error handlers as they were)
# ... (Previous routes from app.py) ...

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
    domain = db.get_or_404(Domain, id)
    return render_template('domain_details.html', domain=domain)

@app.route('/domain/<int:id>/update', methods=['POST'])
def update_domain(id):
    domain = db.get_or_404(Domain, id)
    try:
        if 'status' in request.form:
            new_status = request.form['status']
            if new_status in ['NEW', 'IN PROGRESS', 'FINISHED', 'FALSE ALARM']:
                domain.assessment_status = new_status
            else:
                 flash(f"Invalid assessment status '{new_status}' ignored.", "warning")
        if 'notes' in request.form:
            domain.notes = request.form['notes']
        if 'claim' in request.form:
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
    domain_url = domain.url
    try:
        Vulnerability.query.filter_by(domain_id=id).delete()
        screenshots = Screenshot.query.filter_by(domain_id=id).all()
        for screenshot in screenshots:
            try:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], screenshot.filename)
                if os.path.exists(file_path): os.remove(file_path)
            except Exception as file_err:
                print(f'Error deleting screenshot file {screenshot.filename}: {str(file_err)}')
                flash(f'Warning: Could not delete screenshot file: {screenshot.filename}', 'warning')
        Screenshot.query.filter_by(domain_id=id).delete()
        Endpoint.query.filter_by(domain_id=id).delete()
        APIBypass.query.filter_by(domain_id=id).delete()
        domain.technologies = []
        db.session.commit()
        db.session.delete(domain)
        db.session.commit()
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
    if file:
        try:
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            unique_filename = f"{timestamp}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            screenshot = Screenshot(domain_id=domain.id, filename=unique_filename, description=request.form.get('description', ''))
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
    return render_template('basic_scanner.html', domain_to_scan=domain_to_scan, autorun=autorun)

@app.route('/nuclei-scanner')
def nuclei_scanner_page():
    domain_to_scan = request.args.get('domain', '')
    autorun = request.args.get('autorun', 'false').lower() == 'true'
    return render_template('nuclei_scanner.html', domain_to_scan=domain_to_scan, autorun=autorun)

@app.route('/run-basic-scan', methods=['POST'])
def run_basic_scan():
    single_domain = request.form.get('domain', '').strip()
    domain_list_str = request.form.get('domain_list', '').strip()
    domains_to_scan = []
    if single_domain: domains_to_scan.append(single_domain)
    elif domain_list_str: domains_to_scan = [d.strip() for d in domain_list_str.splitlines() if d.strip()]
    if not domains_to_scan: return jsonify({"error": "No domain(s) provided"}), 400
    scan_group_id = f"basic_scan_group_{int(time.time())}"
    started_scans = 0
    for i, domain_url in enumerate(domains_to_scan):
        if not domain_url: continue
        scan_id = f"{scan_group_id}_{i}"
        print(f"Initiating basic scan for: {domain_url} with scan_id: {scan_id}")
        run_scan_in_thread(basic_scanner.basic_scan, domain_url, scan_id)
        started_scans += 1
    if started_scans == 0: return jsonify({"error": "No valid domains found to scan"}), 400
    return jsonify({"message": f"Basic scan started for {started_scans} domain(s).", "scan_group_id": scan_group_id})

@app.route('/run-basic-scan-batch', methods=['POST'])
def run_basic_scan_batch():
    data = request.get_json()
    if not data or 'domains' not in data: return jsonify({"error": "No domains list provided"}), 400
    domains = data.get('domains', [])
    delay = data.get('delay', 0.1)
    domains_to_scan = [d.strip() for d in domains if isinstance(d, str) and d.strip()]
    if not domains_to_scan: return jsonify({"error": "No valid domains found"}), 400
    batch_id = f"batch_scan_{int(time.time())}"
    started_scans = 0
    print(f"Starting batch scan (ID: {batch_id}) for {len(domains_to_scan)} domains...")
    for i, domain_url in enumerate(domains_to_scan):
        scan_id = f"{batch_id}_{i}"
        print(f"Initiating scan for {domain_url} (Scan ID: {scan_id})")
        run_scan_in_thread(basic_scanner.basic_scan, domain_url, scan_id)
        started_scans += 1
        if delay > 0: time.sleep(delay)
    return jsonify({"message": f"Batch scan initiated for {started_scans} domains.", "batch_id": batch_id})

@app.route('/run-nuclei-scan', methods=['POST'])
def run_nuclei_scan():
    domain_url = request.form.get('domain', '').strip()
    scan_options_str = request.form.get('scan_options', '')
    severity_levels_str = request.form.get('severity_levels', '')
    scan_options = [opt for opt in scan_options_str.split(',') if opt]
    severity_levels = [lvl for lvl in severity_levels_str.split(',') if lvl]
    if not domain_url: return jsonify({"error": "No domain provided"}), 400
    if not scan_options: scan_options = ['cves', 'vulnerabilities', 'misconfiguration', 'exposures', 'technologies']
    if not severity_levels: severity_levels = ['critical', 'high', 'medium']
    scan_id = f"nuclei_scan_{int(time.time())}"
    print(f"Initiating Nuclei scan for: {domain_url} with scan_id: {scan_id}")
    run_scan_in_thread(nuclei_scanner.nuclei_scan, domain_url, scan_id, scan_options, severity_levels)
    domain_id = None
    normalized_domain = normalize_domain_name(domain_url)
    if normalized_domain:
        temp_domain = Domain.query.filter_by(url=normalized_domain).first()
        domain_id = temp_domain.id if temp_domain else None
    return jsonify({"message": "Nuclei scan started", "scan_id": scan_id, "domain": domain_url, "domain_id": domain_id})

# --- NEW Inspect Tab Routes ---

@app.route('/inspect')
def inspect_page():
    """Renders the new Inspect page."""
    # Get URL from query parameter if provided
    prefill_url = request.args.get('url', '')
    # URL decode the prefill_url just in case
    if prefill_url:
        prefill_url = unquote(prefill_url)
    return render_template('inspect.html', prefill_url=prefill_url)


@app.route('/fetch-url-content', methods=['POST'])
def fetch_url_content():
    """Fetches content for a given URL."""
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400

    url_to_fetch = data['url']
    if not url_to_fetch.startswith(('http://', 'https://')):
         return jsonify({"error": "Invalid URL format. Must start with http:// or https://"}), 400

    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0'}) # Basic user agent
    requests.packages.urllib3.disable_warnings() # Disable SSL warnings

    try:
        response = session.get(url_to_fetch, timeout=20, verify=False, stream=True)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        # Read content, attempting UTF-8 decoding
        content = "".join(chunk.decode('utf-8', errors='ignore') for chunk in response.iter_content(chunk_size=8192))

        return jsonify({"url": url_to_fetch, "content": content})

    except requests.exceptions.Timeout:
        return jsonify({"error": f"Timeout fetching URL: {url_to_fetch}"}), 504 # Gateway Timeout
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL content ({url_to_fetch}): {e}")
        # Try to provide a more specific error message if possible
        status_code = getattr(e.response, 'status_code', 'N/A')
        return jsonify({"error": f"Error fetching URL (Status: {status_code}): {str(e)}"}), 502 # Bad Gateway might be appropriate
    except Exception as e:
        print(f"Unexpected error fetching URL content ({url_to_fetch}): {e}")
        return jsonify({"error": f"An unexpected server error occurred: {str(e)}"}), 500


# --- Scan Link Route Modification ---
@app.route('/scan-link/<int:object_id>') # Changed to object_id for flexibility
def scan_link(object_id):
    scan_type = request.args.get('type', 'basic')
    target_url = request.args.get('target_url') # Expect target URL for inspect

    domain = db.get_or_404(Domain, object_id) # Still need domain for context/fallback
    domain_name_only = domain.url

    if scan_type == 'nuclei':
        return redirect(url_for('nuclei_scanner_page', domain=domain_name_only, autorun='true'))
    elif scan_type == 'inspect':
         # If a specific target URL (like a JS file) is provided, use it
         if target_url:
              # URL encode the target_url before passing it as a query parameter
              # Although Flask/Werkzeug might handle this, explicit encoding is safer
              # from urllib.parse import quote
              # encoded_target_url = quote(target_url)
              # return redirect(url_for('inspect_page', url=encoded_target_url))
              # Simpler redirect assuming Werkzeug handles encoding:
              return redirect(url_for('inspect_page', url=target_url))
         else:
              # Fallback: try finding default main.js if no specific URL given
              mainjs_endpoint = find_mainjs_in_endpoints(object_id) # object_id is domain_id here
              if mainjs_endpoint:
                  return redirect(url_for('inspect_page', url=mainjs_endpoint.url))
              else:
                  flash(f"No specific JS URL provided and no default main.js found for {domain.url}. Please inspect manually.", "warning")
                  return redirect(url_for('domain_details', id=object_id))
    elif scan_type == 'api_bypass':
         return redirect(url_for('api_bypass_page', domain=ensure_protocol(domain.url), domain_id=domain.id))
    else: # Default to basic scan
        return redirect(url_for('basic_scanner_page', domain=domain_name_only, autorun='true'))

# --- API Bypass Routes --- (Keep as they were)
@app.route('/api-bypass')
def api_bypass_page():
    wordlists = []
    try:
        wordlists_dir = app.config['WORDLISTS_FOLDER']
        if os.path.isdir(wordlists_dir): wordlists = sorted([f for f in os.listdir(wordlists_dir) if os.path.isfile(os.path.join(wordlists_dir, f))])
        else: print(f"Warning: Wordlists directory not found at {wordlists_dir}"); flash(f"Wordlists directory not found: {wordlists_dir}", "warning")
    except Exception as e: print(f"Error listing wordlists: {e}"); flash("Error loading wordlists.", "danger")
    domain_to_test = request.args.get('domain', '')
    domain_id = request.args.get('domain_id', type=int)
    if domain_id:
        domain_check = db.session.get(Domain, domain_id)
        if not domain_check: flash(f"Invalid Domain ID {domain_id} provided.", "warning"); domain_id = None
        elif not domain_to_test: domain_to_test = ensure_protocol(domain_check.url)
    if domain_to_test: domain_to_test = ensure_protocol(domain_to_test)
    return render_template('api_bypass.html', wordlists=wordlists, domain_to_test=domain_to_test, domain_id=domain_id)

@app.route('/run-bypass', methods=['POST'])
def run_bypass_route():
    domain = request.form.get('domain')
    wordlist_name = request.form.get('wordlist')
    domain_id = request.form.get('domain_id', type=int)
    if not domain or not wordlist_name: return jsonify({"error": "Domain and wordlist are required"}), 400
    wordlist_path = os.path.join(app.config['WORDLISTS_FOLDER'], wordlist_name)
    if not os.path.isfile(wordlist_path): return jsonify({"error": f"Wordlist '{wordlist_name}' not found."}), 400
    domain = ensure_protocol(domain)
    print(f"Running bypass for {domain} with wordlist {wordlist_name} and domain_id {domain_id}")
    try:
        result = api_bypass.run_bypass(domain, wordlist_path, domain_id)
        if not domain_id and result.get('successful_bypasses') and 'error' not in result:
            print("Attempting automatic domain ID lookup...")
            normalized_domain = normalize_domain_name(domain)
            if normalized_domain:
                 domain_obj = Domain.query.filter(Domain.url == normalized_domain).first()
                 if domain_obj:
                     domain_id = domain_obj.id
                     print(f"Automatically found domain ID: {domain_id}")
                     api_bypass.store_successful_bypasses(domain_id, domain, result.get('successful_bypasses', []), result.get('recommendations', ''))
                     result['message'] = "Scan complete. Results automatically associated with domain."
                     result['domain_id'] = domain_id
                 else: print(f"Automatic lookup failed: No domain found matching '{normalized_domain}'")
            else: print("Automatic lookup failed: Could not extract base domain.")
        elif domain_id: result['domain_id'] = domain_id
        return jsonify(result)
    except Exception as e:
         print(f"Error during API bypass execution: {e}")
         return jsonify({"error": f"Error running bypass: {str(e)}"}), 500

@app.route('/api-bypass/store/<int:domain_id>', methods=['POST'])
def store_api_bypass(domain_id):
    domain = db.get_or_404(Domain, domain_id)
    data = request.get_json()
    if not data: return jsonify({"error": "No data provided"}), 400
    bypasses_data = data.get('successful_bypasses', [])
    recommendations = data.get('recommendations', '')
    target_domain_url = data.get('domain', ensure_protocol(domain.url))
    stored_count = 0
    try:
        success = api_bypass.store_successful_bypasses(domain_id, target_domain_url, bypasses_data, recommendations)
        message = f"API bypass results {'processed' if success else 'failed to process'} for domain ID {domain_id}."
        if success: stored_count = len(bypasses_data)
        return jsonify({"success": success, "message": message, "stored_count": stored_count})
    except Exception as e:
         print(f"Error in /api-bypass/store/{domain_id}: {e}")
         return jsonify({"success": False, "error": f"Server error storing results: {str(e)}"}), 500

# --- Vulnerability/Endpoint/Screenshot Management ---
@app.route('/vulnerability/<int:id>/delete', methods=['POST'])
def delete_vulnerability(id):
    vuln = db.get_or_404(Vulnerability, id)
    domain_id = vuln.domain_id
    try: db.session.delete(vuln); db.session.commit(); flash('Vulnerability deleted!', 'success')
    except Exception as e: db.session.rollback(); flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('domain_details', id=domain_id))

@app.route('/vulnerability/<int:id>/update', methods=['POST'])
def update_vulnerability(id):
    vuln = db.get_or_404(Vulnerability, id)
    updated = False
    try:
        if 'severity' in request.form:
            new_severity = request.form['severity'].upper()
            if new_severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']: vuln.severity = new_severity; updated = True
        if 'notes' in request.form: vuln.description = request.form['notes']; updated = True
        if updated: vuln.last_updated = datetime.utcnow(); db.session.commit(); flash('Vulnerability updated!', 'success')
    except Exception as e: db.session.rollback(); flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('domain_details', id=vuln.domain_id))

@app.route('/vulnerability/<int:id>/classify', methods=['POST'])
def classify_vulnerability_route(id):
    vuln = db.get_or_404(Vulnerability, id)
    is_true_positive = request.form.get('is_true_positive', 'false').lower() == 'true'
    try:
        new_status = 'CONFIRMED' if is_true_positive else 'DISMISSED'
        if vuln.status != new_status: vuln.status = new_status; vuln.last_updated = datetime.utcnow(); db.session.commit(); flash(f"Classified as {'TRUE' if is_true_positive else 'FALSE'} POSITIVE", 'success')
    except Exception as e: db.session.rollback(); flash(f"Error: {str(e)}", 'danger')
    return redirect(url_for('domain_details', id=vuln.domain_id))

@app.route('/endpoint/<int:id>/delete', methods=['POST'])
def delete_endpoint(id):
    endpoint = db.get_or_404(Endpoint, id)
    domain_id = endpoint.domain_id
    try: db.session.delete(endpoint); db.session.commit(); flash('Endpoint deleted!', 'success')
    except Exception as e: db.session.rollback(); flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('domain_details', id=domain_id))

@app.route('/endpoint/<int:id>/update', methods=['POST'])
def update_endpoint(id):
    endpoint = db.get_or_404(Endpoint, id)
    try:
        endpoint.notes = request.form.get('notes', endpoint.notes)
        endpoint.is_interesting = 'is_interesting' in request.form
        endpoint.last_checked = datetime.utcnow()
        db.session.commit()
        flash('Endpoint updated!', 'success')
    except Exception as e: db.session.rollback(); flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('domain_details', id=endpoint.domain_id))

@app.route('/screenshot/<int:id>/delete', methods=['POST'])
def delete_screenshot(id):
    screenshot = db.get_or_404(Screenshot, id)
    domain_id = screenshot.domain_id
    filename = screenshot.filename
    try:
        db.session.delete(screenshot)
        db.session.commit()
        flash('Screenshot record deleted!', 'success')
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path): os.remove(file_path)
        except Exception as file_err: flash(f'Warning: Could not delete file: {filename}', 'warning'); print(f"File deletion error: {file_err}")
    except Exception as e: db.session.rollback(); flash(f'Error deleting record: {str(e)}', 'danger')
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
    socketio.run(app, debug=True, host='127.0.0.1', port=5000, use_reloader=False)