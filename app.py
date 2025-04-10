import os
import json
import subprocess
import shutil
import random
import time
import threading
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename
from config import Config
from models import db, Domain, Technology, Vulnerability, Endpoint, Screenshot

# Import the separated scanner modules instead of a single scanner file
import utils.basic_scanner as basic_scanner
import utils.nuclei_scanner as nuclei_scanner
import utils.api_bypass as api_bypass

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db.init_app(app)

# Initialize Socket.IO
socketio = SocketIO(app)

# Initialize both scanners with Socket.IO
basic_scanner.init_socketio(socketio)
nuclei_scanner.init_socketio(socketio)

# Ensure upload and wordlists directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['WORDLISTS_FOLDER'], exist_ok=True)

# Custom template directories
os.makedirs(os.path.join(os.getcwd(), 'custom-templates'), exist_ok=True)

# Instead of @app.before_first_request, we'll create all tables at startup
with app.app_context():
    db.create_all()

# Dashboard route
@app.route('/')
def dashboard():
    # Get stats for dashboard
    total_domains = Domain.query.count()
    active_domains = Domain.query.filter_by(status='ACTIVE').count()
    inactive_domains = Domain.query.filter_by(status='INACTIVE').count()
    
    vulnerabilities = Vulnerability.query.all()
    total_vulnerabilities = len(vulnerabilities)
    
    # Count vulnerabilities by severity
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    
    for vuln in vulnerabilities:
        if vuln.severity in severity_counts:
            severity_counts[vuln.severity] += 1
    
    # Get domains by status
    domains_by_status = {
        'NEW': Domain.query.filter_by(assessment_status='NEW').count(),
        'IN PROGRESS': Domain.query.filter_by(assessment_status='IN PROGRESS').count(),
        'FINISHED': Domain.query.filter_by(assessment_status='FINISHED').count(),
        'FALSE ALARM': Domain.query.filter_by(assessment_status='FALSE ALARM').count()
    }
    
    # Get recent vulnerabilities
    recent_vulnerabilities = Vulnerability.query.order_by(Vulnerability.date_discovered.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                          total_domains=total_domains,
                          active_domains=active_domains,
                          inactive_domains=inactive_domains,
                          total_vulnerabilities=total_vulnerabilities,
                          severity_counts=severity_counts,
                          domains_by_status=domains_by_status,
                          recent_vulnerabilities=recent_vulnerabilities)

# Domains routes
@app.route('/domains')
def domains():
    domains = Domain.query.all()
    technologies = Technology.query.all()
    
    # Filter by technology if provided
    tech_filter = request.args.get('technology')
    status_filter = request.args.get('status')
    assessment_filter = request.args.get('assessment')
    
    if tech_filter:
        tech = Technology.query.filter_by(name=tech_filter).first()
        if tech:
            domains = tech.domains
    
    if status_filter:
        if tech_filter:
            # Need to filter the already filtered list
            domains = [d for d in domains if d.status == status_filter]
        else:
            domains = Domain.query.filter_by(status=status_filter).all()
    
    if assessment_filter:
        # Filter by assessment status (NEW, IN PROGRESS, etc.)
        if tech_filter or status_filter:
            domains = [d for d in domains if d.assessment_status == assessment_filter]
        else:
            domains = Domain.query.filter_by(assessment_status=assessment_filter).all()
    
    return render_template('domains.html', domains=domains, technologies=technologies)

@app.route('/domain/<int:id>')
def domain_details(id):
    domain = Domain.query.get_or_404(id)
    return render_template('domain_details.html', domain=domain)

@app.route('/domain/<int:id>/update', methods=['POST'])
def update_domain(id):
    domain = Domain.query.get_or_404(id)
    
    if 'status' in request.form:
        domain.assessment_status = request.form['status']
    
    if 'notes' in request.form:
        domain.notes = request.form['notes']
    
    if 'claim' in request.form:
        domain.assigned_to = "Current User"  # In a real app, use actual user info
    
    if 'unclaim' in request.form:
        domain.assigned_to = None
    
    db.session.commit()
    flash(f'Domain {domain.url} updated successfully!', 'success')
    return redirect(url_for('domain_details', id=domain.id))

@app.route('/domain/<int:id>/delete', methods=['POST'])
def delete_domain(id):
    domain = Domain.query.get_or_404(id)
    
    # Delete associated vulnerabilities
    Vulnerability.query.filter_by(domain_id=id).delete()
    
    # Delete associated screenshots (files and records)
    screenshots = Screenshot.query.filter_by(domain_id=id).all()
    for screenshot in screenshots:
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], screenshot.filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            flash(f'Error deleting screenshot file: {str(e)}', 'warning')
    
    Screenshot.query.filter_by(domain_id=id).delete()
    
    # Delete associated endpoints
    Endpoint.query.filter_by(domain_id=id).delete()
    
    # Store the domain URL for the flash message
    domain_url = domain.url
    
    # Delete the domain
    db.session.delete(domain)
    db.session.commit()
    
    flash(f'Domain {domain_url} and all its data have been deleted successfully!', 'success')
    return redirect(url_for('domains'))

@app.route('/domain/<int:id>/upload', methods=['POST'])
def upload_screenshot(id):
    domain = Domain.query.get_or_404(id)
    
    if 'screenshot' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('domain_details', id=id))
    
    file = request.files['screenshot']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('domain_details', id=id))
    
    if file:
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        filename = f"{timestamp}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        screenshot = Screenshot(
            domain_id=domain.id,
            filename=filename,
            description=request.form.get('description', '')
        )
        
        db.session.add(screenshot)
        db.session.commit()
        
        flash('Screenshot uploaded successfully!', 'success')
    
    return redirect(url_for('domain_details', id=id))

# Workspace route
@app.route('/workspace')
def workspace():
    # In a real app, filter by current user
    domains = Domain.query.filter_by(assigned_to="Current User").all()
    return render_template('workspace.html', domains=domains)

# Basic Scanner Route
@app.route('/basic-scanner')
def basic_scanner_page():
    # Check if there's a domain to pre-fill from the query string
    domain_to_scan = request.args.get('domain', '')
    autorun = request.args.get('autorun', 'false')
    
    return render_template('basic_scanner.html', 
                          domain_to_scan=domain_to_scan,
                          autorun=autorun)

# Nuclei Scanner Route
@app.route('/nuclei-scanner')
def nuclei_scanner_page():
    # Check if there's a domain to pre-fill from the query string
    domain_to_scan = request.args.get('domain', '')
    autorun = request.args.get('autorun', 'false')
    
    return render_template('nuclei_scanner.html', 
                          domain_to_scan=domain_to_scan,
                          autorun=autorun)

# Run Basic Scan
@app.route('/run-basic-scan', methods=['POST'])
def run_basic_scan():
    domain_url = request.form.get('domain', '').strip()
    if not domain_url:
        return jsonify({"error": "No domain provided"}), 400
    
    # Generate a scan ID
    scan_id = f"basic_scan_{int(time.time())}"
    
    # Run basic scan
    result = basic_scanner.basic_scan(domain_url, scan_id)
    
    # Add domain ID for the link to details
    domain = Domain.query.filter_by(url=result['domain']).first()
    if domain:
        result['domain_id'] = domain.id
    
    return jsonify(result)

# Run Basic Scan Batch
@app.route('/run-basic-scan-batch', methods=['POST'])
def run_basic_scan_batch():
    data = request.get_json()
    
    if not data or 'domains' not in data:
        return jsonify({"error": "No domains provided"}), 400
    
    domains = data['domains']
    batch_size = data.get('batch_size', 10)
    options = data.get('options', {})
    
    # Generate a unique scan ID for this batch
    batch_id = f"batch_scan_{int(time.time())}"
    
    # Start the scanning process in a background thread
    def run_batch_scan():
        with app.app_context():
            for i in range(0, len(domains), batch_size):
                batch = domains[i:i+batch_size]
                for j, domain in enumerate(batch):
                    if domain:
                        # Generate a scan ID for each domain
                        scan_id = f"{batch_id}_{i//batch_size}_{j}"
                        try:
                            basic_scanner.basic_scan(domain, scan_id)
                        except Exception as e:
                            print(f"Error scanning {domain}: {str(e)}")
                # Small delay between batches
                time.sleep(2)
    
    thread = threading.Thread(target=run_batch_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "message": f"Started batch scan of {len(domains)} domains",
        "batch_size": batch_size
    })

# Run Nuclei Scan
@app.route('/run-nuclei-scan', methods=['POST'])
def run_nuclei_scan():
    domain_url = request.form.get('domain', '').strip()
    scan_options = request.form.get('scan_options', '').split(',')
    severity_levels = request.form.get('severity_levels', '').split(',')
    
    if not domain_url:
        return jsonify({"error": "No domain provided"}), 400
    
    # Generate a scan ID
    scan_id = f"nuclei_scan_{int(time.time())}"
    
    # Run nuclei scan
    result = nuclei_scanner.nuclei_scan(domain_url, scan_id, scan_options, severity_levels)
    
    # Add domain ID for the link to details
    domain = Domain.query.filter_by(url=result['domain']).first()
    if domain:
        result['domain_id'] = domain.id
    
    return jsonify(result)

# Main.js Analysis Routes
@app.route('/mainjs-analyzer')
def mainjs_analyzer_page():
    # Get domains with main.js files
    domains_with_mainjs = []
    domains = Domain.query.all()
    
    for domain in domains:
        # Check if any endpoint for this domain contains main.js
        has_mainjs = Endpoint.query.filter(
            Endpoint.domain_id == domain.id,
            (Endpoint.url.like('%main.%js%') | Endpoint.url.like('%app.%js%'))
        ).first() is not None
        
        if has_mainjs:
            domains_with_mainjs.append(domain)
    
    # Check if there's a domain to pre-select
    selected_domain_id = request.args.get('domain_id')
    selected_domain = None
    if selected_domain_id:
        selected_domain = Domain.query.get(selected_domain_id)
    
    return render_template('mainjs_analyzer.html', 
                          domains=domains_with_mainjs,
                          selected_domain=selected_domain)

@app.route('/get-mainjs-content/<int:domain_id>')
def get_mainjs_content(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    
    # Find the main.js endpoint - using improved regex pattern match for main.NNNNN.js
    mainjs_endpoint = Endpoint.query.filter(
        Endpoint.domain_id == domain_id,
        (Endpoint.url.like('%main.%js%') | Endpoint.url.like('%app.%js%'))
    ).first()
    
    if not mainjs_endpoint:
        return jsonify({"error": "No main.js file found for this domain"}), 404
    
    # Fetch the content of main.js
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
        response = requests.get(mainjs_endpoint.url, timeout=10, verify=False)
        
        if response.status_code >= 400:
            return jsonify({"error": f"Failed to fetch main.js: HTTP {response.status_code}"}), 400
        
        return jsonify({
            "url": mainjs_endpoint.url,
            "content": response.text
        })
    except Exception as e:
        return jsonify({"error": f"Error fetching main.js: {str(e)}"}), 500

# Domain Scan Link with Modified Routing
@app.route('/scan-link/<int:domain_id>')
def scan_link(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    scan_type = request.args.get('type', 'basic')
    
    if scan_type == 'nuclei':
        return redirect(url_for('nuclei_scanner_page', 
                               domain=domain.url, 
                               autorun='true'))
    elif scan_type == 'basic':
        return redirect(url_for('basic_scanner_page', 
                               domain=domain.url, 
                               autorun='true'))
    elif scan_type == 'mainjs':
        return redirect(url_for('mainjs_analyzer_page', 
                               domain_id=domain_id))
    else:
        return redirect(url_for('basic_scanner_page', 
                               domain=domain.url, 
                               autorun='true'))

# API Endpoint Bypass routes
@app.route('/api-bypass')
def api_bypass_page():
    # Get list of wordlists from the wordlists directory
    wordlists = []
    try:
        wordlists = [f for f in os.listdir(app.config['WORDLISTS_FOLDER']) if os.path.isfile(os.path.join(app.config['WORDLISTS_FOLDER'], f))]
    except:
        pass
    
    # Check if there's a domain to pre-fill from the query string
    domain_to_test = request.args.get('domain', '')
    
    # Ensure it has https:// prefix
    if domain_to_test and not domain_to_test.startswith(('http://', 'https://')):
        domain_to_test = 'https://' + domain_to_test
    
    return render_template('api_bypass.html', wordlists=wordlists, domain_to_test=domain_to_test)

@app.route('/run-bypass', methods=['POST'])
def run_bypass():
    domain = request.form.get('domain')
    wordlist = request.form.get('wordlist')
    
    if not domain or not wordlist:
        return jsonify({"error": "Domain and wordlist are required"}), 400
    
    # Path to wordlist
    wordlist_path = os.path.join(app.config['WORDLISTS_FOLDER'], wordlist)
    
    # Run the bypass script
    result = api_bypass.run_bypass(domain, wordlist_path)
    return jsonify(result)

# Templates management
@app.route('/templates', methods=['GET', 'POST'])
def templates():
    nuclei_cmd = 'nuclei'  # Assuming nuclei is installed
    
    if request.method == 'POST':
        if 'action' in request.form:
            if request.form['action'] == 'update':
                try:
                    subprocess.run([nuclei_cmd, '-update-templates'], check=True, capture_output=True)
                    flash('Nuclei templates updated successfully!', 'success')
                except Exception as e:
                    flash(f'Error updating templates: {str(e)}', 'danger')
                    
            elif request.form['action'] == 'add-custom' and 'template_content' in request.form:
                try:
                    template_name = request.form.get('template_name', '')
                    if not template_name.endswith('.yaml'):
                        template_name += '.yaml'
                        
                    # Safe template name - prevent directory traversal
                    template_name = os.path.basename(template_name)
                    
                    # Create custom templates directory if it doesn't exist
                    custom_dir = os.path.join(os.getcwd(), 'custom-templates')
                    os.makedirs(custom_dir, exist_ok=True)
                    
                    template_path = os.path.join(custom_dir, template_name)
                    with open(template_path, 'w') as f:
                        f.write(request.form['template_content'])
                        
                    flash(f'Custom template "{template_name}" added successfully!', 'success')
                except Exception as e:
                    flash(f'Error adding custom template: {str(e)}', 'danger')
    
    # Get list of available template categories
    template_categories = []
    custom_templates = []
    
    try:
        # Get built-in template categories
        output = subprocess.run([nuclei_cmd, '-tl'], check=False, capture_output=True, text=True)
        for line in output.stdout.splitlines():
            if line.strip() and not line.startswith(('[', '-')) and not line.strip() == "TEMPLATES":
                template_categories.append(line.strip())
        
        # Get custom templates
        custom_dir = os.path.join(os.getcwd(), 'custom-templates')
        if os.path.exists(custom_dir):
            custom_templates = [f for f in os.listdir(custom_dir) if f.endswith(('.yaml', '.yml'))]
    except Exception as e:
        flash(f'Error getting template list: {str(e)}', 'warning')
    
    return render_template('templates.html', 
                          template_categories=template_categories,
                          custom_templates=custom_templates,
                          nuclei_available=True)

# Add domain route (used internally after scanning)
@app.route('/add-domain', methods=['POST'])
def add_domain():
    url = request.form.get('url')
    
    if not url:
        flash('URL is required', 'danger')
        return redirect(url_for('domains'))
    
    # Check if domain already exists
    existing = Domain.query.filter_by(url=url).first()
    if existing:
        flash(f'Domain {url} already exists', 'warning')
        return redirect(url_for('domains'))
    
    new_domain = Domain(url=url)
    db.session.add(new_domain)
    db.session.commit()
    
    flash(f'Domain {url} added successfully!', 'success')
    return redirect(url_for('domains'))

# Vulnerability management routes
@app.route('/vulnerability/<int:id>/delete', methods=['POST'])
def delete_vulnerability(id):
    vuln = Vulnerability.query.get_or_404(id)
    domain_id = vuln.domain_id
    
    db.session.delete(vuln)
    db.session.commit()
    
    flash('Vulnerability deleted successfully!', 'success')
    return redirect(url_for('domain_details', id=domain_id))

@app.route('/vulnerability/<int:id>/update', methods=['POST'])
def update_vulnerability(id):
    vuln = Vulnerability.query.get_or_404(id)
    
    if 'severity' in request.form:
        vuln.severity = request.form['severity']
    
    if 'notes' in request.form:
        vuln.description = request.form['notes']
    
    db.session.commit()
    
    flash('Vulnerability updated successfully!', 'success')
    return redirect(url_for('domain_details', id=vuln.domain_id))

# Add new route for vulnerability classification
@app.route('/vulnerability/<int:id>/classify', methods=['POST'])
def classify_vulnerability_route(id):
    """Allow analysts to classify a vulnerability as true or false positive"""
    is_true_positive = request.form.get('is_true_positive', 'false').lower() == 'true'
    
    result = nuclei_scanner.classify_vulnerability(id, is_true_positive)
    
    if result:
        flash(f"Vulnerability classified as {'TRUE POSITIVE' if is_true_positive else 'FALSE POSITIVE'}", 'success')
    else:
        flash("Error classifying vulnerability", 'danger')
    
    # Redirect back to the domain details page
    vuln = Vulnerability.query.get_or_404(id)
    return redirect(url_for('domain_details', id=vuln.domain_id))

# Endpoint management routes
@app.route('/endpoint/<int:id>/delete', methods=['POST'])
def delete_endpoint(id):
    endpoint = Endpoint.query.get_or_404(id)
    domain_id = endpoint.domain_id
    
    db.session.delete(endpoint)
    db.session.commit()
    
    flash('Endpoint deleted successfully!', 'success')
    return redirect(url_for('domain_details', id=domain_id))

@app.route('/endpoint/<int:id>/update', methods=['POST'])
def update_endpoint(id):
    endpoint = Endpoint.query.get_or_404(id)
    
    if 'notes' in request.form:
        endpoint.notes = request.form['notes']
    
    if 'is_interesting' in request.form:
        endpoint.is_interesting = True
    else:
        endpoint.is_interesting = False
    
    db.session.commit()
    
    flash('Endpoint updated successfully!', 'success')
    return redirect(url_for('domain_details', id=endpoint.domain_id))

# Screenshot management
@app.route('/screenshot/<int:id>/delete', methods=['POST'])
def delete_screenshot(id):
    screenshot = Screenshot.query.get_or_404(id)
    domain_id = screenshot.domain_id
    
    # Delete the file
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], screenshot.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'warning')
    
    # Delete the database record
    db.session.delete(screenshot)
    db.session.commit()
    
    flash('Screenshot deleted successfully!', 'success')
    return redirect(url_for('domain_details', id=domain_id))

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500, error_message="Server error"), 500

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

# Run the application
if __name__ == '__main__':
    socketio.run(app, debug=True)