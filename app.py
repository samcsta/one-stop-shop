import os
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
from config import Config
from models import db, Domain, Technology, Vulnerability, Screenshot
import utils.scanner as scanner
import utils.api_bypass as api_bypass

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db.init_app(app)

# Ensure upload and wordlists directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['WORDLISTS_FOLDER'], exist_ok=True)

@app.before_first_request
def create_tables():
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

# Scanner routes
@app.route('/scanner')
def scanner_page():
    # Check if there's a domain to pre-fill from the query string
    domain_to_scan = request.args.get('domain', '')
    return render_template('scanner.html', domain_to_scan=domain_to_scan)

@app.route('/scan', methods=['POST'])
def scan():
    if 'single_domain' in request.form:
        domain_url = request.form['single_domain']
        # Call the scanner utility with the domain
        result = scanner.scan_domain(domain_url)
        
        # Check if domain has 403 errors (for API bypass suggestion)
        result['has_403_error'] = any('403' in vuln.lower() for vuln in result.get('vulnerabilities', []))
        
        return jsonify(result)
    elif 'domain_list' in request.form:
        domains = request.form['domain_list'].split('\n')
        results = []
        for domain in domains:
            domain = domain.strip()
            if domain:
                # Scan each domain
                result = scanner.scan_domain(domain)
                
                # Check if domain has 403 errors
                result['has_403_error'] = any('403' in vuln.lower() for vuln in result.get('vulnerabilities', []))
                
                results.append(result)
        return jsonify(results)
    
    return jsonify({"error": "No domain provided"}), 400

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

# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
