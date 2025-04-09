from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Tags for domains
tags = db.Table('tags',
    db.Column('domain_id', db.Integer, db.ForeignKey('domain.id'), primary_key=True),
    db.Column('technology_id', db.Integer, db.ForeignKey('technology.id'), primary_key=True)
)

class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), unique=True, nullable=False)
    status = db.Column(db.String(20), default='ACTIVE')  # ACTIVE/INACTIVE
    assessment_status = db.Column(db.String(20), default='NEW')  # NEW/IN PROGRESS/FINISHED/FALSE ALARM
    last_scanned = db.Column(db.DateTime, default=datetime.utcnow)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_to = db.Column(db.String(100), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='domain', lazy=True)
    screenshots = db.relationship('Screenshot', backref='domain', lazy=True)
    technologies = db.relationship('Technology', secondary=tags, lazy='subquery',
        backref=db.backref('domains', lazy=True))
    endpoints = db.relationship('Endpoint', backref='domain', lazy=True)  # New relationship

    def __repr__(self):
        return f'<Domain {self.url}>'

class Technology(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    version = db.Column(db.String(50), nullable=True)
    
    def __repr__(self):
        return f'<Technology {self.name} {self.version}>'

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    cwe = db.Column(db.String(50), nullable=True)
    cve = db.Column(db.String(50), nullable=True)
    severity = db.Column(db.String(20), nullable=True)  # LOW/MEDIUM/HIGH/CRITICAL
    location = db.Column(db.String(255), nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    date_discovered = db.Column(db.DateTime, default=datetime.utcnow)
    last_updated = db.Column(db.DateTime, nullable=True)  # New field for tracking updates
    status = db.Column(db.String(20), default=None)  # New field: NULL/CONFIRMED/DISMISSED
    
    def __repr__(self):
        return f'<Vulnerability {self.title}>'
    
    @property
    def is_classified(self):
        """Check if the vulnerability has been classified"""
        return self.status is not None
    
    @property
    def is_true_positive(self):
        """Check if the vulnerability is a confirmed true positive"""
        return self.status == 'CONFIRMED'

class Screenshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Screenshot {self.filename}>'

# New model for tracking discovered endpoints
class Endpoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    url = db.Column(db.String(512), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    status_code = db.Column(db.Integer, nullable=True)  # HTTP status code
    method = db.Column(db.String(10), default='GET')  # HTTP method (GET, POST, etc.)
    content_type = db.Column(db.String(100), nullable=True)  # Content-Type of the response
    is_interesting = db.Column(db.Boolean, default=False)  # Flag for endpoints of special interest
    notes = db.Column(db.Text, nullable=True)  # Analyst notes
    date_discovered = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Endpoint {self.url}>'
    
    @property
    def is_accessible(self):
        """Check if the endpoint is accessible (status code < 400)"""
        return self.status_code is not None and self.status_code < 400
    
    @property
    def is_protected(self):
        """Check if the endpoint is protected (401 or 403)"""
        return self.status_code in (401, 403)