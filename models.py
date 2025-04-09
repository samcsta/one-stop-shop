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
    
    def __repr__(self):
        return f'<Vulnerability {self.title}>'

class Screenshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Screenshot {self.filename}>'
