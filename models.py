from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Users(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    imie = db.Column(db.String(50), nullable=False)
    nazwisko = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)  
    role = db.Column(db.String(20), default='user')
    uproszczony = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    # POPRAWKA: Zwiększono limit do 255 znaków, aby baza PostgreSQL na Render nie odrzucała długich wpisów z IPinfo
    registration_ip = db.Column(db.String(255), nullable=True)
    
    latitude = db.Column(db.String(30), nullable=True)
    longitude = db.Column(db.String(30), nullable=True)
    
    two_factor_code = db.Column(db.String(20), nullable=True)
    two_factor_expiry = db.Column(db.DateTime, nullable=True)
    is_approved = db.Column(db.Boolean, default=False)

    # Ochrona przed Brute-Force
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    # Weryfikacja konta, urządzenie i powiadomienia od administratora
    registration_device = db.Column(db.String(255), nullable=True)
    verification_status = db.Column(db.String(20), default='PENDING')
    rejection_reason = db.Column(db.Text, nullable=True)
    admin_message = db.Column(db.Text, nullable=True)

class Attendance(db.Model):
    __tablename__ = "attendance"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    data_sluzby = db.Column(db.Date, nullable=False, index=True)
    typ_mszy = db.Column(db.String(20), nullable=False) 
    nazwa_inna = db.Column(db.String(100), nullable=True)
    godzina = db.Column(db.String(5), nullable=False)
    data_wpisu = db.Column(db.DateTime, default=datetime.now)
    
    user = db.relationship('Users', backref=db.backref('attendances', lazy=True))

class Announcement(db.Model):
    __tablename__ = "announcement"
    id = db.Column(db.Integer, primary_key=True)
    tytul = db.Column(db.String(100), nullable=False)
    tresc = db.Column(db.Text, nullable=False)
    data_dodania = db.Column(db.DateTime, default=datetime.now)

class Schedule(db.Model):
    __tablename__ = "schedule"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    dzien_tygodnia = db.Column(db.String(20), nullable=False)
    godzina = db.Column(db.String(5), nullable=False)

    user = db.relationship('Users', backref=db.backref('schedules', lazy=True))

class PasswordResetRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    ip_address = db.Column(db.String(255)) 
    status = db.Column(db.String(20), default='PENDING')
    proposed_password = db.Column(db.String(255), nullable=True)

class SystemSettings(db.Model):
    __tablename__ = "system_settings"
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(255), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    event_code = db.Column(db.String(50), nullable=False, index=True)
    username = db.Column(db.String(50), nullable=True)
    ip_address = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now, index=True)

def get_setting(key, default=None):
    try:
        item = db.session.get(SystemSettings, key)
        if item is not None:
            return item.value
    except Exception:
        pass
    return str(default) if default is not None else None

def set_setting(key, value):
    item = db.session.get(SystemSettings, key)
    if item is None:
        item = SystemSettings(key=key, value=str(value))
        db.session.add(item)
    else:
        item.value = str(value)
    db.session.commit()
    return item
