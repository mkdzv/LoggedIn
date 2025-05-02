import os
from pathlib import Path

class Config:
    DB_PATH = 'loggedin.db'
    
    # Windows Event Log settings
    WINDOWS_EVENT_IDS = {
        'success_login': 4624,
        'failed_login': 4625,
        'explicit_credential_use': 4648
    }
    
    # Splunk configuration
    SPLUNK = {
        'enabled': True,  # Set to False if not using Splunk
        'host': 'localhost',
        'port': 8089,
        'username': 'admin',
        'password': 'yourpassword',
        'hec_token': 'your-hec-token',  # HTTP Event Collector token
        'index': 'windows_events'
    }
    
    # Alert thresholds
    ALERT_THRESHOLDS = {
        'failed_logins': 5,
        'brute_force_window': '5m',
        'suspicious_user_patterns': [
            r'admin.*',
            r'.*\$',  # Hidden accounts
            r'system'
        ]
    }

class DevelopmentConfig(Config):
    DEBUG = True
    SPLUNK = {**Config.SPLUNK, 'enabled': False}  # Disable Splunk in dev

class ProductionConfig(Config):
    DEBUG = False
    DB_PATH = '/var/log/loggedin/loggedin.db'