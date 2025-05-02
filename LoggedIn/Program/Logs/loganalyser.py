from collections import defaultdict
from datetime import datetime, timedelta
import re
from Program.Configuration.config import Config

class LogAnalyser:
    def __init__(self, storage):
        self.storage = storage
        self.config = Config()
    
    def count_failed_logins(self):
        cursor = self.storage.conn.cursor()
        cursor.execute(f'''
            SELECT user, COUNT(*) as count 
            FROM logs 
            WHERE event_id = {self.config.WINDOWS_EVENT_IDS['failed_login']}
            GROUP BY user 
            ORDER BY count DESC
        ''')
        return cursor.fetchall()
    
    def detect_brute_force(self, window='5m', threshold=5):
        if window.endswith('m'):
            minutes = int(window[:-1])
            window_td = timedelta(minutes=minutes)
        
        cursor = self.storage.conn.cursor()
        cursor.execute(f'''
            SELECT user, timestamp 
            FROM logs 
            WHERE event_id = {self.config.WINDOWS_EVENT_IDS['failed_login']}
            ORDER BY timestamp
        ''')
        
        brute_force_attempts = defaultdict(list)
        now = datetime.now()
        
        for user, timestamp in cursor.fetchall():
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except ValueError:
                    continue
            
            if now - timestamp <= window_td:
                brute_force_attempts[user].append(timestamp)
        
        return {
            user: len(attempts)
            for user, attempts in brute_force_attempts.items()
            if len(attempts) >= threshold
        }
    
    def detect_suspicious_users(self):
        """Detect users matching suspicious patterns"""
        cursor = self.storage.conn.cursor()
        cursor.execute('''
            SELECT DISTINCT user FROM logs
        ''')
        
        suspicious_users = []
        for (user,) in cursor.fetchall():
            for pattern in self.config.ALERT_THRESHOLDS['suspicious_user_patterns']:
                if re.match(pattern, user, re.IGNORECASE):
                    suspicious_users.append(user)
                    break
        
        return suspicious_users