import os
import time
import sys
import random
import datetime
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
from collections import Counter, defaultdict
from matplotlib.ticker import MaxNLocator

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

class LogParser:
    def parse_line(self, line):
        """Parse a log line into structured data."""
        parts = line.split()
        parsed_data = {}
        
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                parsed_data[key] = value
                
        return parsed_data if parsed_data else None

class LogStorage:
    def __init__(self, db_path=None):
        """Initialize storage for logs."""
        self.logs = []
        self.db_path = db_path
        
    def store_log(self, log_entry):
        """Store a log entry."""
        self.logs.append(log_entry)
        
    def get_logs(self):
        """Retrieve all logs."""
        return self.logs
        
    def close(self):
        """Close any open connections."""
        pass

class LogAnalyser:
    def __init__(self, storage):
        """Initialize with a storage instance."""
        self.storage = storage
        
    def count_failed_logins(self):
        """Count failed login attempts by user."""
        failed_logins = Counter()
        
        for log in self.storage.get_logs():
            if log.get('EventID') == '4625':  # Failed login
                user = log.get('User', 'unknown')
                failed_logins[user] += 1
                
        return [(user, count) for user, count in failed_logins.items() if count > 0]
    
    def get_login_timeline(self):
        """Get login events with timestamps for timeline analysis."""
        timeline = []
        
        for log in self.storage.get_logs():
            if log.get('EventID') in ['4624', '4625']:  # Login events
                time_str = log.get('TimeCreated', '')
                if time_str:
                    try:
                        # Convert TimeCreated format to datetime
                        dt = datetime.datetime.strptime(time_str, '%Y%m%dT%H%M%SZ')
                        timeline.append({
                            'timestamp': dt,
                            'event_type': 'Success' if log.get('EventID') == '4624' else 'Failure',
                            'user': log.get('User', 'unknown'),
                            'computer': log.get('Computer', 'unknown')
                        })
                    except ValueError:
                        pass  # Skip entries with invalid timestamp format
                        
        return timeline
    
    def detect_brute_force(self, threshold=3, time_window_minutes=10):
        """Detect potential brute force attacks."""
        timeline = self.get_login_timeline()
        failed_attempts = defaultdict(list)
        
        # Group failed logins by user
        for event in timeline:
            if event['event_type'] == 'Failure':
                failed_attempts[event['user']].append(event['timestamp'])
        
        # Detect rapid sequences of failures
        brute_force = {}
        for user, timestamps in failed_attempts.items():
            if len(timestamps) >= threshold:
                # Sort timestamps
                sorted_times = sorted(timestamps)
                
                # Check for threshold failures within time window
                for i in range(len(sorted_times) - threshold + 1):
                    time_diff = (sorted_times[i + threshold - 1] - sorted_times[i]).total_seconds() / 60
                    if time_diff <= time_window_minutes:
                        brute_force[user] = len(timestamps)
                        break
                        
        return brute_force
    
    def detect_suspicious_users(self):
        """Detect suspicious user accounts."""
        suspicious = set()
        known_suspicious_patterns = ['hacker', 'admin', 'root', 'test', 'guest']
        
        for log in self.storage.get_logs():
            user = log.get('User', '').lower()
            # Check for suspicious patterns
            for pattern in known_suspicious_patterns:
                if pattern in user and user != 'backup_admin':  # Exclude admin accounts
                    suspicious.add(log.get('User'))
                    break
                    
        return list(suspicious)
    
    def detect_unusual_activity(self):
        """Detect unusual login patterns and activity."""
        timeline = self.get_login_timeline()
        
        # Group logins by hour to detect unusual timing
        hour_counts = defaultdict(int)
        user_computers = defaultdict(set)
        unusual_activity = []
        
        for event in timeline:
            hour = event['timestamp'].hour
            hour_counts[hour] += 1
            user_computers[event['user']].add(event['computer'])
        
        # Detect logins during unusual hours (midnight to 5am)
        unusual_hours = [h for h in range(0, 5) if hour_counts[h] > 0]
        if unusual_hours:
            unusual_activity.append(f"Unusual login hours detected: {', '.join(map(str, unusual_hours))}:00")
        
        # Detect users logging in from multiple computers
        for user, computers in user_computers.items():
            if len(computers) > 2:  # Arbitrary threshold
                unusual_activity.append(f"User {user} logged in from multiple computers: {', '.join(computers)}")
                
        return unusual_activity
    
    def get_event_statistics(self):
        """Get statistics about different event types."""
        event_counts = Counter()
        computer_activity = Counter()
        user_activity = Counter()
        
        for log in self.storage.get_logs():
            event_id = log.get('EventID')
            computer = log.get('Computer', 'unknown')
            user = log.get('User', 'unknown')
            
            event_counts[event_id] += 1
            computer_activity[computer] += 1
            user_activity[user] += 1
            
        return {
            'event_counts': dict(event_counts),
            'computer_activity': dict(computer_activity),
            'user_activity': dict(user_activity)
        }

class LogView:
    @staticmethod
    def plot_failed_logins(analyser):
        """Plot failed login attempts."""
        failed_logins = analyser.count_failed_logins()
        
        if not failed_logins:
            print("No failed logins to display.")
            return
            
        users = [x[0] for x in failed_logins]
        counts = [x[1] for x in failed_logins]
        
        plt.figure(figsize=(10, 6))
        bars = plt.bar(users, counts, color='crimson')
        
        plt.title('Failed Login Attempts by User', fontsize=15)
        plt.xlabel('User', fontsize=12)
        plt.ylabel('Number of Failed Attempts', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Add counts on top of bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig('failed_logins.png')
        plt.close()
        print("Failed logins chart saved as 'failed_logins.png'")
    
    @staticmethod
    def plot_login_timeline(analyser):
        """Plot login events over time."""
        timeline = analyser.get_login_timeline()
        
        if not timeline:
            print("No timeline data to display.")
            return
            
        # Extract data
        timestamps = [event['timestamp'] for event in timeline]
        event_types = [event['event_type'] for event in timeline]
        
        # Create figure
        plt.figure(figsize=(12, 6))
        
        # Plot by event type with different colors
        for event_type, color in [('Success', 'green'), ('Failure', 'red')]:
            mask = [t == event_type for t in event_types]
            if any(mask):
                plt.scatter(
                    [timestamps[i] for i in range(len(mask)) if mask[i]],
                    [i for i, m in enumerate(mask) if m],
                    label=event_type,
                    color=color,
                    s=50,
                    alpha=0.7
                )
        
        plt.title('Login Event Timeline', fontsize=15)
        plt.xlabel('Time', fontsize=12)
        plt.ylabel('Event Sequence', fontsize=12)
        plt.grid(True, linestyle='--', alpha=0.7)
        plt.legend()
        
        # Format x-axis with dates
        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
        plt.gcf().autofmt_xdate()
        
        plt.tight_layout()
        plt.savefig('login_timeline.png')
        plt.close()
        print("Login timeline chart saved as 'login_timeline.png'")
    
    @staticmethod
    def plot_event_distribution(analyser):
        """Plot distribution of event types."""
        stats = analyser.get_event_statistics()
        event_counts = stats['event_counts']
        
        if not event_counts:
            print("No event data to display.")
            return
            
        # Map event IDs to descriptive names
        event_names = {
            '4624': 'Successful Login',
            '4625': 'Failed Login',
            '4634': 'Logout',
            '4647': 'User Initiated Logout',
            '4672': 'Admin Login'
        }
        
        labels = [event_names.get(event_id, event_id) for event_id in event_counts.keys()]
        sizes = list(event_counts.values())
        
        # Create figure
        plt.figure(figsize=(10, 7))
        plt.pie(
            sizes, 
            labels=labels, 
            autopct='%1.1f%%',
            shadow=True, 
            startangle=140,
            colors=plt.cm.tab10.colors
        )
        plt.axis('equal')
        plt.title('Event Type Distribution', fontsize=15)
        
        plt.tight_layout()
        plt.savefig('event_distribution.png')
        plt.close()
        print("Event distribution chart saved as 'event_distribution.png'")
    
    @staticmethod
    def plot_computer_activity(analyser):
        """Plot activity by computer."""
        stats = analyser.get_event_statistics()
        computer_activity = stats['computer_activity']
        
        if not computer_activity:
            print("No computer activity data to display.")
            return
            
        computers = list(computer_activity.keys())
        counts = list(computer_activity.values())
        
        # Sort by activity count (descending)
        sorted_data = sorted(zip(computers, counts), key=lambda x: x[1], reverse=True)
        computers = [x[0] for x in sorted_data]
        counts = [x[1] for x in sorted_data]
        
        plt.figure(figsize=(10, 6))
        bars = plt.bar(computers, counts, color=plt.cm.viridis(np.linspace(0, 1, len(computers))))
        
        plt.title('Activity by Computer', fontsize=15)
        plt.xlabel('Computer', fontsize=12)
        plt.ylabel('Number of Events', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Add counts on top of bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig('computer_activity.png')
        plt.close()
        print("Computer activity chart saved as 'computer_activity.png'")
    
    @staticmethod
    def plot_hourly_activity(analyser):
        """Plot login activity by hour of day."""
        timeline = analyser.get_login_timeline()
        
        if not timeline:
            print("No timeline data to display.")
            return
            
        # Count events by hour
        hour_counts = defaultdict(int)
        hour_success = defaultdict(int)
        hour_failures = defaultdict(int)
        
        for event in timeline:
            hour = event['timestamp'].hour
            hour_counts[hour] += 1
            if event['event_type'] == 'Success':
                hour_success[hour] += 1
            else:
                hour_failures[hour] += 1
        
        # Ensure all hours are represented (0-23)
        hours = list(range(24))
        success_counts = [hour_success.get(hour, 0) for hour in hours]
        failure_counts = [hour_failures.get(hour, 0) for hour in hours]
        
        plt.figure(figsize=(12, 6))
        
        # Create stacked bar chart
        plt.bar(hours, success_counts, label='Successful Logins', color='green', alpha=0.7)
        plt.bar(hours, failure_counts, bottom=success_counts, label='Failed Logins', color='red', alpha=0.7)
        
        plt.title('Login Activity by Hour of Day', fontsize=15)
        plt.xlabel('Hour (24-hour format)', fontsize=12)
        plt.ylabel('Number of Events', fontsize=12)
        plt.xticks(hours)
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        plt.legend()
        
        # Highlight business hours (9-17)
        plt.axvspan(9, 17, alpha=0.2, color='blue', label='Business Hours')
        
        plt.tight_layout()
        plt.savefig('hourly_activity.png')
        plt.close()
        print("Hourly activity chart saved as 'hourly_activity.png'")

class SplunkIntegration:
    def __init__(self, config):
        """Initialize with configuration but gracefully handle connection issues."""
        self.enabled = False
        self.error_reported = False
        
        # Store config for reference but don't try to connect
        self.config = config
        
        print("Splunk integration disabled to prevent connection errors")
        
    def send_to_hec(self, data):
        """Simulate sending data to Splunk HEC."""
        if not self.error_reported:
            print("Splunk integration is disabled - skipping data transmission")
            self.error_reported = True
        return True

class Config:
    def __init__(self):
        """Initialize with default configuration."""
        self.DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs.db')
        self.SPLUNK = {
            'enabled': False,  # Disable Splunk by default
            'host': 'localhost',
            'port': 8088,
            'token': 'your-token-here',
            'index': 'windows_events'
        }

def generate_realistic_log(timestamp, event_type='4624', computer=None, user=None):
    """Generate a realistic log entry as a string."""
    computers = ['DC01', 'DC02', 'WS01', 'WS02', 'SRV01', 'SRV02', 'LAPTOP01', 'DESKTOP01']
    normal_users = ['user1@domain.com', 'admin@domain.com', 'service_acct@domain.com', 
                   'backup_admin@domain.com', 'helpdesk@domain.com', 'john.doe@domain.com']
    suspicious_users = ['hacker@bad.com', 'test@domain.com', 'admin123@domain.com', 
                       'root@domain.com', 'guest@domain.com', 'scanner@attack.com']
    
    if not computer:
        computer = random.choice(computers)
    
    if not user:
        if event_type == '4625' and random.random() < 0.7:  # 70% chance of suspicious user for failed logins
            user = random.choice(suspicious_users)
        else:
            user = random.choice(normal_users)
    
    # Format timestamp as expected by the parser
    time_str = timestamp.strftime('%Y%m%dT%H%M%SZ')
    
    # Additional fields based on event type
    additional = ''
    if event_type == '4624':  # Successful login
        logon_types = ['2', '3', '7', '10']
        logon_type = random.choice(logon_types)
        additional = f'LogonType={logon_type} AuthPackage=Kerberos'
    elif event_type == '4625':  # Failed login
        failure_reasons = ['0xC000006D', '0xC000006A', '0xC0000234', '0xC0000072']
        reason = random.choice(failure_reasons)
        additional = f'FailureReason={reason} LogonType=3'
    elif event_type == '4672':  # Admin login
        additional = 'PrivilegeList=SeBackupPrivilege,SeRestorePrivilege'
    
    return f'EventID={event_type} TimeCreated={time_str} Computer={computer} User={user} {additional}'.strip()

def generate_sample_logs(num_logs=100):
    """Generate a list of sample logs with realistic patterns."""
    logs = []
    
    # Start time for the log sequence
    start_time = datetime.datetime.now() - datetime.timedelta(days=1)
    
    # Event types and their relative frequencies
    event_types = {
        '4624': 0.6,  # Successful login (60%)
        '4625': 0.3,  # Failed login (30%)
        '4634': 0.05, # Logout (5%)
        '4672': 0.05  # Admin privileges assigned (5%)
    }
    
    # Generate synthetic attack patterns
    
    # 1. Brute force attack (multiple failed logins followed by success)
    attack_time = start_time + datetime.timedelta(hours=random.randint(1, 6))
    attack_computer = 'WS02'
    attack_user = 'hacker@bad.com'
    
    # Add 5 failed attempts
    for i in range(5):
        timestamp = attack_time + datetime.timedelta(minutes=i*2)
        logs.append(generate_realistic_log(timestamp, '4625', attack_computer, attack_user))
    
    # Occasional success
    if random.random() < 0.3:  # 30% chance the attack "succeeds"
        timestamp = attack_time + datetime.timedelta(minutes=12)
        logs.append(generate_realistic_log(timestamp, '4624', attack_computer, attack_user))
    
    # 2. Unusual hour login (suspicious activity at 2-4 AM)
    unusual_time = start_time.replace(hour=random.randint(2, 4), minute=random.randint(0, 59))
    logs.append(generate_realistic_log(unusual_time, '4624', 'SRV01', 'admin@domain.com'))
    
    # 3. Admin activity
    admin_time = start_time + datetime.timedelta(hours=random.randint(9, 17))  # Business hours
    logs.append(generate_realistic_log(admin_time, '4672', 'DC01', 'backup_admin@domain.com'))
    
    # Fill the rest with random events
    remaining_logs = num_logs - len(logs)
    for i in range(remaining_logs):
        # Random time within the last 24 hours
        hours_offset = random.randint(0, 23)
        minutes_offset = random.randint(0, 59)
        timestamp = start_time + datetime.timedelta(hours=hours_offset, minutes=minutes_offset)
        
        # Select event type based on probability distribution
        rand = random.random()
        cumulative = 0
        selected_event = '4624'  # Default
        for event, prob in event_types.items():
            cumulative += prob
            if rand <= cumulative:
                selected_event = event
                break
        
        logs.append(generate_realistic_log(timestamp, selected_event))
    
    # Sort logs by timestamp
    sorted_logs = sorted(logs, key=lambda x: x.split('TimeCreated=')[1].split(' ')[0])
    
    return sorted_logs

def process_log_file(file_path, storage, splunk=None):
    """Process a log file and store parsed entries."""
    parser = LogParser()
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                parsed = parser.parse_line(line)
                if parsed:
                    storage.store_log(parsed)
                    if splunk and splunk.enabled:
                        splunk.send_to_hec(parsed)

def generate_alerts(analyser, splunk=None):
    """Generate security alerts based on log analysis."""
    print("\n=== Security Alerts ===")
    
    # Brute force detection
    brute_force = analyser.detect_brute_force()
    if brute_force:
        print("\n[!] Brute Force Attempts Detected:")
        for user, attempts in brute_force.items():
            alert_msg = f"User {user} failed {attempts} login attempts"
            print(f"- {alert_msg}")
            if splunk and splunk.enabled:
                splunk.send_to_hec({
                    "event": alert_msg,
                    "severity": "high",
                    "type": "brute_force"
                })
    
    # Suspicious users
    suspicious_users = analyser.detect_suspicious_users()
    if suspicious_users:
        print("\n[!] Suspicious Users Detected:")
        for user in suspicious_users:
            alert_msg = f"Suspicious user account: {user}"
            print(f"- {alert_msg}")
            if splunk and splunk.enabled:
                splunk.send_to_hec({
                    "event": alert_msg,
                    "severity": "medium",
                    "type": "suspicious_user"
                })
    
    # Unusual activity
    unusual_activity = analyser.detect_unusual_activity()
    if unusual_activity:
        print("\n[!] Unusual Activity Detected:")
        for activity in unusual_activity:
            print(f"- {activity}")
            if splunk and splunk.enabled:
                splunk.send_to_hec({
                    "event": activity,
                    "severity": "medium",
                    "type": "unusual_activity"
                })

def main():
    """Main function to run the log analysis application."""
    config = Config()
    storage = LogStorage(db_path=config.DB_PATH)
    analyser = LogAnalyser(storage)
    splunk = SplunkIntegration(config)
    
    print("=== Windows Event Log Security Analysis ===")
    print("Generating 100 sample logs with realistic patterns...")
    
    # Generate sample logs
    sample_logs = generate_sample_logs(num_logs=100)
    
    # Create temporary log file
    log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sample_events.log')
    with open(log_file_path, 'w') as f:
        f.write('\n'.join(sample_logs))
    
    print(f"Log file created at: {log_file_path}")
    print("Processing logs...")
    
    # Process the log file
    process_log_file(log_file_path, storage, splunk)
    
    # Display analysis results
    print("\n=== Analysis Results ===")
    print("\nFailed login attempts by user:")
    for user, count in analyser.count_failed_logins():
        print(f"- {user}: {count} attempts")
    
    print("\nSuspicious users detected:")
    suspicious = analyser.detect_suspicious_users()
    if suspicious:
        for user in suspicious:
            print(f"- {user}")
    else:
        print("- None detected")
    
    # Generate security alerts
    generate_alerts(analyser, splunk)
    
    # Show statistics
    stats = analyser.get_event_statistics()
    print("\n=== Event Statistics ===")
    print(f"Total events processed: {sum(stats['event_counts'].values())}")
    print("Event types:")
    for event_id, count in stats['event_counts'].items():
        event_name = {
            '4624': 'Successful Login',
            '4625': 'Failed Login',
            '4634': 'Logout',
            '4647': 'User Initiated Logout',
            '4672': 'Admin Login'
        }.get(event_id, 'Unknown')
        print(f"- {event_id} ({event_name}): {count}")
    
    # Generate all visualizations
    print("\n=== Generating Visualizations ===")
    LogView.plot_failed_logins(analyser)
    LogView.plot_login_timeline(analyser)
    LogView.plot_event_distribution(analyser)
    LogView.plot_computer_activity(analyser)
    LogView.plot_hourly_activity(analyser)
    
    print("\nAnalysis complete! All visualizations have been saved as PNG files.")
    
    # Clean up
    storage.close()
    os.remove(log_file_path)

if __name__ == '__main__':
    main()