import re
from datetime import datetime

class LogParser:
    def __init__(self):
        # Windows Event Log pattern
        self.windows_event_pattern = re.compile(
            r'EventID=(?P<event_id>\d+)\s+'
            r'TimeCreated=(?P<timestamp>\S+)\s+'
            r'Computer=(?P<computer>\S+)\s+'
            r'User=(?P<user>\S+)'
        )
        
    def parse_line(self, line):
        """Parse a single log line into structured data"""
        match = self.windows_event_pattern.match(line)
        if match:
            log_data = match.groupdict()
            log_data['event_id'] = int(log_data['event_id'])
            log_data['timestamp'] = self._parse_windows_timestamp(log_data['timestamp'])
            return log_data
        return None
    
    def _parse_windows_timestamp(self, timestamp_str):
        """Parse Windows Event timestamp into datetime object"""
        try:
            return datetime.strptime(timestamp_str, '%Y%m%dT%H%M%SZ')
        except ValueError:
            return timestamp_str