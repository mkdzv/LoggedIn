import splunklib.client as client
from splunklib.client import Service
from Program.Configuration.config import Config
import time

class SplunkIntegration:
    def __init__(self, config):
        self.config = config.SPLUNK
        self.service = None
        
        if self.config['enabled']:
            self.connect()
    
    def connect(self):
        """Connect to Splunk instance"""
        try:
            self.service = client.connect(
                host=self.config['host'],
                port=self.config['port'],
                username=self.config['username'],
                password=self.config['password']
            )
            print("Successfully connected to Splunk")
        except Exception as e:
            print(f"Splunk connection failed: {str(e)}")
            self.service = None
    
    def send_to_hec(self, event_data, sourcetype="windows:event"):
        """Send data via HTTP Event Collector (HEC)"""
        if not self.config['enabled']:
            return False
        
        try:
            # In a real implementation, you would use the HEC endpoint
            # This is a simplified version using the SDK
            index = self.service.indexes[self.config['index']]
            index.submit(
                event=event_data,
                sourcetype=sourcetype,
                source="LoggedIn"
            )
            return True
        except Exception as e:
            print(f"Failed to send to Splunk: {str(e)}")
            return False
    
    def search_failed_logins(self, earliest="-24h", latest="now"):
        """Search for failed login events in Splunk"""
        if not self.service:
            return []
        
        search_query = (
            f'search index="{self.config["index"]}" '
            f'EventID={Config.WINDOWS_EVENT_IDS["failed_login"]} '
            f'earliest={earliest} latest={latest} '
            '| stats count by user'
        )
        
        try:
            job = self.service.jobs.create(search_query)
            while not job.is_done():
                time.sleep(0.5)
            
            return [dict(result) for result in job.results()]
        except Exception as e:
            print(f"Splunk search failed: {str(e)}")
            return []