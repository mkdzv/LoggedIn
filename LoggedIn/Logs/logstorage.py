import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Union
import json

class LogStorage:
    def __init__(self, db_path: str = 'event_logs.db') -> None:
        """Initialize the log storage database with enhanced tracking.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.conn = sqlite3.connect(db_path)
        self._create_tables()
        self.log_history = []
    
    def _create_tables(self) -> None:
        """Create the required database tables if they don't exist."""
        cursor = self.conn.cursor()
        
        # Main logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                computer TEXT,
                user TEXT,
                logon_type TEXT,
                source_ip TEXT,
                status TEXT,
                raw_text TEXT,
                additional_info TEXT,
                processed BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                analysis_results TEXT
            )
        ''')
        
        # Visualizations metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS visualizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                log_ids TEXT  # JSON array of related log IDs
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_id ON logs(event_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user ON logs(user)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_computer ON logs(computer)')
        
        self.conn.commit()
    
    def store_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store a parsed log entry with full tracking.
        
        Args:
            log_data: Dictionary containing parsed log data
            
        Returns:
            Dictionary containing stored log info and status
        """
        cursor = self.conn.cursor()
        timestamp = self._parse_timestamp(log_data.get('TimeCreated'))
        
        # Prepare additional fields
        standard_fields = {
            'EventID', 'TimeCreated', 'Computer', 'User', 
            'LogonType', 'SourceIP', 'Status'
        }
        additional_info = {
            k: v for k, v in log_data.items() 
            if k not in standard_fields
        }
        
        cursor.execute('''
            INSERT INTO logs (
                event_id, timestamp, computer, user,
                logon_type, source_ip, status,
                raw_text, additional_info
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_data.get('EventID'),
            timestamp,
            log_data.get('Computer'),
            log_data.get('User'),
            log_data.get('LogonType'),
            log_data.get('SourceIP'),
            log_data.get('Status'),
            str(log_data),
            json.dumps(additional_info) if additional_info else None
        ))
        
        self.conn.commit()
        log_id = cursor.lastrowid
        
        # Track in history
        log_entry = {
            'id': log_id,
            'event_id': log_data.get('EventID'),
            'timestamp': timestamp,
            'computer': log_data.get('Computer'),
            'user': log_data.get('User'),
            'status': 'stored',
            'processed': False,
            'analysis': None
        }
        self.log_history.append(log_entry)
        
        return log_entry
    
    def update_log_analysis(self, log_id: int, analysis_results: Dict[str, Any]) -> bool:
        """Update log with analysis results.
        
        Args:
            log_id: ID of the log to update
            analysis_results: Dictionary of analysis findings
            
        Returns:
            True if update was successful
        """
        cursor = self.conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE logs 
                SET analysis_results = ?, processed = 1 
                WHERE id = ?
            ''', (json.dumps(analysis_results), log_id))
            
            self.conn.commit()
            
            # Update history
            for entry in self.log_history:
                if entry['id'] == log_id:
                    entry['analysis'] = analysis_results
                    entry['status'] = 'analyzed'
                    entry['processed'] = True
                    break
            
            return True
        except sqlite3.Error:
            return False
    
    def store_visualization(self, name: str, file_path: str, related_log_ids: List[int] = None) -> bool:
        """Store visualization metadata.
        
        Args:
            name: Name of the visualization
            file_path: Path to the visualization file
            related_log_ids: List of log IDs this visualization relates to
            
        Returns:
            True if storage was successful
        """
        cursor = self.conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO visualizations (name, file_path, log_ids)
                VALUES (?, ?, ?)
            ''', (
                name,
                file_path,
                json.dumps(related_log_ids) if related_log_ids else None
            ))
            
            self.conn.commit()
            return True
        except sqlite3.Error:
            return False
    
    def get_visualizations(self) -> List[Dict[str, Any]]:
        """Get all stored visualizations.
        
        Returns:
            List of visualization metadata dictionaries
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM visualizations ORDER BY created_at DESC')
        return [
            {
                'id': row[0],
                'name': row[1],
                'file_path': row[2],
                'created_at': row[3],
                'log_ids': json.loads(row[4]) if row[4] else []
            }
            for row in cursor.fetchall()
        ]
    
    def get_log_details(self, log_id: int) -> Dict[str, Any]:
        """Get complete details for a specific log.
        
        Args:
            log_id: ID of the log to retrieve
            
        Returns:
            Dictionary with all log details and analysis
        """
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM logs WHERE id = ?', (log_id,))
        row = cursor.fetchone()
        
        if not row:
            return None
            
        return {
            'id': row[0],
            'event_id': row[1],
            'timestamp': row[2],
            'computer': row[3],
            'user': row[4],
            'logon_type': row[5],
            'source_ip': row[6],
            'status': row[7],
            'raw_text': row[8],
            'additional_info': json.loads(row[9]) if row[9] else None,
            'processed': bool(row[10]),
            'created_at': row[11],
            'analysis_results': json.loads(row[12]) if row[12] else None
        }
    
    def _parse_timestamp(self, time_str: Optional[str]) -> str:
        """Parse and format timestamp string."""
        if not time_str:
            return datetime.now().isoformat()
        
        try:
            dt = datetime.strptime(time_str, '%Y%m%dT%H%M%SZ')
            return dt.isoformat()
        except ValueError:
            return datetime.now().isoformat()
    
    def generate_log_report(self) -> str:
        """Generate a comprehensive report of all log processing.
        
        Returns:
            Formatted string report
        """
        report = ["=== LOG PROCESSING REPORT ==="]
        report.append(f"Total logs processed: {len(self.log_history)}")
        report.append(f"First log timestamp: {self.log_history[0]['timestamp']}")
        report.append(f"Last log timestamp: {self.log_history[-1]['timestamp']}")
        report.append("\nProcessing Summary:")
        
        status_counts = {}
        for entry in self.log_history:
            status_counts[entry['status']] = status_counts.get(entry['status'], 0) + 1
        
        for status, count in status_counts.items():
            report.append(f"- {status}: {count} logs")
        
        report.append("\nSample Log Details:")
        for entry in self.log_history[:5]:  # Show first 5 as sample
            report.append(
                f"\n[Log ID: {entry['id']}] {entry['event_id']} @ {entry['timestamp']}\n"
                f"Computer: {entry['computer']}\n"
                f"User: {entry['user']}\n"
                f"Status: {entry['status']}"
            )
            if entry['analysis']:
                report.append(f"Analysis: {json.dumps(entry['analysis'], indent=2)}")
        
        return "\n".join(report)
    
    def close(self) -> None:
        """Close the database connection and clean up."""
        self.conn.close()
        self.log_history.clear()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


if __name__ == '__main__':
    # Enhanced example usage
    with LogStorage() as storage:
        # Test with sample data
        test_logs = [
            {
                'EventID': '4624',
                'TimeCreated': '20230101T120000Z',
                'Computer': 'WORKSTATION01',
                'User': 'john.doe@domain.com',
                'LogonType': '2',
                'Status': '0x0'
            },
            {
                'EventID': '4625',
                'TimeCreated': '20230101T120100Z',
                'Computer': 'WORKSTATION01',
                'User': 'hacker@bad.com',
                'LogonType': '3',
                'Status': '0xC000006A'
            }
        ]
        
        print("Storing test logs...")
        for log in test_logs:
            storage.store_log(log)
        
        print("\nDatabase contents:")
        storage.print_recent_logs()
        
        print("\nGenerating report...")
        print(storage.generate_log_report())
        
        print(f"\nTotal logs in database: {storage.count_logs()}")