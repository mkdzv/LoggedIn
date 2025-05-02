import os
import json
import matplotlib.pyplot as plt
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import asdict
import hashlib

class DataManager:
    def __init__(self, output_dir='data_results'):
        self.output_dir = output_dir
        self.visualizations_dir = os.path.join(output_dir, 'visualizations')
        self.reports_dir = os.path.join(output_dir, 'reports')
        self._create_directories()

    def _create_directories(self):
        """Ensure all required directories exist."""
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.visualizations_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

    def save_visualization(self, visualization_result) -> Dict[str, Any]:
        """Save visualization with metadata.
        
        Args:
            visualization_result: VisualizationResult object
            
        Returns:
            Dictionary containing saved visualization metadata
        """
        if not visualization_result:
            return None

        # Generate unique filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{visualization_result.name}_{timestamp}.png"
        filepath = os.path.join(self.visualizations_dir, filename)

        # Save the figure
        visualization_result.figure.savefig(filepath, dpi=300)
        plt.close(visualization_result.figure)

        # Create metadata
        metadata = {
            'name': visualization_result.name,
            'filepath': filepath,
            'description': visualization_result.description,
            'created_at': datetime.now().isoformat(),
            'related_log_ids': visualization_result.related_log_ids,
            'file_hash': self._calculate_file_hash(filepath)
        }

        # Save metadata
        metadata_path = os.path.join(
            self.visualizations_dir,
            f"{visualization_result.name}_{timestamp}.json"
        )
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        return metadata

    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def save_analysis_results(self, results: Dict[str, Any], 
                            filename: Optional[str] = None) -> str:
        """Save analysis results with timestamp.
        
        Args:
            results: Analysis results dictionary
            filename: Optional custom filename (without extension)
            
        Returns:
            Path to the saved file
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"analysis_results_{timestamp}.json"

        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        return filepath

    def generate_report(self, results: Dict[str, Any], 
                       report_type: str = 'security') -> str:
        """Generate comprehensive report with visualization references.
        
        Args:
            results: Analysis results dictionary
            report_type: Type of report ('security', 'technical', 'summary')
            
        Returns:
            Path to the generated report file
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        report_lines = [
            f"{report_type.capitalize()} Analysis Report - {timestamp}",
            "=" * 80,
            ""
        ]

        # Add executive summary for security reports
        if report_type == 'security':
            report_lines.extend(self._generate_security_summary(results))

        # Add detailed findings
        report_lines.extend(self._generate_detailed_findings(results, report_type))

        # Add visualization references if available
        if 'visualizations' in results:
            report_lines.extend([
                "",
                "=== VISUALIZATIONS ===",
                "The following visualizations were generated:"
            ])
            for viz in results['visualizations']:
                report_lines.append(
                    f"- {viz['name']}: {viz['description']} "
                    f"(see {os.path.basename(viz['filepath'])})"
                )

        # Save report
        filename = f"{report_type}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write('\n'.join(report_lines))

        return filepath

    def _generate_security_summary(self, results: Dict[str, Any]) -> List[str]:
        """Generate security-specific summary section."""
        summary = ["=== EXECUTIVE SUMMARY ==="]
        
        # Count critical findings
        critical_count = len(results.get('brute_force', {})) + \
                        len(results.get('suspicious_users', []))
        
        summary.append(
            f"Found {critical_count} critical security events "
            f"and {len(results.get('failed_logins', []))} security warnings."
        )
        
        if critical_count > 0:
            summary.append("\n[!] CRITICAL FINDINGS REQUIRE IMMEDIATE ATTENTION")
        
        return summary

    def _generate_detailed_findings(self, results: Dict[str, Any], 
                                  report_type: str) -> List[str]:
        """Generate detailed findings section based on report type."""
        details = ["", "=== DETAILED FINDINGS ==="]
        
        if report_type == 'security':
            # Failed logins
            if results.get('failed_logins'):
                details.append("\n[FAILED LOGIN ATTEMPTS]")
                for user, count, _ in results['failed_logins']:
                    details.append(f"- {user}: {count} attempts")

            # Brute force
            if results.get('brute_force'):
                details.append("\n[BRUTE FORCE ATTEMPTS]")
                for user, attempts in results['brute_force'].items():
                    details.append(f"- {user}: {attempts} failed attempts")

            # Suspicious users
            if results.get('suspicious_users'):
                details.append("\n[SUSPICIOUS USERS]")
                for user in results['suspicious_users']:
                    details.append(f"- {user}")

        # Add technical details for technical reports
        if report_type == 'technical':
            if results.get('event_stats'):
                details.append("\n[EVENT STATISTICS]")
                for event_id, count in results['event_stats'].items():
                    details.append(f"- Event {event_id}: {count} occurrences")

        return details