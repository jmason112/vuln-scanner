#!/usr/bin/env python3
"""
Utility Module - Helper functions for the vulnerability scanner.

This module provides utility functions for logging, severity calculation,
and other common tasks used by the scanner modules.
"""

import os
import logging
import platform
import json
from typing import Dict, List, Any, Optional

def setup_logging(log_file: str, verbose: bool = False) -> logging.Logger:
    """
    Set up logging for the vulnerability scanner.
    
    Args:
        log_file: Path to the log file
        verbose: Whether to enable verbose logging
        
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger("vulnerability_scanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Create file handler
    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO if verbose else logging.WARNING)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    except Exception as e:
        # If we can't set up file logging, just use console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO if verbose else logging.WARNING)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        logger.warning(f"Could not set up file logging: {str(e)}")
    
    return logger

def get_severity_score(vulnerabilities: List[Dict[str, Any]]) -> float:
    """
    Calculate average severity score from vulnerabilities.
    
    Args:
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        Average CVSS-like score (0.0-10.0)
    """
    if not vulnerabilities:
        return 0.0
    
    # Map severity levels to CVSS-like scores
    severity_map = {
        "Critical": 9.5,
        "High": 7.5,
        "Medium": 5.0,
        "Low": 2.5,
        "Info": 0.0
    }
    
    total_score = 0.0
    count = 0
    
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Info")
        score = severity_map.get(severity, 0.0)
        total_score += score
        count += 1
    
    return round(total_score / count, 1) if count > 0 else 0.0

def format_vulnerability_for_output(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format vulnerability data for output.
    
    Args:
        vulnerability: Raw vulnerability dictionary
        
    Returns:
        Formatted vulnerability dictionary
    """
    # Ensure all required fields are present
    formatted = {
        "id": vulnerability.get("id", "UNKNOWN"),
        "description": vulnerability.get("description", "No description provided"),
        "severity": vulnerability.get("severity", "Info"),
        "component": vulnerability.get("component", "Unknown"),
        "fix_available": vulnerability.get("fix_available", False)
    }
    
    # Add optional fields if present
    if "fix" in vulnerability:
        formatted["fix"] = vulnerability["fix"]
    
    if "cvss" in vulnerability:
        formatted["cvss"] = vulnerability["cvss"]
    
    if "references" in vulnerability:
        formatted["references"] = vulnerability["references"]
    
    return formatted

def get_os_package_manager() -> Optional[str]:
    """
    Detect the operating system's package manager.
    
    Returns:
        Name of the package manager or None if not detected
    """
    if platform.system() == "Windows":
        # Check for Chocolatey
        if os.path.exists(os.path.expandvars("%ProgramData%\\chocolatey\\bin\\choco.exe")):
            return "chocolatey"
        return None
    
    # Linux package managers
    package_managers = {
        "/usr/bin/apt": "apt",
        "/usr/bin/apt-get": "apt-get",
        "/usr/bin/yum": "yum",
        "/usr/bin/dnf": "dnf",
        "/usr/bin/pacman": "pacman",
        "/usr/bin/zypper": "zypper"
    }
    
    for path, name in package_managers.items():
        if os.path.exists(path):
            return name
    
    return None

def is_admin() -> bool:
    """
    Check if the script is running with administrative privileges.
    
    Returns:
        True if running as admin/root, False otherwise
    """
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def safe_json_serialize(obj: Any) -> Any:
    """
    Safely serialize objects to JSON.
    
    Args:
        obj: Object to serialize
        
    Returns:
        JSON-serializable object
    """
    if isinstance(obj, dict):
        return {k: safe_json_serialize(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [safe_json_serialize(item) for item in obj]
    elif isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    else:
        return str(obj)

def merge_vulnerabilities(vuln_list1: List[Dict[str, Any]], 
                         vuln_list2: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Merge two vulnerability lists, removing duplicates.
    
    Args:
        vuln_list1: First list of vulnerabilities
        vuln_list2: Second list of vulnerabilities
        
    Returns:
        Merged list with duplicates removed
    """
    # Create a set of vulnerability IDs from the first list
    vuln_ids = {vuln.get("id") for vuln in vuln_list1 if "id" in vuln}
    
    # Add vulnerabilities from the second list if they're not duplicates
    merged_list = vuln_list1.copy()
    for vuln in vuln_list2:
        if "id" in vuln and vuln["id"] not in vuln_ids:
            merged_list.append(vuln)
            vuln_ids.add(vuln["id"])
    
    return merged_list

def generate_html_report(json_report_path: str, html_output_path: str) -> bool:
    """
    Generate an HTML report from the JSON vulnerability report.
    
    Args:
        json_report_path: Path to the JSON report file
        html_output_path: Path to save the HTML report
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Read JSON report
        with open(json_report_path, 'r') as f:
            report = json.load(f)
        
        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
                h1, h2, h3 {{ color: #333; }}
                .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .vulnerability {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 5px; }}
                .Critical {{ border-left: 5px solid #d9534f; }}
                .High {{ border-left: 5px solid #f0ad4e; }}
                .Medium {{ border-left: 5px solid #5bc0de; }}
                .Low {{ border-left: 5px solid #5cb85c; }}
                .Info {{ border-left: 5px solid #777; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Vulnerability Scan Report</h1>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Scan Time:</strong> {report['metadata']['scan_time']}</p>
                <p><strong>Operating System:</strong> {report['metadata']['os']}</p>
                <p><strong>Hostname:</strong> {report['metadata']['hostname']}</p>
                <p><strong>Total Vulnerabilities:</strong> {report['summary']['total_vulnerabilities']}</p>
                <p><strong>Average CVSS Score:</strong> {report['summary']['average_cvss']}</p>
                
                <h3>Vulnerability Counts by Severity</h3>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                    </tr>
        """
        
        # Add severity counts
        for severity, count in report['summary']['severity_counts'].items():
            html_content += f"""
                    <tr>
                        <td>{severity}</td>
                        <td>{count}</td>
                    </tr>
            """
        
        html_content += """
                </table>
            </div>
            
            <h2>Vulnerabilities</h2>
        """
        
        # Sort vulnerabilities by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_vulns = sorted(
            report['vulnerabilities'], 
            key=lambda x: severity_order.get(x.get('severity', 'Info'), 999)
        )
        
        # Add vulnerabilities
        for vuln in sorted_vulns:
            severity = vuln.get('severity', 'Info')
            html_content += f"""
            <div class="vulnerability {severity}">
                <h3>{vuln['id']}</h3>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Severity:</strong> {severity}</p>
                <p><strong>Component:</strong> {vuln['component']}</p>
            """
            
            if 'fix' in vuln and vuln['fix_available']:
                html_content += f"""
                <p><strong>Fix:</strong> {vuln['fix']}</p>
                """
            
            if 'references' in vuln:
                html_content += """
                <p><strong>References:</strong></p>
                <ul>
                """
                for ref in vuln['references']:
                    html_content += f"""
                    <li><a href="{ref}" target="_blank">{ref}</a></li>
                    """
                html_content += """
                </ul>
                """
            
            html_content += """
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        # Write HTML report
        with open(html_output_path, 'w') as f:
            f.write(html_content)
        
        return True
    except Exception as e:
        logging.error(f"Error generating HTML report: {str(e)}")
        return False

def generate_csv_report(json_report_path: str, csv_output_path: str) -> bool:
    """
    Generate a CSV report from the JSON vulnerability report.
    
    Args:
        json_report_path: Path to the JSON report file
        csv_output_path: Path to save the CSV report
        
    Returns:
        True if successful, False otherwise
    """
    try:
        import csv
        
        # Read JSON report
        with open(json_report_path, 'r') as f:
            report = json.load(f)
        
        # Write CSV report
        with open(csv_output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['ID', 'Description', 'Severity', 'Component', 'Fix Available', 'Fix'])
            
            # Write vulnerabilities
            for vuln in report['vulnerabilities']:
                writer.writerow([
                    vuln.get('id', 'UNKNOWN'),
                    vuln.get('description', 'No description'),
                    vuln.get('severity', 'Info'),
                    vuln.get('component', 'Unknown'),
                    'Yes' if vuln.get('fix_available', False) else 'No',
                    vuln.get('fix', 'N/A')
                ])
        
        return True
    except Exception as e:
        logging.error(f"Error generating CSV report: {str(e)}")
        return False
