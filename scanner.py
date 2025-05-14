#!/usr/bin/env python3
"""
Vulnerability Scanner - A cross-platform tool for detecting vulnerabilities in systems.

This scanner detects OS-level, software, and configuration vulnerabilities on
both Windows and Linux systems. Results are output in JSON format.
"""

import os
import sys
import json
import platform
import argparse
import logging
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Any, Optional

# Import scanner modules
from os_scanner import OSScanner
from package_scanner import PackageScanner
from network_scanner import NetworkScanner
from permission_scanner import PermissionScanner
from config_scanner import ConfigScanner
from utils import setup_logging, get_severity_score, generate_html_report, generate_csv_report

class VulnerabilityScanner:
    """Main vulnerability scanner class that orchestrates the scanning process."""

    def __init__(self, output_file: str = "vulnerability_report.json",
                 log_file: str = "scanner.log",
                 threads: int = 4,
                 verbose: bool = False):
        """
        Initialize the vulnerability scanner.

        Args:
            output_file: Path to the output JSON file
            log_file: Path to the log file
            threads: Number of threads to use for scanning
            verbose: Whether to print verbose output
        """
        self.output_file = output_file
        self.log_file = log_file
        self.threads = threads
        self.verbose = verbose

        # Setup logging
        self.logger = setup_logging(log_file, verbose)

        # Detect operating system
        self.os_info = self._detect_os()
        self.logger.info(f"Detected OS: {self.os_info['os_name']} {self.os_info['os_version']}")

        # Initialize scanner modules
        self.os_scanner = OSScanner(self.os_info)
        self.package_scanner = PackageScanner(self.os_info)
        self.network_scanner = NetworkScanner()
        self.permission_scanner = PermissionScanner(self.os_info)
        self.config_scanner = ConfigScanner(self.os_info)

        # Results storage
        self.vulnerabilities = []
        self.scan_metadata = {}

    def _detect_os(self) -> Dict[str, str]:
        """
        Detect the operating system and version.

        Returns:
            Dict containing OS information
        """
        os_info = {
            "os_name": platform.system(),
            "os_version": platform.version(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "platform": sys.platform
        }

        # Add more detailed information based on the OS
        if os_info["os_name"] == "Windows":
            os_info["os_distribution"] = platform.win32_ver()[0]
        elif os_info["os_name"] == "Linux":
            try:
                import distro
                os_info["os_distribution"] = distro.name(pretty=True)
                os_info["os_distribution_version"] = distro.version()
            except ImportError:
                self.logger.warning("Python 'distro' package not found. Limited Linux distribution info available.")
                os_info["os_distribution"] = "Unknown"

        return os_info

    def run_scan(self) -> None:
        """Run all vulnerability scans and collect results."""
        self.logger.info("Starting vulnerability scan...")
        start_time = datetime.now()

        # Create scan metadata
        self.scan_metadata = {
            "scan_time": start_time.isoformat(),
            "scanner_version": "1.0.0",
            "os": f"{self.os_info['os_name']} {self.os_info['os_version']}",
            "hostname": platform.node()
        }

        # Run scans in parallel using ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            scan_functions = [
                (self._run_os_scan, "OS vulnerabilities"),
                (self._run_package_scan, "Package vulnerabilities"),
                (self._run_network_scan, "Network vulnerabilities"),
                (self._run_permission_scan, "Permission vulnerabilities"),
                (self._run_config_scan, "Configuration vulnerabilities")
            ]

            futures = {executor.submit(func): name for func, name in scan_functions}

            for future in concurrent.futures.as_completed(futures):
                scan_name = futures[future]
                try:
                    scan_results = future.result()
                    self.vulnerabilities.extend(scan_results)
                    self.logger.info(f"Completed {scan_name} scan. Found {len(scan_results)} vulnerabilities.")
                except Exception as e:
                    self.logger.error(f"Error in {scan_name} scan: {str(e)}")

        # Calculate scan duration
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        self.scan_metadata["scan_duration_seconds"] = duration
        self.scan_metadata["vulnerabilities_found"] = len(self.vulnerabilities)

        self.logger.info(f"Scan completed in {duration:.2f} seconds. Found {len(self.vulnerabilities)} vulnerabilities.")

    def _run_os_scan(self) -> List[Dict[str, Any]]:
        """Run OS vulnerability scan."""
        self.logger.info("Scanning for OS vulnerabilities...")
        return self.os_scanner.scan()

    def _run_package_scan(self) -> List[Dict[str, Any]]:
        """Run package vulnerability scan."""
        self.logger.info("Scanning for package vulnerabilities...")
        return self.package_scanner.scan()

    def _run_network_scan(self) -> List[Dict[str, Any]]:
        """Run network vulnerability scan."""
        self.logger.info("Scanning for network vulnerabilities...")
        return self.network_scanner.scan()

    def _run_permission_scan(self) -> List[Dict[str, Any]]:
        """Run permission vulnerability scan."""
        self.logger.info("Scanning for permission vulnerabilities...")
        return self.permission_scanner.scan()

    def _run_config_scan(self) -> List[Dict[str, Any]]:
        """Run configuration vulnerability scan."""
        self.logger.info("Scanning for configuration vulnerabilities...")
        return self.config_scanner.scan()

    def save_results(self) -> None:
        """Save scan results to JSON file."""
        # Calculate severity statistics
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "Info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Create final report structure
        report = {
            "metadata": self.scan_metadata,
            "summary": {
                "total_vulnerabilities": len(self.vulnerabilities),
                "severity_counts": severity_counts,
                "average_cvss": get_severity_score(self.vulnerabilities)
            },
            "vulnerabilities": self.vulnerabilities
        }

        # Save to file
        try:
            with open(self.output_file, 'w') as f:
                json.dump(report, f, indent=2)
            self.logger.info(f"Results saved to {self.output_file}")
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            raise

def main():
    """Main entry point for the vulnerability scanner."""
    parser = argparse.ArgumentParser(description="Cross-platform vulnerability scanner")
    parser.add_argument("-o", "--output", default="vulnerability_report.json",
                        help="Output file path (default: vulnerability_report.json)")
    parser.add_argument("-l", "--log", default="scanner.log",
                        help="Log file path (default: scanner.log)")
    parser.add_argument("-t", "--threads", type=int, default=4,
                        help="Number of threads to use (default: 4)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--no-html", action="store_true",
                        help="Disable HTML report generation")
    parser.add_argument("--no-csv", action="store_true",
                        help="Disable CSV report generation")

    args = parser.parse_args()

    try:
        # Run the vulnerability scan
        scanner = VulnerabilityScanner(
            output_file=args.output,
            log_file=args.log,
            threads=args.threads,
            verbose=args.verbose
        )
        scanner.run_scan()
        scanner.save_results()
        print(f"Scan completed. Results saved to {args.output}")

        # Generate additional report formats
        output_base = os.path.splitext(args.output)[0]

        # Generate HTML report
        if not args.no_html:
            html_output = f"{output_base}.html"
            if generate_html_report(args.output, html_output):
                print(f"HTML report saved to {html_output}")
            else:
                print("Failed to generate HTML report")

        # Generate CSV report
        if not args.no_csv:
            csv_output = f"{output_base}.csv"
            if generate_csv_report(args.output, csv_output):
                print(f"CSV report saved to {csv_output}")
            else:
                print("Failed to generate CSV report")

        return 0
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 1
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
