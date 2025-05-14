#!/usr/bin/env python3
"""
Package Scanner Module - Detects vulnerabilities in installed packages.

This module scans for vulnerabilities in installed software packages by
comparing them against known CVE databases.
"""

import os
import re
import json
import subprocess
import logging
import platform
import requests
from typing import Dict, List, Any, Optional, Tuple

class PackageScanner:
    """Scanner for package vulnerabilities."""
    
    def __init__(self, os_info: Dict[str, str]):
        """
        Initialize the package scanner.
        
        Args:
            os_info: Dictionary containing OS information
        """
        self.os_info = os_info
        self.logger = logging.getLogger("vulnerability_scanner")
        
        # Define OS-specific commands for package listing
        self.commands = self._get_package_commands()
        
        # API keys (in a real application, these would be securely stored)
        self.vulners_api_key = os.environ.get("VULNERS_API_KEY", "")
    
    def _get_package_commands(self) -> Dict[str, str]:
        """
        Get OS-specific commands for package listing.
        
        Returns:
            Dictionary of commands for the current OS
        """
        if self.os_info["os_name"] == "Windows":
            return {
                "installed_packages": "wmic product get name,version",
                "chocolatey_packages": "choco list --local-only",
                "windows_features": "dism /online /get-features"
            }
        elif self.os_info["os_name"] == "Linux":
            # Determine package manager
            if os.path.exists("/usr/bin/dpkg"):  # Debian/Ubuntu
                return {
                    "installed_packages": "dpkg -l",
                    "package_updates": "apt list --upgradable 2>/dev/null"
                }
            elif os.path.exists("/usr/bin/rpm"):  # RHEL/CentOS/Fedora
                return {
                    "installed_packages": "rpm -qa",
                    "package_updates": "yum check-update -q"
                }
            else:
                self.logger.warning("Unknown Linux package manager")
                return {
                    "installed_packages": "ls -la /usr/bin"
                }
        else:
            self.logger.warning(f"Unsupported OS: {self.os_info['os_name']}")
            return {}
    
    def _run_command(self, command: str) -> Tuple[int, str, str]:
        """
        Run a shell command and return its output.
        
        Args:
            command: Command to run
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                text=True
            )
            stdout, stderr = process.communicate()
            return process.returncode, stdout, stderr
        except Exception as e:
            self.logger.error(f"Error running command '{command}': {str(e)}")
            return -1, "", str(e)
    
    def _get_windows_packages(self) -> List[Dict[str, str]]:
        """
        Get list of installed packages on Windows.
        
        Returns:
            List of dictionaries with package name and version
        """
        packages = []
        
        # Get installed applications
        returncode, stdout, stderr = self._run_command(self.commands["installed_packages"])
        if returncode == 0:
            lines = stdout.strip().split('\n')[1:]  # Skip header
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 2:
                    name = ' '.join(parts[:-1])
                    version = parts[-1]
                    packages.append({
                        "name": name,
                        "version": version,
                        "source": "wmic"
                    })
        
        # Get Chocolatey packages if available
        try:
            returncode, stdout, stderr = self._run_command(self.commands["chocolatey_packages"])
            if returncode == 0:
                lines = stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    match = re.match(r'(.+?)\s+(.+)', line.strip())
                    if match:
                        name, version = match.groups()
                        packages.append({
                            "name": name,
                            "version": version,
                            "source": "chocolatey"
                        })
        except Exception as e:
            self.logger.debug(f"Chocolatey not available: {str(e)}")
        
        return packages
    
    def _get_linux_packages(self) -> List[Dict[str, str]]:
        """
        Get list of installed packages on Linux.
        
        Returns:
            List of dictionaries with package name and version
        """
        packages = []
        
        # Get installed packages
        returncode, stdout, stderr = self._run_command(self.commands["installed_packages"])
        if returncode == 0:
            if "dpkg" in self.commands["installed_packages"]:  # Debian/Ubuntu
                lines = stdout.strip().split('\n')[5:]  # Skip headers
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        packages.append({
                            "name": parts[1],
                            "version": parts[2],
                            "source": "dpkg"
                        })
            elif "rpm" in self.commands["installed_packages"]:  # RHEL/CentOS/Fedora
                lines = stdout.strip().split('\n')
                for line in lines:
                    # Format is typically name-version-release.arch
                    match = re.match(r'(.+)-([^-]+)-([^-]+)\.([^.]+)', line.strip())
                    if match:
                        name, version, release, arch = match.groups()
                        packages.append({
                            "name": name,
                            "version": f"{version}-{release}",
                            "source": "rpm"
                        })
        
        return packages
    
    def _check_vulners_database(self, packages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Check packages against Vulners database.
        
        Args:
            packages: List of package dictionaries
            
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        if not self.vulners_api_key:
            self.logger.warning("No Vulners API key provided. Skipping online vulnerability check.")
            return vulnerabilities
        
        try:
            # Group packages by source for efficient API calls
            package_groups = {}
            for package in packages:
                source = package["source"]
                if source not in package_groups:
                    package_groups[source] = []
                package_groups[source].append(f"{package['name']}-{package['version']}")
            
            # Check each group against Vulners API
            for source, package_list in package_groups.items():
                # Map source to Vulners OS
                os_mapping = {
                    "dpkg": "debian",
                    "rpm": "centos",
                    "wmic": "windows",
                    "chocolatey": "windows"
                }
                
                vulners_os = os_mapping.get(source, "generic")
                
                # Prepare API request
                url = "https://vulners.com/api/v3/audit/audit/"
                data = {
                    "os": vulners_os,
                    "version": self.os_info.get("os_version", ""),
                    "package": package_list
                }
                
                headers = {
                    "Content-Type": "application/json",
                    "API-Key": self.vulners_api_key
                }
                
                # Make API request (commented out to avoid actual API calls in this example)
                # response = requests.post(url, headers=headers, json=data)
                # if response.status_code == 200:
                #     result = response.json()
                #     if result.get("result") == "OK":
                #         for package, vulns in result.get("data", {}).get("packages", {}).items():
                #             for vuln in vulns:
                #                 vulnerabilities.append({
                #                     "id": vuln.get("id", "Unknown"),
                #                     "description": vuln.get("title", "Unknown vulnerability"),
                #                     "severity": self._map_cvss_to_severity(vuln.get("cvss", {}).get("score", 0)),
                #                     "component": package,
                #                     "fix_available": True,
                #                     "fix": f"Update {package} to a patched version"
                #                 })
                
                # Simulate some vulnerabilities for demonstration
                if source == "dpkg":
                    for package in package_list[:3]:  # Just check first 3 packages
                        if "openssl" in package.lower():
                            vulnerabilities.append({
                                "id": "CVE-2023-0286",
                                "description": "OpenSSL X.400 address type confusion in X.509 GeneralName",
                                "severity": "High",
                                "component": package,
                                "fix_available": True,
                                "fix": f"Update {package} to a patched version"
                            })
                        elif "apache" in package.lower():
                            vulnerabilities.append({
                                "id": "CVE-2022-31813",
                                "description": "HTTP Request Smuggling in Apache HTTP Server",
                                "severity": "Medium",
                                "component": package,
                                "fix_available": True,
                                "fix": f"Update {package} to a patched version"
                            })
                elif source == "wmic":
                    for package in package_list[:3]:  # Just check first 3 packages
                        if "adobe" in package.lower():
                            vulnerabilities.append({
                                "id": "CVE-2023-26369",
                                "description": "Adobe Acrobat Reader DC security bypass vulnerability",
                                "severity": "Critical",
                                "component": package,
                                "fix_available": True,
                                "fix": f"Update {package} to the latest version"
                            })
        
        except Exception as e:
            self.logger.error(f"Error checking Vulners database: {str(e)}")
        
        return vulnerabilities
    
    def _map_cvss_to_severity(self, cvss_score: float) -> str:
        """
        Map CVSS score to severity level.
        
        Args:
            cvss_score: CVSS score (0.0-10.0)
            
        Returns:
            Severity level (Critical, High, Medium, Low)
        """
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        else:
            return "Low"
    
    def _check_local_vulnerabilities(self, packages: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Check packages against local vulnerability database.
        
        Args:
            packages: List of package dictionaries
            
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # This is a simplified example - in a real scanner, you would have a local
        # database of vulnerabilities to check against
        
        # Check for some common vulnerable packages and versions
        vulnerable_packages = {
            "openssl": {
                "1.0.1": {
                    "id": "CVE-2014-0160",
                    "description": "Heartbleed vulnerability in OpenSSL",
                    "severity": "Critical"
                },
                "1.0.2": {
                    "id": "CVE-2016-0800",
                    "description": "DROWN vulnerability in OpenSSL",
                    "severity": "High"
                }
            },
            "apache": {
                "2.4.49": {
                    "id": "CVE-2021-41773",
                    "description": "Path traversal vulnerability in Apache HTTP Server",
                    "severity": "Critical"
                }
            },
            "log4j": {
                "2.0": {
                    "id": "CVE-2021-44228",
                    "description": "Log4Shell vulnerability in Log4j",
                    "severity": "Critical"
                }
            }
        }
        
        for package in packages:
            name = package["name"].lower()
            version = package["version"]
            
            # Check if package is in our vulnerable packages list
            for vuln_name, vuln_versions in vulnerable_packages.items():
                if vuln_name in name:
                    for vuln_version, vuln_info in vuln_versions.items():
                        if version.startswith(vuln_version):
                            vulnerabilities.append({
                                "id": vuln_info["id"],
                                "description": vuln_info["description"],
                                "severity": vuln_info["severity"],
                                "component": f"{name}-{version}",
                                "fix_available": True,
                                "fix": f"Update {name} to a patched version"
                            })
        
        return vulnerabilities
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan for package vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        self.logger.info(f"Scanning for package vulnerabilities on {self.os_info['os_name']}...")
        
        # Get installed packages
        if self.os_info["os_name"] == "Windows":
            packages = self._get_windows_packages()
        elif self.os_info["os_name"] == "Linux":
            packages = self._get_linux_packages()
        else:
            self.logger.warning(f"Unsupported OS: {self.os_info['os_name']}")
            return []
        
        self.logger.info(f"Found {len(packages)} installed packages")
        
        # Check for vulnerabilities
        local_vulnerabilities = self._check_local_vulnerabilities(packages)
        online_vulnerabilities = self._check_vulners_database(packages)
        
        # Combine results
        all_vulnerabilities = local_vulnerabilities + online_vulnerabilities
        
        self.logger.info(f"Found {len(all_vulnerabilities)} package vulnerabilities")
        return all_vulnerabilities
