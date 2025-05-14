#!/usr/bin/env python3
"""
OS Scanner Module - Detects operating system vulnerabilities.

This module scans for OS-level vulnerabilities including kernel version,
missing patches, and other OS-specific security issues.
"""

import os
import re
import subprocess
import logging
import platform
from typing import Dict, List, Any, Optional, Tuple

class OSScanner:
    """Scanner for operating system vulnerabilities."""
    
    def __init__(self, os_info: Dict[str, str]):
        """
        Initialize the OS scanner.
        
        Args:
            os_info: Dictionary containing OS information
        """
        self.os_info = os_info
        self.logger = logging.getLogger("vulnerability_scanner")
        
        # Define OS-specific commands
        self.commands = self._get_os_commands()
    
    def _get_os_commands(self) -> Dict[str, str]:
        """
        Get OS-specific commands for vulnerability scanning.
        
        Returns:
            Dictionary of commands for the current OS
        """
        if self.os_info["os_name"] == "Windows":
            return {
                "kernel_version": "systeminfo | findstr /B /C:\"OS Version\"",
                "hotfixes": "wmic qfe list brief",
                "security_center": "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState",
                "services": "sc query type= service state= all",
                "startup": "wmic startup list full"
            }
        elif self.os_info["os_name"] == "Linux":
            return {
                "kernel_version": "uname -r",
                "os_release": "cat /etc/os-release",
                "security_updates": "apt list --upgradable 2>/dev/null || yum check-update -q",
                "services": "systemctl list-units --type=service --all || service --status-all",
                "open_ports": "ss -tuln || netstat -tuln"
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
    
    def _check_windows_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Check for Windows-specific vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # Check Windows version and known vulnerabilities
        try:
            returncode, stdout, stderr = self._run_command(self.commands["kernel_version"])
            if returncode == 0:
                # Extract Windows version
                match = re.search(r"OS Version:\s+(.*)", stdout)
                if match:
                    windows_version = match.group(1)
                    
                    # Check for end-of-life Windows versions
                    eol_versions = {
                        "5.1": "Windows XP",
                        "6.0": "Windows Vista",
                        "6.1": "Windows 7",
                        "6.2": "Windows 8",
                        "10.0.10240": "Windows 10 1507",
                        "10.0.10586": "Windows 10 1511",
                        "10.0.14393": "Windows 10 1607",
                        "10.0.15063": "Windows 10 1703",
                        "10.0.16299": "Windows 10 1709",
                        "10.0.17134": "Windows 10 1803",
                        "10.0.17763": "Windows 10 1809",
                        "10.0.18362": "Windows 10 1903",
                        "10.0.18363": "Windows 10 1909"
                    }
                    
                    for version, name in eol_versions.items():
                        if version in windows_version:
                            vulnerabilities.append({
                                "id": f"OS-EOL-{version}",
                                "description": f"End-of-life Windows version: {name}",
                                "severity": "High",
                                "component": "Operating System",
                                "fix_available": True,
                                "fix": "Upgrade to a supported Windows version"
                            })
            
            # Check for missing security updates
            returncode, stdout, stderr = self._run_command(self.commands["hotfixes"])
            if returncode == 0:
                # Check if important security updates are missing
                # This is a simplified check - in a real scanner, you would compare against a database
                # of required security updates for the specific Windows version
                if "KB4569073" not in stdout:  # Example security update
                    vulnerabilities.append({
                        "id": "OS-MISSING-UPDATE-KB4569073",
                        "description": "Missing critical security update KB4569073",
                        "severity": "High",
                        "component": "Operating System",
                        "fix_available": True,
                        "fix": "Install Windows Update KB4569073"
                    })
            
            # Check antivirus status
            returncode, stdout, stderr = self._run_command(self.commands["security_center"])
            if returncode == 0:
                if not stdout.strip() or "displayName" not in stdout:
                    vulnerabilities.append({
                        "id": "OS-NO-AV",
                        "description": "No antivirus software detected",
                        "severity": "Medium",
                        "component": "Security Software",
                        "fix_available": True,
                        "fix": "Install and enable antivirus software"
                    })
        
        except Exception as e:
            self.logger.error(f"Error checking Windows vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _check_linux_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Check for Linux-specific vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        try:
            # Check kernel version
            returncode, stdout, stderr = self._run_command(self.commands["kernel_version"])
            if returncode == 0:
                kernel_version = stdout.strip()
                
                # Check for old kernel versions (example thresholds)
                if kernel_version.startswith("2.") or kernel_version.startswith("3."):
                    vulnerabilities.append({
                        "id": "OS-OLD-KERNEL",
                        "description": f"Old Linux kernel version: {kernel_version}",
                        "severity": "High",
                        "component": "Operating System",
                        "fix_available": True,
                        "fix": "Update the kernel to a newer version"
                    })
                
                # Check for specific vulnerable kernel versions
                vulnerable_kernels = ["4.4.0-21", "4.8.0-34", "5.4.0-26"]
                for v_kernel in vulnerable_kernels:
                    if kernel_version.startswith(v_kernel):
                        vulnerabilities.append({
                            "id": f"OS-VULN-KERNEL-{v_kernel}",
                            "description": f"Known vulnerable kernel version: {kernel_version}",
                            "severity": "Critical",
                            "component": "Operating System",
                            "fix_available": True,
                            "fix": "Update the kernel to a patched version"
                        })
            
            # Check for available security updates
            returncode, stdout, stderr = self._run_command(self.commands["security_updates"])
            if returncode == 0 and stdout.strip():
                # Count security updates
                security_updates_count = len(re.findall(r"security", stdout, re.IGNORECASE))
                
                if security_updates_count > 0:
                    vulnerabilities.append({
                        "id": "OS-MISSING-SECURITY-UPDATES",
                        "description": f"Missing security updates ({security_updates_count} available)",
                        "severity": "Medium",
                        "component": "Operating System",
                        "fix_available": True,
                        "fix": "Run system update (apt upgrade or yum update)"
                    })
            
            # Check for SSH configuration issues
            if os.path.exists("/etc/ssh/sshd_config"):
                with open("/etc/ssh/sshd_config", "r") as f:
                    sshd_config = f.read()
                    
                    # Check for root login
                    if "PermitRootLogin yes" in sshd_config:
                        vulnerabilities.append({
                            "id": "OS-SSH-ROOT-LOGIN",
                            "description": "SSH root login is enabled",
                            "severity": "High",
                            "component": "SSH Configuration",
                            "fix_available": True,
                            "fix": "Disable root login in /etc/ssh/sshd_config"
                        })
                    
                    # Check for password authentication
                    if "PasswordAuthentication yes" in sshd_config:
                        vulnerabilities.append({
                            "id": "OS-SSH-PASSWORD-AUTH",
                            "description": "SSH password authentication is enabled",
                            "severity": "Medium",
                            "component": "SSH Configuration",
                            "fix_available": True,
                            "fix": "Use key-based authentication instead"
                        })
        
        except Exception as e:
            self.logger.error(f"Error checking Linux vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan for OS vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        self.logger.info(f"Scanning for {self.os_info['os_name']} vulnerabilities...")
        
        if self.os_info["os_name"] == "Windows":
            return self._check_windows_vulnerabilities()
        elif self.os_info["os_name"] == "Linux":
            return self._check_linux_vulnerabilities()
        else:
            self.logger.warning(f"Unsupported OS: {self.os_info['os_name']}")
            return []
