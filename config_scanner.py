#!/usr/bin/env python3
"""
Configuration Scanner Module - Detects configuration vulnerabilities.

This module scans for misconfigurations in system and application settings
that could pose security risks.
"""

import os
import re
import subprocess
import logging
import platform
from typing import Dict, List, Any, Optional, Tuple

class ConfigScanner:
    """Scanner for configuration vulnerabilities."""
    
    def __init__(self, os_info: Dict[str, str]):
        """
        Initialize the configuration scanner.
        
        Args:
            os_info: Dictionary containing OS information
        """
        self.os_info = os_info
        self.logger = logging.getLogger("vulnerability_scanner")
        
        # Define OS-specific commands
        self.commands = self._get_config_commands()
        
        # Define common configuration files to check
        self.config_files = self._get_config_files()
    
    def _get_config_commands(self) -> Dict[str, str]:
        """
        Get OS-specific commands for configuration scanning.
        
        Returns:
            Dictionary of commands for the current OS
        """
        if self.os_info["os_name"] == "Windows":
            return {
                "security_policy": "secedit /export /cfg %temp%\\secpol.cfg",
                "audit_policy": "auditpol /get /category:*",
                "services": "sc query type= service state= all",
                "registry_autorun": "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "registry_winlogon": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\"",
                "antivirus": "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName,productState"
            }
        else:  # Linux
            return {
                "sysctl": "sysctl -a 2>/dev/null",
                "services": "systemctl list-units --type=service --all || service --status-all",
                "ssh_config": "cat /etc/ssh/sshd_config 2>/dev/null",
                "pam_config": "cat /etc/pam.d/common-password 2>/dev/null || cat /etc/pam.d/system-auth 2>/dev/null",
                "cron_jobs": "for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done",
                "antivirus": "ps aux | grep -i 'clam\\|av\\|antivirus'"
            }
    
    def _get_config_files(self) -> Dict[str, Dict[str, Any]]:
        """
        Get list of configuration files to check based on OS.
        
        Returns:
            Dictionary of configuration files with check parameters
        """
        if self.os_info["os_name"] == "Windows":
            return {
                "%WINDIR%\\System32\\drivers\\etc\\hosts": {
                    "check_type": "file_permissions",
                    "severity": "Medium"
                },
                "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup": {
                    "check_type": "directory_contents",
                    "severity": "Medium"
                }
            }
        else:  # Linux
            return {
                "/etc/passwd": {
                    "check_type": "file_permissions",
                    "severity": "High"
                },
                "/etc/shadow": {
                    "check_type": "file_permissions",
                    "severity": "Critical"
                },
                "/etc/ssh/sshd_config": {
                    "check_type": "content",
                    "patterns": {
                        "PermitRootLogin\\s+yes": "SSH root login is enabled",
                        "PasswordAuthentication\\s+yes": "SSH password authentication is enabled",
                        "X11Forwarding\\s+yes": "SSH X11 forwarding is enabled"
                    },
                    "severity": "Medium"
                },
                "/etc/sudoers": {
                    "check_type": "content",
                    "patterns": {
                        "NOPASSWD": "Sudo without password is configured",
                        "ALL\\s*=\\s*\\(ALL\\)\\s*ALL": "User has full sudo privileges"
                    },
                    "severity": "Medium"
                }
            }
    
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
    
    def _check_windows_config(self) -> List[Dict[str, Any]]:
        """
        Check for Windows-specific configuration vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # Check Windows security policy
        returncode, stdout, stderr = self._run_command(self.commands["security_policy"])
        if returncode == 0:
            # Check security policy file
            secpol_path = os.path.expandvars("%temp%\\secpol.cfg")
            if os.path.exists(secpol_path):
                try:
                    with open(secpol_path, "r") as f:
                        secpol_content = f.read()
                        
                        # Check password complexity
                        if "PasswordComplexity = 0" in secpol_content:
                            vulnerabilities.append({
                                "id": "CONFIG-NO-PASSWORD-COMPLEXITY",
                                "description": "Password complexity is not enabled",
                                "severity": "Medium",
                                "component": "Security Policy",
                                "fix_available": True,
                                "fix": "Enable password complexity in security policy"
                            })
                        
                        # Check minimum password length
                        match = re.search(r"MinimumPasswordLength\s*=\s*(\d+)", secpol_content)
                        if match and int(match.group(1)) < 8:
                            vulnerabilities.append({
                                "id": "CONFIG-SHORT-PASSWORD",
                                "description": f"Minimum password length is only {match.group(1)} characters",
                                "severity": "Medium",
                                "component": "Security Policy",
                                "fix_available": True,
                                "fix": "Increase minimum password length to at least 8 characters"
                            })
                        
                        # Check account lockout threshold
                        match = re.search(r"LockoutBadCount\s*=\s*(\d+)", secpol_content)
                        if not match or int(match.group(1)) == 0:
                            vulnerabilities.append({
                                "id": "CONFIG-NO-ACCOUNT-LOCKOUT",
                                "description": "Account lockout policy is not enabled",
                                "severity": "Medium",
                                "component": "Security Policy",
                                "fix_available": True,
                                "fix": "Enable account lockout policy"
                            })
                except Exception as e:
                    self.logger.error(f"Error reading security policy file: {str(e)}")
        
        # Check audit policy
        returncode, stdout, stderr = self._run_command(self.commands["audit_policy"])
        if returncode == 0:
            # Check if important audit policies are enabled
            important_audits = [
                "Account Logon", "Account Management", "Logon", 
                "Object Access", "Privilege Use", "System"
            ]
            
            for audit in important_audits:
                if f"{audit}  No Auditing" in stdout:
                    vulnerabilities.append({
                        "id": f"CONFIG-NO-AUDIT-{audit.replace(' ', '-')}",
                        "description": f"Auditing is not enabled for {audit}",
                        "severity": "Low",
                        "component": "Audit Policy",
                        "fix_available": True,
                        "fix": f"Enable auditing for {audit}"
                    })
        
        # Check antivirus status
        returncode, stdout, stderr = self._run_command(self.commands["antivirus"])
        if returncode == 0:
            if not stdout.strip() or "displayName" not in stdout:
                vulnerabilities.append({
                    "id": "CONFIG-NO-ANTIVIRUS",
                    "description": "No antivirus software detected",
                    "severity": "High",
                    "component": "Security Software",
                    "fix_available": True,
                    "fix": "Install and enable antivirus software"
                })
            else:
                # Check if antivirus is disabled or out of date
                # productState is a bit field, 16 means "disabled"
                if "16" in stdout:
                    vulnerabilities.append({
                        "id": "CONFIG-DISABLED-ANTIVIRUS",
                        "description": "Antivirus software is disabled",
                        "severity": "High",
                        "component": "Security Software",
                        "fix_available": True,
                        "fix": "Enable antivirus software"
                    })
        
        # Check autorun entries
        returncode, stdout, stderr = self._run_command(self.commands["registry_autorun"])
        if returncode == 0:
            # This is a simplified check - in a real scanner, you would check each autorun entry
            # against a database of known malicious or suspicious entries
            autorun_count = len([line for line in stdout.strip().split('\n') if line.strip() and "REG_" in line])
            if autorun_count > 10:  # Arbitrary threshold
                vulnerabilities.append({
                    "id": "CONFIG-EXCESS-AUTORUNS",
                    "description": f"Excessive number of autorun entries: {autorun_count}",
                    "severity": "Low",
                    "component": "Registry",
                    "fix_available": True,
                    "fix": "Review and clean up autorun entries"
                })
        
        return vulnerabilities
    
    def _check_linux_config(self) -> List[Dict[str, Any]]:
        """
        Check for Linux-specific configuration vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # Check sysctl settings
        returncode, stdout, stderr = self._run_command(self.commands["sysctl"])
        if returncode == 0:
            # Check for common security settings
            sysctl_checks = {
                "net.ipv4.conf.all.accept_redirects": {"value": "0", "description": "ICMP redirects are accepted"},
                "net.ipv4.conf.all.send_redirects": {"value": "0", "description": "ICMP redirects are sent"},
                "net.ipv4.conf.all.accept_source_route": {"value": "0", "description": "Source routing is accepted"},
                "net.ipv4.tcp_syncookies": {"value": "1", "description": "TCP SYN cookies are not enabled"},
                "kernel.randomize_va_space": {"value": "2", "description": "Address space layout randomization is not fully enabled"}
            }
            
            for setting, check in sysctl_checks.items():
                pattern = f"{setting}\\s*=\\s*(\\d+)"
                match = re.search(pattern, stdout)
                if match and match.group(1) != check["value"]:
                    vulnerabilities.append({
                        "id": f"CONFIG-SYSCTL-{setting.replace('.', '-')}",
                        "description": f"Insecure sysctl setting: {check['description']}",
                        "severity": "Medium",
                        "component": "Kernel Parameters",
                        "fix_available": True,
                        "fix": f"Set {setting}={check['value']} in /etc/sysctl.conf"
                    })
        
        # Check SSH configuration
        returncode, stdout, stderr = self._run_command(self.commands["ssh_config"])
        if returncode == 0:
            # Check for insecure SSH settings
            ssh_checks = {
                "PermitRootLogin\\s+yes": {
                    "description": "SSH root login is enabled",
                    "severity": "High",
                    "fix": "Set PermitRootLogin no in /etc/ssh/sshd_config"
                },
                "PasswordAuthentication\\s+yes": {
                    "description": "SSH password authentication is enabled",
                    "severity": "Medium",
                    "fix": "Use key-based authentication instead"
                },
                "X11Forwarding\\s+yes": {
                    "description": "SSH X11 forwarding is enabled",
                    "severity": "Low",
                    "fix": "Set X11Forwarding no in /etc/ssh/sshd_config"
                },
                "Protocol\\s+1": {
                    "description": "SSH protocol version 1 is enabled",
                    "severity": "High",
                    "fix": "Use SSH protocol version 2 only"
                }
            }
            
            for pattern, check in ssh_checks.items():
                if re.search(pattern, stdout):
                    vulnerabilities.append({
                        "id": f"CONFIG-SSH-{pattern.split()[0]}",
                        "description": check["description"],
                        "severity": check["severity"],
                        "component": "SSH Configuration",
                        "fix_available": True,
                        "fix": check["fix"]
                    })
        
        # Check PAM configuration
        returncode, stdout, stderr = self._run_command(self.commands["pam_config"])
        if returncode == 0:
            # Check for password quality requirements
            if not re.search(r"pam_pwquality.so", stdout) and not re.search(r"pam_cracklib.so", stdout):
                vulnerabilities.append({
                    "id": "CONFIG-PAM-NO-PASSWORD-QUALITY",
                    "description": "No password quality requirements configured",
                    "severity": "Medium",
                    "component": "PAM Configuration",
                    "fix_available": True,
                    "fix": "Configure password quality requirements in PAM"
                })
        
        # Check for antivirus
        returncode, stdout, stderr = self._run_command(self.commands["antivirus"])
        if returncode == 0:
            if not re.search(r"clam|sophos|mcafee|symantec|trend", stdout, re.IGNORECASE):
                vulnerabilities.append({
                    "id": "CONFIG-NO-ANTIVIRUS",
                    "description": "No antivirus software detected",
                    "severity": "Medium",
                    "component": "Security Software",
                    "fix_available": True,
                    "fix": "Install antivirus software (e.g., ClamAV)"
                })
        
        # Check configuration files
        for file_path, check_info in self.config_files.items():
            if os.path.exists(file_path):
                if check_info["check_type"] == "file_permissions":
                    # Check file permissions
                    try:
                        file_stat = os.stat(file_path)
                        mode = file_stat.st_mode
                        
                        # Check if file is world-readable or world-writable
                        if mode & 0o004 or mode & 0o002:
                            vulnerabilities.append({
                                "id": f"CONFIG-FILE-PERMISSIONS-{os.path.basename(file_path)}",
                                "description": f"Insecure permissions on {file_path}",
                                "severity": check_info["severity"],
                                "component": "File Permissions",
                                "fix_available": True,
                                "fix": f"Restrict permissions: chmod 600 {file_path}"
                            })
                    except Exception as e:
                        self.logger.error(f"Error checking file permissions for {file_path}: {str(e)}")
                
                elif check_info["check_type"] == "content":
                    # Check file content
                    try:
                        with open(file_path, "r") as f:
                            content = f.read()
                            
                            for pattern, description in check_info["patterns"].items():
                                if re.search(pattern, content):
                                    vulnerabilities.append({
                                        "id": f"CONFIG-FILE-CONTENT-{pattern.split()[0]}",
                                        "description": f"{description} in {file_path}",
                                        "severity": check_info["severity"],
                                        "component": "Configuration File",
                                        "fix_available": True,
                                        "fix": f"Review and secure configuration in {file_path}"
                                    })
                    except Exception as e:
                        self.logger.error(f"Error checking file content for {file_path}: {str(e)}")
        
        return vulnerabilities
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan for configuration vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        self.logger.info(f"Scanning for configuration vulnerabilities on {self.os_info['os_name']}...")
        
        if self.os_info["os_name"] == "Windows":
            return self._check_windows_config()
        elif self.os_info["os_name"] == "Linux":
            return self._check_linux_config()
        else:
            self.logger.warning(f"Unsupported OS: {self.os_info['os_name']}")
            return []
