#!/usr/bin/env python3
"""
Permission Scanner Module - Detects permission-related vulnerabilities.

This module scans for user and file permission issues that could pose security risks.
"""

import os
import re
import stat
import subprocess
import logging
import platform
from typing import Dict, List, Any, Optional, Tuple

class PermissionScanner:
    """Scanner for permission vulnerabilities."""
    
    def __init__(self, os_info: Dict[str, str]):
        """
        Initialize the permission scanner.
        
        Args:
            os_info: Dictionary containing OS information
        """
        self.os_info = os_info
        self.logger = logging.getLogger("vulnerability_scanner")
        
        # Define OS-specific commands
        self.commands = self._get_permission_commands()
        
        # Define critical directories to check
        self.critical_directories = self._get_critical_directories()
    
    def _get_permission_commands(self) -> Dict[str, str]:
        """
        Get OS-specific commands for permission scanning.
        
        Returns:
            Dictionary of commands for the current OS
        """
        if self.os_info["os_name"] == "Windows":
            return {
                "user_list": "net user",
                "admin_list": "net localgroup Administrators",
                "password_policy": "net accounts",
                "service_permissions": "sc query type= service state= all",
                "scheduled_tasks": "schtasks /query /fo LIST"
            }
        else:  # Linux
            return {
                "user_list": "cat /etc/passwd",
                "sudo_list": "cat /etc/sudoers",
                "suid_files": "find / -perm -4000 -type f -exec ls -la {} \\; 2>/dev/null",
                "world_writable": "find / -perm -2 -type f -not -path \"/proc/*\" -exec ls -la {} \\; 2>/dev/null",
                "no_password_users": "cat /etc/shadow | grep -v ':!:' | grep -v ':\\*:' | grep '::'"
            }
    
    def _get_critical_directories(self) -> List[str]:
        """
        Get list of critical directories to check based on OS.
        
        Returns:
            List of critical directory paths
        """
        if self.os_info["os_name"] == "Windows":
            return [
                "C:\\Windows\\System32",
                "C:\\Windows\\System32\\drivers",
                "C:\\Program Files",
                "C:\\Program Files (x86)",
                "C:\\Windows\\Temp"
            ]
        else:  # Linux
            return [
                "/etc",
                "/bin",
                "/sbin",
                "/usr/bin",
                "/usr/sbin",
                "/var/log",
                "/tmp",
                "/home"
            ]
    
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
    
    def _check_windows_permissions(self) -> List[Dict[str, Any]]:
        """
        Check for Windows-specific permission vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # Check password policy
        returncode, stdout, stderr = self._run_command(self.commands["password_policy"])
        if returncode == 0:
            # Check minimum password length
            match = re.search(r"Minimum password length\s+:\s+(\d+)", stdout)
            if match and int(match.group(1)) < 8:
                vulnerabilities.append({
                    "id": "PERM-WEAK-PASSWORD-POLICY",
                    "description": f"Weak password policy: minimum length is {match.group(1)} (should be at least 8)",
                    "severity": "Medium",
                    "component": "User Permissions",
                    "fix_available": True,
                    "fix": "Increase minimum password length in password policy"
                })
            
            # Check password complexity
            if "Password complexity requirements are not being enforced" in stdout:
                vulnerabilities.append({
                    "id": "PERM-NO-PASSWORD-COMPLEXITY",
                    "description": "Password complexity requirements are not enforced",
                    "severity": "Medium",
                    "component": "User Permissions",
                    "fix_available": True,
                    "fix": "Enable password complexity requirements in password policy"
                })
        
        # Check administrator accounts
        returncode, stdout, stderr = self._run_command(self.commands["admin_list"])
        if returncode == 0:
            admin_count = len([line for line in stdout.strip().split('\n') if line.strip() and not line.startswith('-')])
            if admin_count > 3:  # Arbitrary threshold
                vulnerabilities.append({
                    "id": "PERM-EXCESS-ADMINS",
                    "description": f"Excessive number of administrator accounts: {admin_count}",
                    "severity": "Medium",
                    "component": "User Permissions",
                    "fix_available": True,
                    "fix": "Review and reduce the number of administrator accounts"
                })
            
            # Check for default admin account
            if "Administrator" in stdout:
                vulnerabilities.append({
                    "id": "PERM-DEFAULT-ADMIN",
                    "description": "Default Administrator account is enabled",
                    "severity": "Low",
                    "component": "User Permissions",
                    "fix_available": True,
                    "fix": "Rename or disable the default Administrator account"
                })
        
        # Check directory permissions
        for directory in self.critical_directories:
            if os.path.exists(directory):
                try:
                    # Check if directory is writable by everyone
                    if os.access(directory, os.W_OK):
                        vulnerabilities.append({
                            "id": f"PERM-WRITABLE-DIR-{os.path.basename(directory)}",
                            "description": f"Critical directory {directory} is writable",
                            "severity": "High",
                            "component": "File Permissions",
                            "fix_available": True,
                            "fix": f"Restrict write permissions on {directory}"
                        })
                except Exception as e:
                    self.logger.error(f"Error checking permissions for {directory}: {str(e)}")
        
        return vulnerabilities
    
    def _check_linux_permissions(self) -> List[Dict[str, Any]]:
        """
        Check for Linux-specific permission vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # Check for users with no password
        returncode, stdout, stderr = self._run_command(self.commands["no_password_users"])
        if returncode == 0 and stdout.strip():
            no_password_users = stdout.strip().split('\n')
            for user_entry in no_password_users:
                user = user_entry.split(':')[0]
                vulnerabilities.append({
                    "id": f"PERM-NO-PASSWORD-{user}",
                    "description": f"User {user} has no password set",
                    "severity": "Critical",
                    "component": "User Permissions",
                    "fix_available": True,
                    "fix": f"Set a strong password for user {user}"
                })
        
        # Check for SUID binaries
        returncode, stdout, stderr = self._run_command(self.commands["suid_files"])
        if returncode == 0:
            suid_files = stdout.strip().split('\n')
            
            # Known dangerous SUID binaries
            dangerous_suid = [
                "nmap", "vim", "find", "bash", "sh", "nano", "pico", "less",
                "more", "perl", "python", "ruby", "gdb", "netcat", "nc"
            ]
            
            for suid_file in suid_files:
                for dangerous in dangerous_suid:
                    if dangerous in suid_file:
                        vulnerabilities.append({
                            "id": f"PERM-DANGEROUS-SUID-{dangerous}",
                            "description": f"Dangerous SUID binary: {suid_file}",
                            "severity": "High",
                            "component": "File Permissions",
                            "fix_available": True,
                            "fix": f"Remove SUID bit: chmod -s {suid_file.split()[-1]}"
                        })
        
        # Check for world-writable files
        returncode, stdout, stderr = self._run_command(self.commands["world_writable"])
        if returncode == 0:
            world_writable = stdout.strip().split('\n')
            
            # Check critical directories for world-writable files
            for file_entry in world_writable:
                for critical_dir in self.critical_directories:
                    if critical_dir in file_entry:
                        vulnerabilities.append({
                            "id": "PERM-WORLD-WRITABLE",
                            "description": f"World-writable file in critical directory: {file_entry}",
                            "severity": "High",
                            "component": "File Permissions",
                            "fix_available": True,
                            "fix": f"Remove world-writable permission: chmod o-w {file_entry.split()[-1]}"
                        })
        
        # Check for weak directory permissions
        for directory in self.critical_directories:
            if os.path.exists(directory):
                try:
                    # Check if directory is world-writable
                    mode = os.stat(directory).st_mode
                    if mode & stat.S_IWOTH:
                        vulnerabilities.append({
                            "id": f"PERM-WORLD-WRITABLE-DIR-{os.path.basename(directory)}",
                            "description": f"Critical directory {directory} is world-writable",
                            "severity": "High",
                            "component": "File Permissions",
                            "fix_available": True,
                            "fix": f"Remove world-writable permission: chmod o-w {directory}"
                        })
                except Exception as e:
                    self.logger.error(f"Error checking permissions for {directory}: {str(e)}")
        
        return vulnerabilities
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan for permission vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        self.logger.info(f"Scanning for permission vulnerabilities on {self.os_info['os_name']}...")
        
        if self.os_info["os_name"] == "Windows":
            return self._check_windows_permissions()
        elif self.os_info["os_name"] == "Linux":
            return self._check_linux_permissions()
        else:
            self.logger.warning(f"Unsupported OS: {self.os_info['os_name']}")
            return []
