#!/usr/bin/env python3
"""
Network Scanner Module - Detects network-related vulnerabilities.

This module scans for open ports, running services, and network configuration
issues that could pose security risks.
"""

import os
import re
import socket
import subprocess
import logging
import platform
from typing import Dict, List, Any, Optional, Tuple, Set

class NetworkScanner:
    """Scanner for network vulnerabilities."""
    
    def __init__(self):
        """Initialize the network scanner."""
        self.logger = logging.getLogger("vulnerability_scanner")
        
        # Define common vulnerable ports and services
        self.vulnerable_ports = {
            21: {"service": "FTP", "severity": "Medium", "description": "Unencrypted file transfer protocol"},
            22: {"service": "SSH", "severity": "Low", "description": "Secure Shell - ensure latest version and proper configuration"},
            23: {"service": "Telnet", "severity": "High", "description": "Unencrypted terminal access"},
            25: {"service": "SMTP", "severity": "Medium", "description": "Mail server - often targeted for spam relaying"},
            53: {"service": "DNS", "severity": "Medium", "description": "Domain Name System - ensure properly configured"},
            80: {"service": "HTTP", "severity": "Medium", "description": "Unencrypted web server"},
            110: {"service": "POP3", "severity": "Medium", "description": "Unencrypted mail retrieval"},
            135: {"service": "RPC", "severity": "High", "description": "Windows RPC service - often exploited"},
            137: {"service": "NetBIOS", "severity": "High", "description": "NetBIOS Name Service - often exploited"},
            139: {"service": "NetBIOS", "severity": "High", "description": "NetBIOS Session Service - often exploited"},
            445: {"service": "SMB", "severity": "High", "description": "Server Message Block - often exploited"},
            1433: {"service": "MSSQL", "severity": "Medium", "description": "Microsoft SQL Server - ensure properly secured"},
            1521: {"service": "Oracle", "severity": "Medium", "description": "Oracle Database - ensure properly secured"},
            3306: {"service": "MySQL", "severity": "Medium", "description": "MySQL Database - ensure properly secured"},
            3389: {"service": "RDP", "severity": "Medium", "description": "Remote Desktop Protocol - ensure properly secured"},
            5432: {"service": "PostgreSQL", "severity": "Medium", "description": "PostgreSQL Database - ensure properly secured"},
            5900: {"service": "VNC", "severity": "High", "description": "Virtual Network Computing - often unencrypted"},
            8080: {"service": "HTTP-ALT", "severity": "Medium", "description": "Alternative HTTP port - often used for proxies"},
            8443: {"service": "HTTPS-ALT", "severity": "Low", "description": "Alternative HTTPS port"}
        }
        
        # Define OS-specific commands
        self.commands = self._get_network_commands()
    
    def _get_network_commands(self) -> Dict[str, str]:
        """
        Get OS-specific commands for network scanning.
        
        Returns:
            Dictionary of commands for the current OS
        """
        if platform.system() == "Windows":
            return {
                "open_ports": "netstat -ano",
                "listening_services": "netstat -ano | findstr LISTENING",
                "firewall_status": "netsh advfirewall show allprofiles",
                "routing_table": "route print",
                "arp_table": "arp -a"
            }
        else:  # Linux
            return {
                "open_ports": "ss -tuln || netstat -tuln",
                "listening_services": "ss -tuln | grep LISTEN || netstat -tuln | grep LISTEN",
                "firewall_status": "iptables -L || ufw status",
                "routing_table": "ip route || route -n",
                "arp_table": "ip neigh || arp -a"
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
    
    def _scan_open_ports(self) -> Set[int]:
        """
        Scan for open ports using system commands.
        
        Returns:
            Set of open port numbers
        """
        open_ports = set()
        
        # Run netstat or ss command to get open ports
        returncode, stdout, stderr = self._run_command(self.commands["open_ports"])
        if returncode == 0:
            # Parse output to extract port numbers
            if platform.system() == "Windows":
                # Windows netstat format: Proto  Local Address  Foreign Address  State  PID
                for line in stdout.strip().split('\n')[4:]:  # Skip header lines
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        local_address = parts[1]
                        if ":" in local_address:
                            port = local_address.split(":")[-1]
                            try:
                                open_ports.add(int(port))
                            except ValueError:
                                pass
            else:
                # Linux ss/netstat format varies, but generally includes :port
                for line in stdout.strip().split('\n'):
                    # Look for patterns like *:22 or 127.0.0.1:80
                    port_matches = re.findall(r':(\d+)\s', line)
                    for port in port_matches:
                        try:
                            open_ports.add(int(port))
                        except ValueError:
                            pass
        
        return open_ports
    
    def _scan_ports_with_socket(self, max_port: int = 1024) -> Set[int]:
        """
        Scan for open ports using socket connections.
        
        Args:
            max_port: Maximum port number to scan
            
        Returns:
            Set of open port numbers
        """
        open_ports = set()
        
        # Only scan localhost to avoid network issues
        host = '127.0.0.1'
        
        for port in range(1, max_port + 1):
            try:
                # Create socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)  # Short timeout
                
                # Try to connect
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.add(port)
                
                # Close socket
                s.close()
            except:
                pass
        
        return open_ports
    
    def _check_firewall_status(self) -> List[Dict[str, Any]]:
        """
        Check firewall status and configuration.
        
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # Run firewall status command
        returncode, stdout, stderr = self._run_command(self.commands["firewall_status"])
        if returncode == 0:
            if platform.system() == "Windows":
                # Check if Windows Firewall is enabled
                if "State                                 OFF" in stdout:
                    vulnerabilities.append({
                        "id": "NET-FIREWALL-DISABLED",
                        "description": "Windows Firewall is disabled",
                        "severity": "High",
                        "component": "Firewall",
                        "fix_available": True,
                        "fix": "Enable Windows Firewall"
                    })
            else:
                # Check if Linux firewall is configured
                if "Chain INPUT (policy ACCEPT)" in stdout and "Chain FORWARD (policy ACCEPT)" in stdout:
                    vulnerabilities.append({
                        "id": "NET-FIREWALL-DEFAULT-ACCEPT",
                        "description": "Firewall default policy is set to ACCEPT",
                        "severity": "High",
                        "component": "Firewall",
                        "fix_available": True,
                        "fix": "Configure firewall with default DROP policy"
                    })
                
                if "inactive" in stdout.lower() or (len(stdout.strip().split('\n')) < 3 and "Chain" not in stdout):
                    vulnerabilities.append({
                        "id": "NET-FIREWALL-INACTIVE",
                        "description": "Firewall appears to be inactive or unconfigured",
                        "severity": "High",
                        "component": "Firewall",
                        "fix_available": True,
                        "fix": "Enable and configure firewall (iptables or ufw)"
                    })
        
        return vulnerabilities
    
    def _check_port_vulnerabilities(self, open_ports: Set[int]) -> List[Dict[str, Any]]:
        """
        Check for vulnerabilities associated with open ports.
        
        Args:
            open_ports: Set of open port numbers
            
        Returns:
            List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        for port in open_ports:
            if port in self.vulnerable_ports:
                service_info = self.vulnerable_ports[port]
                vulnerabilities.append({
                    "id": f"NET-OPEN-PORT-{port}",
                    "description": f"Open {service_info['service']} port ({port}): {service_info['description']}",
                    "severity": service_info["severity"],
                    "component": "Network",
                    "fix_available": True,
                    "fix": f"Close port {port} if not needed, or secure the {service_info['service']} service"
                })
        
        return vulnerabilities
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan for network vulnerabilities.
        
        Returns:
            List of vulnerability dictionaries
        """
        self.logger.info("Scanning for network vulnerabilities...")
        vulnerabilities = []
        
        # Scan for open ports
        open_ports = self._scan_open_ports()
        self.logger.info(f"Found {len(open_ports)} open ports")
        
        # Check for port-related vulnerabilities
        port_vulnerabilities = self._check_port_vulnerabilities(open_ports)
        vulnerabilities.extend(port_vulnerabilities)
        
        # Check firewall status
        firewall_vulnerabilities = self._check_firewall_status()
        vulnerabilities.extend(firewall_vulnerabilities)
        
        # Additional network checks
        if platform.system() == "Windows":
            # Check for SMB vulnerabilities on Windows
            if 445 in open_ports:
                # Check SMB version (simplified example)
                vulnerabilities.append({
                    "id": "NET-SMB-EXPOSED",
                    "description": "SMB port (445) is open and potentially accessible",
                    "severity": "Medium",
                    "component": "Network",
                    "fix_available": True,
                    "fix": "Block SMB port (445) on public networks"
                })
        else:
            # Check for SSH root login on Linux
            if 22 in open_ports and os.path.exists("/etc/ssh/sshd_config"):
                try:
                    with open("/etc/ssh/sshd_config", "r") as f:
                        sshd_config = f.read()
                        if "PermitRootLogin yes" in sshd_config:
                            vulnerabilities.append({
                                "id": "NET-SSH-ROOT-LOGIN",
                                "description": "SSH root login is enabled",
                                "severity": "High",
                                "component": "Network",
                                "fix_available": True,
                                "fix": "Disable root login in /etc/ssh/sshd_config"
                            })
                except Exception as e:
                    self.logger.error(f"Error checking SSH config: {str(e)}")
        
        self.logger.info(f"Found {len(vulnerabilities)} network vulnerabilities")
        return vulnerabilities
