#!/usr/bin/env python3
"""
F5 BIG-IP Security Configuration Auditor
A comprehensive tool for auditing F5 BIG-IP configurations against security best practices
"""

import re
import json
import argparse
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from collections import defaultdict

class F5SecurityAuditor:
   """Main auditor class for F5 BIG-IP security configuration analysis"""

def __init__(self, config_file: str):
    self.config_file = config_file
    self.config_content = ""
    self.findings = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": []
    }
    self.stats = {
        "virtual_servers": 0,
        "pools": 0,
        "ssl_profiles": 0,
        "irules": 0
    }
    
    # Security standards
    self.weak_ciphers = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", 
        "anon", "ADH", "aNULL", "eNULL"
    ]
    
    self.deprecated_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"]
    
    self.strong_ciphers = [
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256"
    ]
    
    self.default_credentials = [
        ("admin", "admin"),
        ("root", "default"),
        ("support", "support")
    ]

def load_config(self) -> bool:
    """Load F5 configuration file"""
    try:
        with open(self.config_file, 'r') as f:
            self.config_content = f.read()
        print(f"[+] Loaded configuration file: {self.config_file}")
        return True
    except FileNotFoundError:
        print(f"[-] Error: Configuration file not found: {self.config_file}")
        return False
    except Exception as e:
        print(f"[-] Error loading configuration: {str(e)}")
        return False

def add_finding(self, severity: str, category: str, title: str, 
               description: str, recommendation: str, affected_items: List[str] = None):
    """Add a security finding"""
    finding = {
        "category": category,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "affected_items": affected_items or [],
        "timestamp": datetime.now().isoformat()
    }
    self.findings[severity].append(finding)

def audit_ssl_tls_configuration(self):
    """Audit SSL/TLS configuration for security issues"""
    print("\n[*] Auditing SSL/TLS Configuration...")
    
    # Find SSL profiles
    ssl_profile_pattern = r'ltm profile client-ssl\s+([^\s{]+)\s*{([^}]+)}'
    ssl_profiles = re.findall(ssl_profile_pattern, self.config_content, re.DOTALL)
    
    self.stats["ssl_profiles"] = len(ssl_profiles)
    
    for profile_name, profile_config in ssl_profiles:
        # Check for weak protocols
        for protocol in self.deprecated_protocols:
            if re.search(rf'\bno-{protocol}\b', profile_config):
                continue  # Protocol is disabled (good)
            if protocol.lower() in profile_config.lower():
                self.add_finding(
                    "high",
                    "SSL/TLS",
                    f"Deprecated Protocol Enabled: {protocol}",
                    f"SSL profile '{profile_name}' may allow {protocol}, which has known vulnerabilities.",
                    f"Disable {protocol} and enforce TLS 1.2 or higher only.",
                    [profile_name]
                )
        
        # Check cipher configuration
        cipher_match = re.search(r'ciphers\s+([^\n]+)', profile_config)
        if cipher_match:
            cipher_string = cipher_match.group(1).strip()
            
            # Check for weak ciphers
            for weak_cipher in self.weak_ciphers:
                if weak_cipher in cipher_string:
                    self.add_finding(
                        "critical",
                        "SSL/TLS",
                        f"Weak Cipher Suite Detected: {weak_cipher}",
                        f"SSL profile '{profile_name}' includes weak cipher: {weak_cipher}",
                        f"Remove {weak_cipher} from cipher suite and use only strong AEAD ciphers.",
                        [profile_name]
                    )
            
            # Check for absence of strong ciphers
            has_strong_cipher = any(sc in cipher_string for sc in self.strong_ciphers)
            if not has_strong_cipher:
                self.add_finding(
                    "medium",
                    "SSL/TLS",
                    "No Modern Cipher Suites Configured",
                    f"SSL profile '{profile_name}' does not explicitly include modern AEAD ciphers.",
                    "Configure cipher suites with ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384, etc.",
                    [profile_name]
                )
        else:
            self.add_finding(
                "low",
                "SSL/TLS",
                "Cipher Suite Not Explicitly Configured",
                f"SSL profile '{profile_name}' relies on default cipher configuration.",
                "Explicitly configure strong cipher suites for better security control.",
                [profile_name]
            )
        
        # Check for Perfect Forward Secrecy
        if not re.search(r'ECDHE|DHE', profile_config):
            self.add_finding(
                "medium",
                "SSL/TLS",
                "Perfect Forward Secrecy Not Enforced",
                f"SSL profile '{profile_name}' may not enforce PFS (no ECDHE/DHE ciphers detected).",
                "Enable Perfect Forward Secrecy by including ECDHE or DHE cipher suites.",
                [profile_name]
            )

def audit_certificate_configuration(self):
    """Audit certificate configuration and expiration"""
    print("[*] Auditing Certificate Configuration...")
    
    cert_pattern = r'cert\s+([^\s]+)'
    key_pattern = r'key\s+([^\s]+)'
    
    certs = re.findall(cert_pattern, self.config_content)
    keys = re.findall(key_pattern, self.config_content)
    
    # Check for default certificates
    default_certs = ["default.crt", "server.crt", "localhost.crt", "test.crt"]
    for cert in certs:
        if any(dc in cert.lower() for dc in default_certs):
            self.add_finding(
                "high",
                "Certificates",
                "Default or Test Certificate in Use",
                f"Certificate '{cert}' appears to be a default or test certificate.",
                "Replace with a valid, organization-specific certificate from a trusted CA.",
                [cert]
            )
    
    # Check for missing key
    if len(certs) != len(keys):
        self.add_finding(
            "medium",
            "Certificates",
            "Certificate/Key Mismatch",
            f"Found {len(certs)} certificates but {len(keys)} keys. Verify all certificates have corresponding private keys.",
            "Ensure each certificate has a corresponding private key configured.",
            []
        )

def audit_authentication_configuration(self):
    """Audit authentication and access control"""
    print("[*] Auditing Authentication Configuration...")
    
    # Check for user accounts
    user_pattern = r'auth user\s+([^\s{]+)\s*{([^}]+)}'
    users = re.findall(user_pattern, self.config_content, re.DOTALL)
    
    for username, user_config in users:
        # Check for default usernames
        if username.lower() in ["admin", "root", "support", "test"]:
            self.add_finding(
                "high",
                "Authentication",
                f"Default or Weak Username: {username}",
                f"User account '{username}' uses a commonly-known default username.",
                "Rename default accounts and use unique, non-obvious usernames.",
                [username]
            )
        
        # Check for weak password configurations
        if re.search(r'password\s+\$[16]\$', user_config):
            self.add_finding(
                "critical",
                "Authentication",
                f"Weak Password Hash Detected",
                f"User '{username}' may be using MD5 or weak password hashing.",
                "Enforce strong password hashing (bcrypt, SHA-256+) and implement MFA.",
                [username]
            )
    
    # Check for remote authentication
    if "auth remote-role" not in self.config_content and "auth ldap" not in self.config_content:
        self.add_finding(
            "low",
            "Authentication",
            "No Centralized Authentication Configured",
            "No LDAP, RADIUS, or TACACS+ authentication detected.",
            "Consider implementing centralized authentication for better access control and auditing.",
            []
        )

def audit_virtual_servers(self):
    """Audit virtual server configurations"""
    print("[*] Auditing Virtual Server Configuration...")
    
    vs_pattern = r'ltm virtual\s+([^\s{]+)\s*{([^}]+(?:{[^}]+})*[^}]+)}'
    virtual_servers = re.findall(vs_pattern, self.config_content, re.DOTALL)
    
    self.stats["virtual_servers"] = len(virtual_servers)
    
    for vs_name, vs_config in virtual_servers:
        # Check for missing SSL profile
        if "destination" in vs_config and "443" in vs_config:
            if "client-ssl" not in vs_config:
                self.add_finding(
                    "high",
                    "Virtual Servers",
                    "HTTPS Virtual Server Without SSL Profile",
                    f"Virtual server '{vs_name}' listens on port 443 but has no client-ssl profile configured.",
                    "Configure an appropriate SSL profile for HTTPS traffic.",
                    [vs_name]
                )
        
        # Check for missing pool
        if "pool" not in vs_config:
            self.add_finding(
                "medium",
                "Virtual Servers",
                "Virtual Server Without Pool",
                f"Virtual server '{vs_name}' has no pool configured.",
                "Assign a pool with appropriate backend servers or disable the virtual server.",
                [vs_name]
            )
        
        # Check for source address translation
        if "source-address-translation" not in vs_config:
            self.add_finding(
                "low",
                "Virtual Servers",
                "No SNAT Configured",
                f"Virtual server '{vs_name}' may not have SNAT configured.",
                "Consider configuring SNAT if backend servers cannot route back to clients.",
                [vs_name]
            )

def audit_pools_and_monitors(self):
    """Audit pool and health monitor configuration"""
    print("[*] Auditing Pools and Health Monitors...")
    
    pool_pattern = r'ltm pool\s+([^\s{]+)\s*{([^}]+(?:{[^}]+})*[^}]+)}'
    pools = re.findall(pool_pattern, self.config_content, re.DOTALL)
    
    self.stats["pools"] = len(pools)
    
    for pool_name, pool_config in pools:
        # Check for missing health monitor
        if "monitor" not in pool_config:
            self.add_finding(
                "medium",
                "Pools",
                "Pool Without Health Monitor",
                f"Pool '{pool_name}' has no health monitor configured.",
                "Configure an appropriate health monitor to detect failed pool members.",
                [pool_name]
            )
        
        # Check for pool members
        if "members" not in pool_config:
            self.add_finding(
                "low",
                "Pools",
                "Empty Pool Configuration",
                f"Pool '{pool_name}' has no members configured.",
                "Add backend server members or remove unused pool.",
                [pool_name]
            )

def audit_irules(self):
    """Audit iRules for security issues"""
    print("[*] Auditing iRules...")
    
    irule_pattern = r'ltm rule\s+([^\s{]+)\s*{([^}]+)}'
    irules = re.findall(irule_pattern, self.config_content, re.DOTALL)
    
    self.stats["irules"] = len(irules)
    
    dangerous_commands = ["exec", "eval", "HTTP::respond", "HTTP::redirect"]
    
    for irule_name, irule_content in irules:
        # Check for dangerous commands
        for cmd in dangerous_commands:
            if cmd in irule_content:
                self.add_finding(
                    "medium",
                    "iRules",
                    f"Potentially Dangerous Command in iRule: {cmd}",
                    f"iRule '{irule_name}' uses {cmd} which could pose security risks if not properly validated.",
                    f"Ensure all inputs are validated and sanitized before using {cmd}.",
                    [irule_name]
                )
        
        # Check for HTTP header injection risks
        if "HTTP::header insert" in irule_content or "HTTP::header replace" in irule_content:
            if "validate" not in irule_content.lower() and "sanitize" not in irule_content.lower():
                self.add_finding(
                    "high",
                    "iRules",
                    "Potential HTTP Header Injection",
                    f"iRule '{irule_name}' modifies HTTP headers without apparent input validation.",
                    "Implement input validation and sanitization before modifying HTTP headers.",
                    [irule_name]
                )

def audit_management_access(self):
    """Audit management interface security"""
    print("[*] Auditing Management Access Configuration...")
    
    # Check for management IP restrictions
    if "net self-allow" not in self.config_content:
        self.add_finding(
            "high",
            "Management",
            "No Management Access Restrictions",
            "Management access restrictions (self-allow) are not configured.",
            "Configure port lockdown to restrict management access to specific IPs/networks.",
            []
        )
    
    # Check for HTTPs management
    if re.search(r'httpd.*ssl-port\s+0', self.config_content):
        self.add_finding(
            "critical",
            "Management",
            "HTTPS Management Interface Disabled",
            "HTTPS management interface is disabled, management traffic may be unencrypted.",
            "Enable HTTPS for management interface (ssl-port 443) and disable HTTP.",
            []
        )
    
    # Check for SSH configuration
    if "sshd" in self.config_content:
        if not re.search(r'sshd.*inactivity-timeout', self.config_content):
            self.add_finding(
                "low",
                "Management",
                "No SSH Inactivity Timeout",
                "SSH does not have inactivity timeout configured.",
                "Configure SSH inactivity timeout to automatically disconnect idle sessions.",
                []
            )

def audit_logging_configuration(self):
    """Audit logging and monitoring configuration"""
    print("[*] Auditing Logging Configuration...")
    
    # Check for remote logging
    if "sys syslog" not in self.config_content and "log publisher" not in self.config_content:
        self.add_finding(
            "medium",
            "Logging",
            "No Remote Logging Configured",
            "Remote syslog or log publisher not configured.",
            "Configure remote logging to a centralized SIEM for security monitoring.",
            []
        )
    
    # Check for audit logging
    if "sys audit" not in self.config_content:
        self.add_finding(
            "medium",
            "Logging",
            "Audit Logging Not Configured",
            "System audit logging may not be enabled.",
            "Enable audit logging to track configuration changes and administrative actions.",
            []
        )

def audit_network_security(self):
    """Audit network security configuration"""
    print("[*] Auditing Network Security Configuration...")
    
    # Check for unused services
    services_to_check = ["telnet", "ftp", "snmp"]
    for service in services_to_check:
        if re.search(rf'sys service {service}.*disabled\s+false', self.config_content):
            self.add_finding(
                "high",
                "Network Security",
                f"Insecure Service Enabled: {service.upper()}",
                f"The {service.upper()} service is enabled, which transmits data in cleartext.",
                f"Disable {service.upper()} and use secure alternatives (SSH, SFTP, SNMPv3).",
                []
            )
    
    # Check for SNMPv1/v2c
    if re.search(r'snmp.*community\s+public', self.config_content):
        self.add_finding(
            "critical",
            "Network Security",
            "Default SNMP Community String",
            "SNMP is configured with default community string 'public'.",
            "Change SNMP community strings and use SNMPv3 with encryption.",
            []
        )

def generate_report(self, output_format: str = "text") -> str:
    """Generate security audit report"""
    if output_format == "json":
        return self._generate_json_report()
    else:
        return self._generate_text_report()

def _generate_text_report(self) -> str:
    """Generate human-readable text report"""
    report = []
    report.append("=" * 80)
    report.append("F5 BIG-IP SECURITY AUDIT REPORT")
    report.append("=" * 80)
    report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Configuration File: {self.config_file}")
    report.append("\n" + "-" * 80)
    report.append("CONFIGURATION STATISTICS")
    report.append("-" * 80)
    report.append(f"Virtual Servers: {self.stats['virtual_servers']}")
    report.append(f"Pools: {self.stats['pools']}")
    report.append(f"SSL Profiles: {self.stats['ssl_profiles']}")
    report.append(f"iRules: {self.stats['irules']}")
    
    report.append("\n" + "-" * 80)
    report.append("FINDINGS SUMMARY")
    report.append("-" * 80)
    
    total_findings = sum(len(findings) for findings in self.findings.values())
    report.append(f"Total Findings: {total_findings}")
    report.append(f"  Critical: {len(self.findings['critical'])}")
    report.append(f"  High: {len(self.findings['high'])}")
    report.append(f"  Medium: {len(self.findings['medium'])}")
    report.append(f"  Low: {len(self.findings['low'])}")
    report.append(f"  Info: {len(self.findings['info'])}")
    
    for severity in ["critical", "high", "medium", "low", "info"]:
        if self.findings[severity]:
            report.append(f"\n{'=' * 80}")
            report.append(f"{severity.upper()} SEVERITY FINDINGS ({len(self.findings[severity])})")
            report.append("=" * 80)
            
            for idx, finding in enumerate(self.findings[severity], 1):
                report.append(f"\n[{severity.upper()}-{idx:03d}] {finding['title']}")
                report.append(f"Category: {finding['category']}")
                report.append(f"\nDescription:")
                report.append(f"  {finding['description']}")
                report.append(f"\nRecommendation:")
                report.append(f"  {finding['recommendation']}")
                if finding['affected_items']:
                    report.append(f"\nAffected Items:")
                    for item in finding['affected_items']:
                        report.append(f"  - {item}")
                report.append("-" * 80)
    
    report.append("\n" + "=" * 80)
    report.append("END OF REPORT")
    report.append("=" * 80)
    
    return "\n".join(report)

def _generate_json_report(self) -> str:
    """Generate JSON format report"""
    report = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "config_file": self.config_file,
            "auditor_version": "1.0.0"
        },
        "statistics": self.stats,
        "summary": {
            "total_findings": sum(len(findings) for findings in self.findings.values()),
            "by_severity": {
                severity: len(findings) 
                for severity, findings in self.findings.items()
            }
        },
        "findings": self.findings
    }
    return json.dumps(report, indent=2)

def run_audit(self):
    """Run complete security audit"""
    print("\n" + "=" * 80)
    print("F5 BIG-IP Security Configuration Auditor")
    print("=" * 80)
    
    if not self.load_config():
        return False
    
    # Run all audit checks
    self.audit_ssl_tls_configuration()
    self.audit_certificate_configuration()
    self.audit_authentication_configuration()
    self.audit_virtual_servers()
    self.audit_pools_and_monitors()
    self.audit_irules()
    self.audit_management_access()
    self.audit_logging_configuration()
    self.audit_network_security()
    
    print("\n[+] Audit completed successfully!")
    return True

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
      description="F5 BIG-IP Security Configuration Auditor",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog="""
Examples:
python3 f5_security_auditor.py –config-file bigip.conf
python3 f5_security_auditor.py –config-file bigip.conf –output report.json –format json
python3 f5_security_auditor.py –config-file bigip.conf –output report.txt
"""
    )

    parser.add_argument(
        "--config-file",
        required=True,
        help="Path to F5 BIG-IP configuration file"
    )

    parser.add_argument(
        "--output",
        help="Output file for the report (default: stdout)"
    )

    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter findings by minimum severity level"
    )

    args = parser.parse_args()

    # Run audit
    auditor = F5SecurityAuditor(args.config_file)

    if not auditor.run_audit():
        sys.exit(1)

    # Generate report
    report = auditor.generate_report(args.format)

    # Output report
    if args.output:
        try:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\n[+] Report saved to: {args.output}")
        except Exception as e:
            print(f"[-] Error saving report: {str(e)}")
            sys.exit(1)
    else:
        print("\n" + report)

    # Exit with appropriate code
    total_critical_high = len(auditor.findings['critical']) + len(auditor.findings['high'])
    if total_critical_high > 0:
        print(f"\n[!] WARNING: Found {total_critical_high} critical/high severity findings!")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
