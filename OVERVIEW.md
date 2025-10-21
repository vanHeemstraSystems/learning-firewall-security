# Learning Firewall Security (F5 BIG-IP)

A comprehensive repository for learning F5 BIG-IP security concepts, configuration best practices, and security auditing techniques.

## Overview

This repository contains tools, scripts, and documentation for understanding and securing F5 BIG-IP Application Delivery Controllers (ADCs). F5 BIG-IP is widely used for load balancing, application security, and traffic management in enterprise environments.

## Repository Contents

- **F5 Configuration Security Auditor** - Python tool for analyzing F5 BIG-IP configurations
- **Security Best Practices Documentation**
- **Common Vulnerabilities and Mitigations**
- **Sample Configurations**

## What is F5 BIG-IP?

F5 BIG-IP is an Application Delivery Controller that provides:

- **Load Balancing** - Distributes traffic across multiple servers
- **Web Application Firewall (WAF)** - Protects against OWASP Top 10 threats
- **SSL/TLS Offloading** - Handles encryption/decryption
- **DDoS Protection** - Mitigates denial-of-service attacks
- **Access Policy Manager (APM)** - Authentication and authorization
- **Local Traffic Manager (LTM)** - Application delivery and optimization

## Key Security Concepts

### 1. Traffic Management

- Virtual Servers (VIPs)
- Pools and Pool Members
- Health Monitors
- Load Balancing Algorithms

### 2. SSL/TLS Security

- Certificate Management
- Cipher Suite Configuration
- Perfect Forward Secrecy (PFS)
- TLS Version Control

### 3. Access Control

- iRules for custom traffic control
- Data Groups for IP whitelisting/blacklisting
- Authentication mechanisms
- Role-Based Access Control (RBAC)

### 4. Application Security Module (ASM/WAF)

- Signature-based detection
- Behavioral analysis
- Bot detection
- Attack signatures

### 5. Network Security

- Port lockdown
- Self IP configuration
- VLANs and route domains
- SNAT/DNAT configurations

## F5 Configuration Security Auditor

The main tool in this repository is a Python-based security auditor that checks F5 BIG-IP configurations against security best practices.

### Features

- ✅ SSL/TLS configuration analysis
- ✅ Cipher suite vulnerability detection
- ✅ Weak authentication detection
- ✅ Default credential checks
- ✅ Port lockdown verification
- ✅ Certificate expiration monitoring
- ✅ iRule security analysis
- ✅ Virtual server health checks
- ✅ Logging and monitoring configuration
- ✅ SNAT/DNAT security review

### Usage

```bash
python3 f5_security_auditor.py --config-file bigip_config.conf --output report.json
```

### Prerequisites

```bash
pip install -r requirements.txt
```

## Common F5 Security Issues

### 1. Weak SSL/TLS Configuration

- **Issue**: Using outdated protocols (SSLv3, TLS 1.0)
- **Impact**: Vulnerable to POODLE, BEAST attacks
- **Mitigation**: Enforce TLS 1.2+ only

### 2. Weak Cipher Suites

- **Issue**: Supporting RC4, DES, or export ciphers
- **Impact**: Cryptographic vulnerabilities
- **Mitigation**: Use only strong ciphers (AES-GCM, ChaCha20)

### 3. Default Credentials

- **Issue**: Using admin/admin or default passwords
- **Impact**: Unauthorized access
- **Mitigation**: Strong password policy and key-based auth

### 4. Unrestricted Management Access

- **Issue**: Management interface accessible from public networks
- **Impact**: Unauthorized configuration changes
- **Mitigation**: Restrict management to specific IPs/VLANs

### 5. Missing Security Headers

- **Issue**: No HSTS, X-Frame-Options, CSP headers
- **Impact**: Client-side attacks
- **Mitigation**: Implement security headers via iRules

### 6. Insufficient Logging

- **Issue**: Inadequate audit logging
- **Impact**: Poor incident response capability
- **Mitigation**: Enable comprehensive logging to SIEM

## Best Practices Checklist

- [ ] TLS 1.2 or higher only
- [ ] Strong cipher suites configured
- [ ] Perfect Forward Secrecy (PFS) enabled
- [ ] Certificate expiration monitoring
- [ ] Management access restricted to authorized networks
- [ ] Strong authentication (MFA preferred)
- [ ] Regular security updates applied
- [ ] Comprehensive logging enabled
- [ ] iRules reviewed for injection vulnerabilities
- [ ] Health monitors properly configured
- [ ] Unused services disabled
- [ ] Default accounts removed or secured
- [ ] Regular configuration backups
- [ ] Security headers implemented

## Learning Resources

### Official F5 Documentation

- [F5 BIG-IP Configuration Guide](https://support.f5.com)
- [F5 Security Advisory](https://support.f5.com/csp/article/K4602)
- [F5 DevCentral](https://devcentral.f5.com)

### Security Standards

- OWASP Top 10
- CIS Benchmarks for F5 BIG-IP
- NIST Cybersecurity Framework
- PCI DSS Requirements

### Community Resources

- F5 DevCentral Forums
- GitHub F5 iRules Repository
- F5 Solutions Articles

## Common F5 CLI Commands

```bash
# View running configuration
tmsh list ltm virtual

# Check SSL profile
tmsh list ltm profile client-ssl

# View pool status
tmsh show ltm pool

# Check license
tmsh show sys license

# View system version
tmsh show sys version

# Save configuration
tmsh save sys config
```

## Lab Environment Setup

For hands-on learning, consider:

- F5 BIG-IP Virtual Edition (trial available)
- GNS3 or EVE-NG for network simulation
- Docker containers for backend applications
- Attack simulation with Kali Linux

## Contributing

Contributions are welcome! Please:

1. Fork the repository
1. Create a feature branch
1. Add your tools/documentation
1. Submit a pull request

## Security Considerations

This repository is for **educational purposes only**. Always:

- Test in isolated lab environments
- Never run audits on production systems without authorization
- Follow responsible disclosure for vulnerabilities
- Comply with organizational security policies

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse of this software.

## Author

**Your Name** - Cybersecurity Engineer

- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your Profile](https://linkedin.com/in/yourprofile)

## Roadmap

- [ ] Add API integration for live configuration pulls
- [ ] Implement automated remediation suggestions
- [ ] Create Ansible playbooks for hardening
- [ ] Add support for F5 ASM policy analysis
- [ ] Integrate with SIEM platforms
- [ ] Add iRule vulnerability scanner
- [ ] Create comparison tool for configuration drift

-----

**Last Updated**: October 2025
