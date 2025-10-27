# 100 - 📁 Repository Structure

**Core Application:**

1. **f5_security_auditor.py** - A comprehensive Python tool that audits F5 configurations for security issues including:

- SSL/TLS vulnerabilities (weak ciphers, deprecated protocols)
- Certificate problems
- Authentication weaknesses
- Virtual server misconfigurations
- iRule security issues
- Management access controls
- Logging configuration
- Network security settings

**Documentation:**<br/>
2. **OVERVIEW.md** - Comprehensive overview with security concepts, best practices, and learning resources<br/>
3. **USAGE.md** - Detailed usage guide with examples, CI/CD integration, and troubleshooting<br/>
4. **F5-SECURITY-CHEATSHEET.md** - Quick reference for commands, configurations, and security practices<br/>
5. **SECURITY.md** - Security policy for responsible use<br/>
6. **CONTRIBUTING.md** - Guidelines for contributors

**Configuration Files:**<br/>
7. **sample_bigip_config.conf** - Intentionally vulnerable test configuration for practicing<br/>
8. **requirements.txt** - Python dependencies (minimal, uses standard library)<br/>
9. **.gitignore** - Prevents committing sensitive files<br/>
10. **LICENSE** - MIT License with responsible use terms