# F5 Security Auditor - Usage Guide

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Learning-Firewall-Security.git
cd Learning-Firewall-Security

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (if any)
pip install -r requirements.txt
```

### 2. Running Your First Audit

Test with the sample configuration:

```bash
python3 f5_security_auditor.py --config-file sample_bigip_config.conf
```

### 3. Basic Usage

```bash
# Run audit and display results on screen
python3 f5_security_auditor.py --config-file /path/to/bigip.conf

# Save report to text file
python3 f5_security_auditor.py --config-file /path/to/bigip.conf --output audit_report.txt

# Generate JSON report for automation
python3 f5_security_auditor.py --config-file /path/to/bigip.conf --output report.json --format json
```

## Getting F5 Configuration Files

### Method 1: From F5 BIG-IP CLI

```bash
# SSH to your F5 device
ssh admin@f5-device-ip

# Save current configuration
tmsh save sys config

# Generate single configuration file (UCS not needed)
tmsh list > bigip_full_config.conf

# Or export specific sections
tmsh list ltm > ltm_config.conf
tmsh list auth > auth_config.conf
tmsh list sys > sys_config.conf
```

### Method 2: From F5 Web GUI

1. Log in to F5 web interface (https://your-f5-ip)
1. Navigate to **System → Archives**
1. Click **Create** to generate a UCS archive
1. Download the UCS file
1. Extract configuration: `tar -xzf backup.ucs bigip.conf`

### Method 3: Using iControl REST API

```bash
# Get configuration via API
curl -k -u admin:password \
  https://f5-device-ip/mgmt/tm/sys/config \
  -o bigip_config.json
```

## Understanding the Output

### Severity Levels

- **CRITICAL**: Immediate action required (e.g., weak ciphers, default credentials)
- **HIGH**: Significant security risk (e.g., deprecated protocols, missing SSL profiles)
- **MEDIUM**: Moderate risk that should be addressed (e.g., missing health monitors, no PFS)
- **LOW**: Best practice violations (e.g., missing timeouts, no explicit configuration)
- **INFO**: Informational findings for awareness

### Sample Output

```
================================================================================
F5 BIG-IP SECURITY AUDIT REPORT
================================================================================

Generated: 2025-10-21 14:30:45
Configuration File: bigip.conf

--------------------------------------------------------------------------------
CONFIGURATION STATISTICS
--------------------------------------------------------------------------------
Virtual Servers: 5
Pools: 3
SSL Profiles: 2
iRules: 4

--------------------------------------------------------------------------------
FINDINGS SUMMARY
--------------------------------------------------------------------------------
Total Findings: 12
  Critical: 2
  High: 3
  Medium: 4
  Low: 2
  Info: 1

================================================================================
CRITICAL SEVERITY FINDINGS (2)
================================================================================

[CRITICAL-001] Weak Cipher Suite Detected: RC4
Category: SSL/TLS

Description:
  SSL profile 'weak_ssl_profile' includes weak cipher: RC4

Recommendation:
  Remove RC4 from cipher suite and use only strong AEAD ciphers.

Affected Items:
  - weak_ssl_profile
--------------------------------------------------------------------------------
```

## Common Audit Scenarios

### Scenario 1: Pre-Deployment Security Review

```bash
# Audit configuration before deploying to production
python3 f5_security_auditor.py --config-file staging_config.conf --output pre_deploy_audit.txt

# Review critical and high findings
grep -A 10 "CRITICAL\|HIGH" pre_deploy_audit.txt
```

### Scenario 2: Regular Compliance Audits

```bash
# Monthly security audit with JSON output for tracking
python3 f5_security_auditor.py \
  --config-file prod_config.conf \
  --output audit_$(date +%Y%m%d).json \
  --format json
```

### Scenario 3: Post-Change Validation

```bash
# Audit after configuration changes
python3 f5_security_auditor.py --config-file updated_config.conf --output post_change_audit.txt

# Compare with baseline
diff baseline_audit.txt post_change_audit.txt
```

## Integration with CI/CD

### GitLab CI Example

```yaml
f5_security_audit:
  stage: test
  script:
    - python3 f5_security_auditor.py --config-file config/bigip.conf --output audit.json --format json
    - |
      if [ $(jq '.summary.by_severity.critical + .summary.by_severity.high' audit.json) -gt 0 ]; then
        echo "Critical or High severity findings detected!"
        exit 1
      fi
  artifacts:
    paths:
      - audit.json
    expire_in: 30 days
```

### Jenkins Pipeline Example

```groovy
stage('F5 Security Audit') {
    steps {
        sh '''
            python3 f5_security_auditor.py \
              --config-file config/bigip.conf \
              --output audit_report.json \
              --format json
        '''
        
        script {
            def report = readJSON file: 'audit_report.json'
            def criticalCount = report.summary.by_severity.critical
            def highCount = report.summary.by_severity.high
            
            if (criticalCount + highCount > 0) {
                error("Found ${criticalCount} critical and ${highCount} high severity issues")
            }
        }
    }
}
```

## Filtering Results

To focus on specific severity levels:

```bash
# Show only critical findings
python3 f5_security_auditor.py --config-file bigip.conf --severity critical

# Process JSON output with jq
python3 f5_security_auditor.py --config-file bigip.conf --format json | \
  jq '.findings.critical'
```

## Automation Scripts

### Bash Script for Regular Audits

```bash
#!/bin/bash
# audit_f5.sh

CONFIG_DIR="/path/to/configs"
REPORT_DIR="/path/to/reports"
DATE=$(date +%Y%m%d_%H%M%S)

for config in ${CONFIG_DIR}/*.conf; do
    device=$(basename "$config" .conf)
    echo "Auditing ${device}..."
    
    python3 f5_security_auditor.py \
        --config-file "$config" \
        --output "${REPORT_DIR}/${device}_${DATE}.json" \
        --format json
done

echo "Audit completed. Reports saved to ${REPORT_DIR}"
```

## Troubleshooting

### Issue: Configuration file not found

**Solution**: Verify the file path and ensure you have read permissions:

```bash
ls -l /path/to/config.conf
```

### Issue: Empty or no findings

**Possible causes**:

- Configuration file is incomplete
- Configuration is already secure (good!)
- File format not recognized

**Solution**: Verify the configuration file contains standard F5 TMSH output

### Issue: Too many false positives

**Solution**: Review the context of each finding. Some warnings may not apply to your specific environment. Consider:

- Your organization’s security policies
- Compensating controls in place
- Environment-specific requirements

## Best Practices

1. **Regular Audits**: Run audits at least monthly or after any configuration change
1. **Version Control**: Store both configurations and audit reports in version control
1. **Trend Analysis**: Track findings over time to measure security posture improvement
1. **Automated Remediation**: Use findings to generate remediation tasks automatically
1. **Integration**: Integrate with your SIEM or ticketing system for workflow automation

## Getting Help

- **Issues**: Report bugs at https://github.com/yourusername/Learning-Firewall-Security/issues
- **Questions**: Start a discussion in the GitHub Discussions tab
- **Documentation**: Check README.md for detailed information

## Next Steps

After running your first audit:

1. Review all critical and high findings
1. Prioritize remediation based on risk
1. Implement fixes in a test environment first
1. Validate fixes with another audit
1. Deploy to production following change management procedures
1. Schedule regular recurring audits

Happy auditing! 🔒
