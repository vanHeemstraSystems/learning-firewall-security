# 300 - 💡 Quick Start

```bash
# Clone your repository
git clone https://github.com/yourusername/Learning-Firewall-Security.git
cd Learning-Firewall-Security

# Test with sample configuration
python3 f5_security_auditor.py --config-file sample_bigip_config.conf

# Generate JSON report
python3 f5_security_auditor.py --config-file sample_bigip_config.conf --output audit.json --format json
```