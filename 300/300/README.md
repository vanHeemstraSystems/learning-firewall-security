# 300 - 💡 Quick Start

```bash
# Clone your repository
git clone https://github.com/vanHeemstraSystems/learning-firewall-security.git
cd learning-firewall-security
```

## 100 - Create a virtual environment for Python

See [README.md](./100/README.md)

## 200 - Next Steps

```bash
# Test with sample configuration
python3 f5_security_auditor.py --config-file sample_bigip_config.conf

# Generate JSON report
python3 f5_security_auditor.py --config-file sample_bigip_config.conf --output audit.json --format json
```