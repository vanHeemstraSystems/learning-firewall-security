# 300 - Next Steps

Lets continue now that we have the virtual environment set up using the recommended method!

Your command line should start with (venv), indicating that you are working inside your virtual environment.

```bash
# Test with sample configuration
python3 f5_security_auditor.py --config-file sample_bigip_config.conf

# Generate JSON report
python3 f5_security_auditor.py --config-file sample_bigip_config.conf --output audit.json --format json
```