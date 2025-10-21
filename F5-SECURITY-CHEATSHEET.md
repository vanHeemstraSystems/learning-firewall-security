# F5 BIG-IP Security Cheat Sheet

Quick reference for F5 BIG-IP security operations, commands, and best practices.

## Table of Contents

- [Common CLI Commands](#common-cli-commands)
- [SSL/TLS Security](#ssltls-security)
- [Virtual Server Security](#virtual-server-security)
- [iRule Security](#irule-security)
- [Access Control](#access-control)
- [Monitoring & Logging](#monitoring--logging)
- [Hardening Checklist](#hardening-checklist)

-----

## Common CLI Commands

### System Information

```bash
# Show system version
tmsh show sys version

# Show system hardware
tmsh show sys hardware

# Show license
tmsh show sys license

# Show running configuration
tmsh list

# Show management IP
tmsh list sys management-ip
```

### Configuration Management

```bash
# Save configuration
tmsh save sys config

# Load configuration
tmsh load sys config

# Create UCS backup
tmsh save sys ucs /var/local/ucs/backup.ucs

# Restore from UCS
tmsh load sys ucs /var/local/ucs/backup.ucs

# Show configuration differences
tmsh show sys config-diff
```

### SSL/TLS Commands

```bash
# List SSL profiles
tmsh list ltm profile client-ssl
tmsh list ltm profile server-ssl

# Show SSL certificate details
tmsh list sys file ssl-cert

# Show SSL key details
tmsh list sys file ssl-key

# Test SSL connection
openssl s_client -connect <vip>:443 -servername hostname
```

### Virtual Server Commands

```bash
# List all virtual servers
tmsh list ltm virtual

# Show virtual server details
tmsh show ltm virtual <vs_name>

# Show virtual server statistics
tmsh show ltm virtual <vs_name> statistics

# Enable/disable virtual server
tmsh modify ltm virtual <vs_name> enabled
tmsh modify ltm virtual <vs_name> disabled
```

### Pool Commands

```bash
# List pools
tmsh list ltm pool

# Show pool status
tmsh show ltm pool

# Show pool member status
tmsh show ltm pool <pool_name> members

# Enable/disable pool member
tmsh modify ltm pool <pool_name> members <ip>:<port> state user-down
tmsh modify ltm pool <pool_name> members <ip>:<port> state user-up
```

-----

## SSL/TLS Security

### Recommended Cipher Suites (TLS 1.2+)

```
ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256
```

### Create Secure SSL Profile

```bash
tmsh create ltm profile client-ssl secure_profile {
    cert mycert.crt
    key mycert.key
    ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
    options { no-sslv2 no-sslv3 no-tlsv1 no-tlsv1.1 }
    unclean-shutdown disabled
}
```

### SSL Hardening Commands

```bash
# Disable weak protocols
tmsh modify ltm profile client-ssl <profile> options add { no-sslv2 no-sslv3 no-tlsv1 no-tlsv1.1 }

# Set strong ciphers
tmsh modify ltm profile client-ssl <profile> ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"

# Enable strict SNI matching
tmsh modify ltm profile client-ssl <profile> strict-sni enabled
```

### Certificate Management

```bash
# Import certificate
tmsh install sys crypto cert <cert_name> from-local-file /path/to/cert.crt

# Import key
tmsh install sys crypto key <key_name> from-local-file /path/to/key.key

# Check certificate expiration
tmsh list sys file ssl-cert <cert_name> | grep "expiration"

# Create self-signed cert (testing only!)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout selfsigned.key -out selfsigned.crt
```

-----

## Virtual Server Security

### Create Secure HTTPS Virtual Server

```bash
tmsh create ltm virtual secure_vs {
    destination 10.1.1.100:443
    ip-protocol tcp
    pool secure_pool
    profiles add {
        secure_ssl_profile { context clientside }
        tcp { }
        http { }
    }
    source-address-translation { type automap }
    persist { cookie { default yes } }
    rules { security_headers_irule }
}
```

### Apply Security Policies

```bash
# Add WAF policy
tmsh modify ltm virtual <vs_name> policies add { asm_policy }

# Add access policy (APM)
tmsh modify ltm virtual <vs_name> access-policy <apm_policy>

# Add rate limiting
tmsh modify ltm virtual <vs_name> rate-limit 1000

# Set connection limits
tmsh modify ltm virtual <vs_name> connection-limit 10000
```

-----

## iRule Security

### Security Headers iRule

```tcl
when HTTP_RESPONSE {
    # HSTS
    HTTP::header insert Strict-Transport-Security "max-age=31536000; includeSubDomains"
    
    # XSS Protection
    HTTP::header insert X-XSS-Protection "1; mode=block"
    
    # Content Type Options
    HTTP::header insert X-Content-Type-Options "nosniff"
    
    # Frame Options
    HTTP::header insert X-Frame-Options "DENY"
    
    # CSP
    HTTP::header insert Content-Security-Policy "default-src 'self'"
}
```

### HTTP to HTTPS Redirect

```tcl
when HTTP_REQUEST {
    if { [TCP::local_port] == 80 } {
        HTTP::redirect "https://[HTTP::host][HTTP::uri]"
    }
}
```

### IP Whitelist iRule

```tcl
when CLIENT_ACCEPTED {
    if { not ([class match [IP::client_addr] equals allowed_ips]) } {
        reject
    }
}
```

### Rate Limiting iRule

```tcl
when HTTP_REQUEST {
    set client_ip [IP::client_addr]
    set request_count [table lookup -notouch $client_ip]
    
    if { $request_count eq "" } {
        table set $client_ip 1 60 60
    } else {
        if { $request_count > 100 } {
            HTTP::respond 429 content "Rate limit exceeded"
            return
        }
        table incr $client_ip
    }
}
```

-----

## Access Control

### Port Lockdown (Management Access)

```bash
# Allow only SSH and HTTPS from specific network
tmsh modify net self-allow defaults { none }
tmsh modify net self-allow defaults add { tcp:22 tcp:443 }

# Add specific source IPs
tmsh create security firewall rule-list management_access {
    rules add {
        allow_admin {
            action accept
            ip-protocol tcp
            destination { ports add { 22 443 } }
            source { addresses add { 10.0.0.0/24 } }
        }
        deny_all {
            action drop
        }
    }
}
```

### User Management

```bash
# Create user with limited privileges
tmsh create auth user security_auditor {
    partition-access add { Common { role auditor } }
    shell tmsh
}

# Change password
tmsh modify auth user admin password <new_password>

# Enable password policy
tmsh modify auth password-policy policy-enforcement enabled
tmsh modify auth password-policy min-length 12
tmsh modify auth password-policy required-uppercase 1
tmsh modify auth password-policy required-lowercase 1
tmsh modify auth password-policy required-numeric 1
tmsh modify auth password-policy required-special 1
```

### Configure Remote Authentication

```bash
# LDAP configuration
tmsh create auth ldap system-auth {
    servers add { ldap.example.com }
    bind-dn "cn=admin,dc=example,dc=com"
    bind-pw <password>
    search-base-dn "dc=example,dc=com"
}

# RADIUS configuration
tmsh create auth radius system-auth {
    servers add {
        primary {
            server radius.example.com
            secret <shared_secret>
        }
    }
}
```

-----

## Monitoring & Logging

### Configure Remote Logging

```bash
# Create remote syslog destination
tmsh create sys log-config destination remote-syslog remote_siem {
    remote-high-speed-log siem_pool
}

# Create pool for SIEM
tmsh create ltm pool siem_pool {
    members add { 10.0.0.50:514 }
    monitor tcp
}

# Configure log publisher
tmsh create sys log-config publisher siem_publisher {
    destinations add { remote_siem }
}
```

### Enable Security Logging

```bash
# Enable authentication logging
tmsh modify auth audit enabled

# Enable SSL handshake logging
tmsh modify ltm profile client-ssl <profile> alert-timeout 10

# Enable traffic logging
tmsh modify ltm virtual <vs_name> ip-protocol-logging enabled
```

### Monitoring Commands

```bash
# View real-time logs
tail -f /var/log/ltm

# View security events
tail -f /var/log/security

# View audit logs
tail -f /var/log/audit

# Check for failed login attempts
grep "authentication failed" /var/log/audit

# Monitor connection table
tmsh show sys connection

# View traffic statistics
tmsh show ltm virtual <vs_name> statistics
```

-----

## Hardening Checklist

### Critical (Do First)

- [ ] Change default admin password
- [ ] Restrict management access (port lockdown)
- [ ] Disable unused services (HTTP management, telnet, FTP)
- [ ] Enable TLS 1.2+ only, disable SSLv2/v3, TLS 1.0/1.1
- [ ] Configure strong cipher suites
- [ ] Remove default SSL certificates

### High Priority

- [ ] Implement centralized authentication (LDAP/RADIUS)
- [ ] Enable audit logging
- [ ] Configure remote syslog to SIEM
- [ ] Set up regular configuration backups
- [ ] Enable SNMPv3 (disable v1/v2c)
- [ ] Configure session timeouts
- [ ] Implement rate limiting

### Medium Priority

- [ ] Add security headers via iRules
- [ ] Configure health monitors for all pools
- [ ] Implement HTTP to HTTPS redirects
- [ ] Set up certificate expiration monitoring
- [ ] Configure connection limits
- [ ] Enable SYN flood protection
- [ ] Document all custom configurations

### Best Practices

- [ ] Review iRules for security issues
- [ ] Implement least privilege access
- [ ] Regular security audits
- [ ] Keep system updated
- [ ] Monitor for security advisories
- [ ] Test in lab before production
- [ ] Document all changes
- [ ] Regular vulnerability scanning

-----

## Common Vulnerabilities

### CVE References

- **CVE-2020-5902**: RCE via TMUI (patch immediately!)
- **CVE-2021-22986**: iControl REST RCE
- **CVE-2022-1388**: iControl REST auth bypass

### Security Advisory Locations

- F5 Security Advisories: https://support.f5.com/csp/article/K4602
- F5 CVE Search: https://support.f5.com/csp/article/K9970

### Quick Vulnerability Check

```bash
# Check F5 version
tmsh show sys version

# Check for vulnerable components
tmsh list sys db provision.* value

# Review security bulletins
curl -s https://support.f5.com/csp/article/K4602 | grep -i "critical"
```

-----

## Emergency Response

### Incident Response Commands

```bash
# Block malicious IP immediately
tmsh create net address-list blocked_ips addresses add { 1.2.3.4/32 }

# Disable compromised virtual server
tmsh modify ltm virtual <vs_name> disabled

# Capture traffic for analysis
tcpdump -i <interface> -w /var/tmp/capture.pcap host <suspicious_ip>

# Review active connections
tmsh show sys connection | grep <suspicious_ip>

# Kill specific connection
tmsh delete sys connection <connection_id>

# Generate diagnostics
qkview -f /var/tmp/diagnostics.qkview
```

### Forensics

```bash
# Check for unauthorized changes
tmsh show sys config-diff

# Review recent logins
last | head -20

# Check for suspicious processes
ps aux | grep -v "\[.*\]"

# Review command history
cat ~/.bash_history

# Check cron jobs
crontab -l
ls -la /etc/cron.*
```

-----

## Quick Reference Tables

### Port Numbers

|Port|Service      |Protocol|Secure Alternative|
|----|-------------|--------|------------------|
|22  |SSH          |TCP     |-                 |
|80  |HTTP         |TCP     |443 (HTTPS)       |
|161 |SNMP         |UDP     |SNMPv3            |
|443 |HTTPS        |TCP     |-                 |
|8443|Management UI|TCP     |-                 |

### Default Credentials (Change These!)

|Account|Default Password|Action Required   |
|-------|----------------|------------------|
|admin  |admin           |Change immediately|
|root   |default         |Change immediately|

### Cipher Suite Security Levels

|Cipher  |Security|Use  |
|--------|--------|-----|
|AES-GCM |✅ Strong|Yes  |
|ChaCha20|✅ Strong|Yes  |
|RC4     |❌ Broken|Never|
|DES/3DES|❌ Weak  |Never|
|MD5     |❌ Broken|Never|

-----

**Note**: Always test changes in a lab environment before applying to production!

For more detailed information, refer to:

- [F5 DevCentral](https://devcentral.f5.com)
- [F5 Support Portal](https://support.f5.com)
- [F5 Security Advisories](https://support.f5.com/csp/article/K4602)
