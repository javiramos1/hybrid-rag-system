# Security Advisory: Server-Side Request Forgery (SSRF) in http-server

**CVE ID:** CVE-2024-1241  
**Package:** http-server  
**Ecosystem:** pip (Python)  
**Severity:** Medium  
**CVSS Score:** 5.3  
**Published:** March 5, 2024

## Executive Summary

A Server-Side Request Forgery (SSRF) vulnerability has been discovered in the `http-server` Python package affecting versions 0.9.0 through 0.9.7. This vulnerability allows attackers to make the server send HTTP requests to arbitrary internal or external URLs, potentially leading to information disclosure, internal network scanning, or access to internal services that should not be exposed.

## Vulnerability Details

### Description

The `http-server` package processes user-supplied URLs without proper validation, allowing attackers to specify arbitrary URLs including internal network addresses, localhost, and cloud metadata endpoints. The library fails to implement URL validation, IP address filtering, or protocol restrictions, enabling SSRF attacks. SSRF vulnerabilities are particularly dangerous in cloud environments where they can be used to access metadata services that contain sensitive credentials and configuration information.

### Affected Versions

| Version Range | Status | Fixed Version |
|--------------|--------|---------------|
| >= 0.9.0 < 0.9.8 | Vulnerable | 0.9.8 |
| < 0.9.0 | Not affected | - |
| >= 0.9.8 | Safe | - |

### Attack Vector

An attacker can exploit this vulnerability by providing a malicious URL in API requests. The server will then make HTTP requests to the specified URL, potentially accessing internal services, cloud metadata endpoints, or other restricted resources. Common attack scenarios include:

- **Internal service access**: Accessing services running on localhost or internal network addresses that should not be publicly accessible
- **Cloud metadata access**: Retrieving credentials and configuration from cloud provider metadata services (AWS, Azure, GCP)
- **Internal network scanning**: Discovering internal network topology and identifying other vulnerable services
- **Protocol abuse**: Using non-HTTP protocols like `file://` or `gopher://` to access local files or other services
- **DNS rebinding**: Exploiting DNS resolution timing to access internal IPs after initial validation

### Vulnerable Code Example

```python
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    # VULNERABLE: No URL validation
    url = request.json.get('url')
    
    if not url:
        return jsonify({'error': 'URL required'}), 400
    
    # VULNERABLE: Direct request without validation
    try:
        response = requests.get(url, timeout=10)
        return jsonify({
            'status_code': response.status_code,
            'content': response.text[:1000]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
```

**Attack Payload Examples:**

Attackers can exploit this by submitting URLs such as:
- `http://localhost:8080/admin` - Access internal admin interface
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` - Access AWS metadata service
- `http://192.168.1.1/admin` - Access internal network devices
- `file:///etc/passwd` - Attempt to read local files (if protocol not restricted)
- `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` - Access GCP metadata

### Impact

- **Information Disclosure:** Access to internal services, databases, and APIs
- **Cloud Metadata Access:** Retrieval of cloud credentials and configuration
- **Internal Network Scanning:** Discovery of internal network topology
- **Bypass Firewalls:** Access to services behind firewalls
- **Denial of Service:** Resource exhaustion through request loops

### CVSS Breakdown

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network | Exploitable remotely via API |
| Attack Complexity | Low | Simple URL manipulation required |
| Privileges Required | None | No authentication needed |
| User Interaction | None | No user interaction required |
| Scope | Changed | Can affect internal services |
| Confidentiality | Medium | Can access internal resources |
| Integrity | None | Limited modification capability |
| Availability | Low | Can cause resource exhaustion |

## Remediation

### Immediate Actions

1. **Upgrade immediately** to version 0.9.8 or later:
   ```bash
   pip install --upgrade http-server
   ```

2. **Implement URL validation** in all endpoints that process URLs

3. **Review and restrict** network access for the application

### Fixed Code Example

The fixed version implements comprehensive URL validation:

```python
from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

def is_internal_ip(ip):
    """Check if IP is internal/private"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False

def validate_url(url):
    """Validate URL to prevent SSRF"""
    if not url:
        return False, "URL is required"
    
    parsed = urlparse(url)
    
    # Only allow HTTP and HTTPS
    if parsed.scheme not in ['http', 'https']:
        return False, "Only HTTP and HTTPS protocols are allowed"
    
    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid hostname"
    
    # Resolve and check IPs
    ips = socket.gethostbyname_ex(hostname)[2]
    for ip in ips:
        if is_internal_ip(ip):
            return False, "Internal IP addresses are not allowed"
    
    # Block cloud metadata endpoints
    blocked_hosts = ['169.254.169.254', 'metadata.google.internal']
    if hostname in blocked_hosts or any(ip in blocked_hosts for ip in ips):
        return False, "Cloud metadata endpoints are blocked"
    
    return True, None

@app.route('/api/fetch', methods=['POST'])
def fetch_url():
    url = request.json.get('url')
    is_valid, error_msg = validate_url(url)
    
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=False)
        return jsonify({
            'status_code': response.status_code,
            'content': response.text[:1000]
        })
    except Exception as e:
        return jsonify({'error': 'Request failed'}), 500
```

### Additional Security Measures

1. **Network Segmentation:** Isolate application servers from internal networks, use firewalls to restrict outbound connections
2. **URL Parsing:** Use proper URL parsing libraries and reconstruct URLs to prevent injection
3. **DNS Rebinding Protection:** Resolve hostnames immediately and cache, re-validate IP on each request, use IP whitelist instead of hostname
4. **Request Limits:** Set short timeouts, disable redirects, limit response sizes
5. **Content-Type Validation:** Only allow specific content types in responses

### SSRF Prevention Checklist

| Measure | Status | Description |
|---------|--------|-------------|
| URL scheme validation | ✅ | Only allow http/https |
| IP address validation | ✅ | Block private/internal IPs |
| Hostname whitelist | ⚠️ | Consider whitelisting allowed domains |
| DNS resolution check | ✅ | Validate resolved IPs |
| Cloud metadata blocking | ✅ | Block known metadata endpoints |
| Redirect prevention | ✅ | Disable or limit redirects |
| Protocol restrictions | ✅ | Block file://, gopher://, etc. |
| Network segmentation | ⚠️ | Isolate application network |

### Remediation Timeline

| Date | Action |
|------|--------|
| 2024-03-01 | Vulnerability discovered during security testing |
| 2024-03-03 | Vendor notified |
| 2024-03-05 | CVE assigned and advisory published |
| 2024-03-05 | Fixed version 0.9.8 released |
| 2024-03-19 | Recommended patch deadline (14 days) |

## Testing for SSRF

Security testing should verify that requests to internal IPs, localhost, and cloud metadata endpoints are blocked. Test cases should include:
- Internal IP addresses (127.0.0.1, 192.168.x.x, 10.x.x.x)
- Cloud metadata endpoints (169.254.169.254, metadata.google.internal)
- Non-HTTP protocols (file://, gopher://)
- Encoded URLs and DNS rebinding attempts

All such attempts should be rejected with appropriate error messages.

## References

- [OWASP Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [PortSwigger SSRF Tutorial](https://portswigger.net/web-security/ssrf)
- [http-server PyPI Package](https://pypi.org/project/http-server/)
- [CVE-2024-1241 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1241)

## Credits

This vulnerability was discovered by the Snyk Security Research Team during automated security scanning.
