# Security Advisory: Cross-Site Request Forgery (CSRF) in api-client

**CVE ID:** CVE-2024-1239  
**Package:** api-client  
**Ecosystem:** pip (Python)  
**Severity:** High  
**CVSS Score:** 7.8  
**Published:** February 20, 2024

## Executive Summary

A Cross-Site Request Forgery (CSRF) vulnerability has been identified in the `api-client` Python package affecting versions 1.0.0 through 1.3.9. This vulnerability allows attackers to perform unauthorized actions on behalf of authenticated users by tricking them into submitting malicious requests. The package fails to implement proper CSRF token validation in API endpoints, making it vulnerable to state-changing request forgery attacks.

## Vulnerability Details

### Description

The `api-client` package does not implement CSRF protection mechanisms for state-changing operations (POST, PUT, DELETE requests). The library relies solely on session cookies for authentication without validating the origin of requests, allowing attackers to craft malicious requests that are executed when an authenticated user visits a malicious website. CSRF attacks exploit the trust that a site has in a user's browser, causing the browser to automatically include session cookies with requests, even when those requests originate from a different site.

### Affected Versions

| Version Range | Status | Fixed Version |
|--------------|--------|---------------|
| >= 1.0.0 < 1.4.0 | Vulnerable | 1.4.0 |
| < 1.0.0 | Not affected | - |
| >= 1.4.0 | Safe | - |

### Attack Vector

An attacker creates a malicious website that automatically submits a request to the vulnerable API endpoint when a victim visits the site. Since the victim's browser automatically includes session cookies with the request, the API processes it as an authenticated request from the legitimate user. Common attack scenarios include:

1. **Hidden form submission**: A malicious website contains a hidden form that automatically submits when the page loads, changing the victim's email address or password
2. **JavaScript-based attacks**: Malicious JavaScript code makes fetch requests to the vulnerable API, performing actions on behalf of the authenticated user
3. **Image tag attacks**: An `<img>` tag with a GET request URL can trigger state-changing operations (though less common with modern REST APIs)

### Vulnerable Code Example

```python
from flask import Flask, request, session, jsonify
from api_client import APIClient

app = Flask(__name__)
app.secret_key = 'your-secret-key'

@app.route('/api/user/email', methods=['POST'])
def update_email():
    # VULNERABLE: No CSRF token validation
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    new_email = request.json.get('email')
    client = APIClient()
    result = client.update_user_email(session['user_id'], new_email)
    return jsonify({'success': True, 'email': new_email})
```

**Attack Scenario:**

A malicious website could contain code that automatically submits a request to change the victim's email address. When the victim visits the malicious site while logged into the vulnerable application, their browser automatically includes the session cookie, making the request appear legitimate. The attacker can then use password reset functionality to gain control of the account.

### Impact

- **Unauthorized Actions:** Attackers can perform actions on behalf of users
- **Data Modification:** Email addresses, passwords, and profile data can be changed
- **Account Takeover:** Password changes can lead to complete account compromise
- **Financial Impact:** If payment information is accessible, financial transactions can be initiated
- **Reputation Damage:** Malicious actions can damage user trust

### CVSS Breakdown

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network | Requires network access |
| Attack Complexity | Low | Simple HTML/JavaScript required |
| Privileges Required | None | No authentication needed for attacker |
| User Interaction | Required | Victim must visit malicious site |
| Scope | Changed | Can affect user accounts |
| Confidentiality | Low | Limited direct data exposure |
| Integrity | High | Can modify user data |
| Availability | None | No direct availability impact |

## Remediation

### Immediate Actions

1. **Upgrade immediately** to version 1.4.0 or later:
   ```bash
   pip install --upgrade api-client
   ```

2. **Implement CSRF tokens** in all state-changing endpoints

3. **Review and audit** all API endpoints for CSRF protection

### Fixed Code Example

The fixed version implements CSRF token validation:

```python
from flask import Flask, request, session, jsonify
from flask_wtf.csrf import CSRFProtect
from api_client import APIClient
import secrets

app = Flask(__name__)
app.secret_key = 'your-secret-key'
csrf = CSRFProtect(app)

def generate_csrf_token():
    """Generate CSRF token for session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token():
    """Validate CSRF token from request"""
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return False
    return True

@app.route('/api/user/email', methods=['POST'])
def update_email():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # FIXED: Validate CSRF token
    if not validate_csrf_token():
        return jsonify({'error': 'Invalid CSRF token'}), 403
    
    new_email = request.json.get('email')
    if not is_valid_email(new_email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    client = APIClient()
    result = client.update_user_email(session['user_id'], new_email)
    return jsonify({'success': True, 'email': new_email})
```

### Additional Security Measures

1. **SameSite Cookie Attribute:** Set cookies with `SameSite=Strict` to prevent cross-site cookie transmission
2. **Origin/Referer Validation:** Validate the `Origin` or `Referer` headers to ensure requests come from expected domains
3. **Double Submit Cookie Pattern:** Use a cookie value that must also be present in a request header
4. **Custom Headers:** Require custom headers for AJAX requests (browsers enforce same-origin policy for custom headers)

### CSRF Protection Methods Comparison

| Method | Effectiveness | Implementation Complexity | Notes |
|--------|--------------|--------------------------|-------|
| CSRF Tokens | High | Medium | Most common and reliable |
| SameSite Cookies | High | Low | Browser support required |
| Origin/Referer Check | Medium | Low | Can be bypassed in some cases |
| Double Submit Cookie | High | Medium | Good alternative to tokens |
| Custom Headers | Medium | Low | Works for AJAX requests |

### Remediation Timeline

| Date | Action |
|------|--------|
| 2024-02-15 | Vulnerability discovered during security audit |
| 2024-02-17 | Vendor notified |
| 2024-02-20 | CVE assigned and advisory published |
| 2024-02-20 | Fixed version 1.4.0 released |
| 2024-03-06 | Recommended patch deadline (14 days) |

## Testing for CSRF

Security testing should verify that state-changing requests without valid CSRF tokens are rejected. Test cases should include:
- POST/PUT/DELETE requests without CSRF tokens (should fail)
- Requests with invalid CSRF tokens (should fail)
- Requests with valid CSRF tokens (should succeed)
- Cross-origin requests (should be blocked or require tokens)

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 - A05:2021 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [api-client PyPI Package](https://pypi.org/project/api-client/)
- [CVE-2024-1239 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1239)

## Credits

This vulnerability was discovered by independent security researcher during a bug bounty program.
