# Security Advisory: SQL Injection in webapp-auth

**CVE ID:** CVE-2024-1235  
**Package:** webapp-auth  
**Ecosystem:** npm  
**Severity:** Critical  
**CVSS Score:** 9.8  
**Published:** January 20, 2024

## Executive Summary

A critical SQL injection vulnerability has been identified in the `webapp-auth` package affecting versions 2.0.0 through 2.3.0. This vulnerability allows attackers to execute arbitrary SQL commands through the authentication query builder, potentially leading to complete database compromise, data exfiltration, and authentication bypass.

## Vulnerability Details

### Description

The `webapp-auth` package constructs SQL queries using string concatenation with user-controlled input in the authentication flow. The library fails to use parameterized queries or proper input sanitization, allowing attackers to inject malicious SQL code that is executed directly against the database.

### Affected Versions

| Version Range | Status | Fixed Version |
|--------------|--------|---------------|
| >= 2.0.0 < 2.3.1 | Vulnerable | 2.3.1 |
| < 2.0.0 | Not affected | - |
| >= 2.3.1 | Safe | - |

### Attack Vector

An attacker can exploit this vulnerability by submitting specially crafted input in authentication fields (username, email, etc.) that includes SQL injection payloads. The malicious SQL code is then executed when the authentication query is processed.

### Vulnerable Code Example

```javascript
const db = require('./database');
const crypto = require('crypto');

class AuthService {
  async authenticateUser(username, password) {
    // VULNERABLE: Direct string concatenation in SQL query
    const query = `
      SELECT id, username, email, password_hash 
      FROM users 
      WHERE username = '${username}' 
      AND active = 1
    `;
    
    const result = await db.query(query);
    
    if (result.rows.length === 0) {
      throw new Error('Invalid credentials');
    }
    
    const user = result.rows[0];
    const passwordHash = crypto.createHash('sha256')
      .update(password + user.salt)
      .digest('hex');
    
    if (passwordHash !== user.password_hash) {
      throw new Error('Invalid credentials');
    }
    
    return user;
  }
}
```

**Attack Payload Examples:**

1. **Authentication Bypass:**
   ```
   Username: admin' OR '1'='1' --
   Password: anything
   ```

2. **Data Exfiltration:**
   ```
   Username: admin' UNION SELECT id, username, email, password_hash FROM users WHERE '1'='1
   ```

3. **Database Schema Discovery:**
   ```
   Username: admin' UNION SELECT null, null, null, table_name FROM information_schema.tables --
   ```

### Impact

- **Authentication Bypass:** Attackers can log in as any user without knowing the password
- **Data Exfiltration:** Complete database contents can be extracted
- **Data Manipulation:** Attackers can modify, delete, or insert data
- **Privilege Escalation:** Database administrator privileges may be compromised
- **System Compromise:** In some configurations, SQL injection can lead to remote code execution

### CVSS Breakdown

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network | Exploitable remotely via API |
| Attack Complexity | Low | No special conditions required |
| Privileges Required | None | No authentication needed |
| User Interaction | None | No user interaction required |
| Scope | Changed | Can affect entire database |
| Confidentiality | Critical | Complete data exposure |
| Integrity | Critical | Complete data modification |
| Availability | High | Can delete or corrupt data |

## Remediation

### Immediate Actions

1. **Upgrade immediately** to version 2.3.1 or later:
   ```bash
   npm install webapp-auth@latest
   ```

2. **Audit your codebase** for any custom authentication logic that might have similar issues

3. **Review database logs** for signs of SQL injection attempts

### Fixed Code Example

```javascript
const db = require('./database');
const crypto = require('crypto');

class AuthService {
  async authenticateUser(username, password) {
    // FIXED: Use parameterized queries
    const query = `
      SELECT id, username, email, password_hash, salt
      FROM users 
      WHERE username = $1 
      AND active = 1
    `;
    
    // Input validation
    if (!username || typeof username !== 'string' || username.length > 100) {
      throw new Error('Invalid username format');
    }
    
    const result = await db.query(query, [username]);
    
    if (result.rows.length === 0) {
      // Use generic error message to prevent user enumeration
      throw new Error('Invalid credentials');
    }
    
    const user = result.rows[0];
    const passwordHash = crypto.createHash('sha256')
      .update(password + user.salt)
      .digest('hex');
    
    if (passwordHash !== user.password_hash) {
      throw new Error('Invalid credentials');
    }
    
    return user;
  }
}
```

### Additional Security Measures

1. **Input Validation:** Implement strict input validation and length limits
2. **Least Privilege:** Database user should have minimal required permissions
3. **Prepared Statements:** Always use parameterized queries or prepared statements
4. **Error Handling:** Avoid exposing database errors to users
5. **Web Application Firewall (WAF):** Deploy WAF rules to detect SQL injection patterns

### Remediation Timeline

| Date | Action |
|------|--------|
| 2024-01-15 | Vulnerability discovered during security audit |
| 2024-01-17 | Vendor notified |
| 2024-01-20 | CVE assigned and advisory published |
| 2024-01-20 | Fixed version 2.3.1 released |
| 2024-01-27 | Critical patch deadline (7 days) |

## Testing for SQL Injection

### Manual Testing

```bash
# Test authentication endpoint
curl -X POST https://example.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1", "password": "test"}'
```

### Automated Testing

Use tools like SQLMap or implement automated security testing in your CI/CD pipeline.

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 - A03:2021 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [webapp-auth GitHub Repository](https://github.com/example/webapp-auth)
- [CVE-2024-1235 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1235)

## Credits

This vulnerability was discovered by independent security researcher and reported through responsible disclosure.

