# Security Advisory: Path Traversal in data-processor

**CVE ID:** CVE-2024-1236  
**Package:** data-processor  
**Ecosystem:** npm  
**Severity:** High  
**CVSS Score:** 8.1  
**Published:** February 1, 2024

## Executive Summary

A critical path traversal vulnerability has been identified in the `data-processor` package affecting versions 1.2.0 through 1.5.1. This vulnerability allows attackers to read, write, or delete files outside the intended directory by manipulating file paths with directory traversal sequences (e.g., `../`). This can lead to unauthorized access to sensitive files, data exfiltration, and potential system compromise.

## Vulnerability Details

### Description

The `data-processor` package processes file operations without properly validating and sanitizing user-supplied file paths. The library fails to prevent directory traversal attacks, allowing attackers to escape the intended directory boundaries and access arbitrary files on the filesystem. Path traversal attacks exploit the fact that file path validation is insufficient, enabling attackers to navigate to parent directories using sequences like `../` (Unix/Linux) or `..\\` (Windows).

### Affected Versions

| Version Range | Status | Fixed Version |
|--------------|--------|---------------|
| >= 1.2.0 < 1.5.2 | Vulnerable | 1.5.2 |
| < 1.2.0 | Not affected | - |
| >= 1.5.2 | Safe | - |

### Attack Vector

An attacker can exploit this vulnerability by providing file paths containing directory traversal sequences in API requests. The application processes these paths without proper validation, allowing access to files outside the intended directory. Common attack patterns include:

- **Reading sensitive files**: Accessing system configuration files like `/etc/passwd` on Linux or `C:\\Windows\\System32\\config\\sam` on Windows
- **Reading application secrets**: Accessing environment files, database configuration, or API keys stored in application directories
- **Writing malicious files**: Placing backdoor scripts or malicious code in application directories
- **Deleting critical files**: Removing configuration files or application data to cause service disruption

### Vulnerable Code Example

```javascript
const fs = require('fs');
const path = require('path');

class DataProcessor {
  constructor(baseDir) {
    this.baseDir = baseDir;
  }

  async readFile(userPath) {
    // VULNERABLE: Direct path concatenation without validation
    const filePath = path.join(this.baseDir, userPath);
    const content = await fs.promises.readFile(filePath, 'utf8');
    return content;
  }
}

// Usage in API endpoint
app.get('/api/files/:filename', async (req, res) => {
  const processor = new DataProcessor('/app/uploads');
  const content = await processor.readFile(req.params.filename);
  res.send(content);
});
```

**Attack Payload Examples:**

Attackers can exploit this by submitting paths like:
- `../../../etc/passwd` - Accesses system password file
- `../../config/database.yml` - Accesses application configuration
- `..\\..\\..\\windows\\system32\\config\\sam` - Accesses Windows SAM file (Windows systems)

### Impact

- **Confidentiality:** Sensitive files (passwords, API keys, configuration) can be read
- **Integrity:** Critical files can be modified or deleted
- **Availability:** System files can be deleted, causing service disruption
- **System Compromise:** In some cases, can lead to remote code execution if malicious files are written

### CVSS Breakdown

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network | Exploitable remotely via API |
| Attack Complexity | Low | Simple path manipulation required |
| Privileges Required | None | No authentication needed |
| User Interaction | None | No user interaction required |
| Scope | Changed | Can affect entire filesystem |
| Confidentiality | High | Can read sensitive files |
| Integrity | High | Can modify or delete files |
| Availability | High | Can delete critical files |

## Remediation

### Immediate Actions

1. **Upgrade immediately** to version 1.5.2 or later:
   ```bash
   npm install data-processor@latest
   ```

2. **Audit file access logs** for suspicious path traversal attempts

3. **Review and restrict** file system permissions for the application user

### Fixed Code Example

The fixed version implements proper path validation to prevent directory traversal:

```javascript
class DataProcessor {
  constructor(baseDir) {
    this.baseDir = path.resolve(baseDir);
  }

  validatePath(userPath) {
    const normalizedPath = path.normalize(userPath);
    
    // Prevent directory traversal
    if (normalizedPath.includes('..')) {
      throw new Error('Invalid path: directory traversal detected');
    }
    
    const resolvedPath = path.resolve(this.baseDir, normalizedPath);
    
    // Ensure path is within base directory
    if (!resolvedPath.startsWith(this.baseDir)) {
      throw new Error('Invalid path: outside base directory');
    }
    
    return resolvedPath;
  }

  async readFile(userPath) {
    const filePath = this.validatePath(userPath);
    const stats = await fs.promises.stat(filePath);
    
    if (!stats.isFile()) {
      throw new Error('Path is not a file');
    }
    
    return await fs.promises.readFile(filePath, 'utf8');
  }
}
```

### Additional Security Measures

1. **Input Validation:** Sanitize filenames by removing path separators and restricting to allowed characters
2. **Whitelist Approach:** Maintain a list of allowed files and reject all others
3. **File System Permissions:** Run application with minimal required permissions, use chroot or containerization
4. **API Security:** Implement strict filename validation at the API layer using regex patterns

### Path Traversal Prevention Checklist

| Measure | Status | Description |
|---------|--------|-------------|
| Path normalization | ✅ | Normalize paths before processing |
| Directory traversal detection | ✅ | Check for `..` sequences |
| Path resolution validation | ✅ | Verify resolved path is within base directory |
| Whitelist validation | ⚠️ | Consider whitelisting allowed files |
| File type validation | ✅ | Ensure path points to a file, not directory |
| Permission restrictions | ⚠️ | Limit filesystem permissions |
| Input sanitization | ✅ | Sanitize user input at API layer |

### Remediation Timeline

| Date | Action |
|------|--------|
| 2024-01-28 | Vulnerability discovered during security audit |
| 2024-01-30 | Vendor notified |
| 2024-02-01 | CVE assigned and advisory published |
| 2024-02-01 | Fixed version 1.5.2 released |
| 2024-02-08 | Recommended patch deadline (7 days) |

## Testing for Path Traversal

Security testing should include attempts to access files outside the intended directory using various path traversal sequences. Common test cases include:
- Standard traversal: `../../../etc/passwd`
- Encoded traversal: `..%2F..%2F..%2Fetc%2Fpasswd`
- Windows-style: `..\\..\\..\\windows\\system32\\config\\sam`
- Double encoding: `....//....//etc/passwd`

All such attempts should be rejected with appropriate error messages.

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [data-processor GitHub Repository](https://github.com/example/data-processor)
- [CVE-2024-1236 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1236)

## Credits

This vulnerability was discovered by independent security researcher during a penetration test.
