# Security Advisory: Insecure Deserialization in json-parser

**CVE ID:** CVE-2024-1242  
**Package:** json-parser  
**Ecosystem:** pip (Python)  
**Severity:** High  
**CVSS Score:** 7.2  
**Published:** March 10, 2024

## Executive Summary

An insecure deserialization vulnerability has been identified in the `json-parser` Python package affecting versions 3.0.0 through 3.2.0. This vulnerability allows attackers to execute arbitrary code or perform object injection attacks by providing malicious serialized data. The package uses unsafe deserialization methods that can instantiate arbitrary objects and execute code during the deserialization process.

## Vulnerability Details

### Description

The `json-parser` package deserializes JSON data using methods that allow object instantiation and code execution. When processing user-controlled JSON data, the library can be tricked into instantiating malicious objects or executing code through specially crafted payloads that exploit Python's object serialization mechanisms. The vulnerability stems from the use of unsafe functions like `eval()`, `exec()`, `pickle.loads()`, or `yaml.load()` instead of their safe counterparts.

### Affected Versions

| Version Range | Status | Fixed Version |
|--------------|--------|---------------|
| >= 3.0.0 < 3.2.1 | Vulnerable | 3.2.1 |
| < 3.0.0 | Not affected | - |
| >= 3.2.1 | Safe | - |

### Attack Vector

An attacker can exploit this vulnerability by providing malicious JSON payloads that, when deserialized, trigger object instantiation or code execution. This can occur through various Python serialization mechanisms including `pickle`, `yaml.load()`, or custom deserialization logic that uses `eval()` or similar unsafe methods. The attack is particularly dangerous because the malicious code executes with the full privileges of the application process.

### Vulnerable Code Example

```python
import json
import yaml
from json_parser import JSONParser

class DataProcessor:
    def process_json_data(self, json_string):
        # VULNERABLE: Using eval for "enhanced" JSON parsing
        try:
            data = eval(f"json.loads({repr(json_string)})")
            return self.handle_data(data)
        except:
            data = json.loads(json_string)
            return self.handle_data(data)
    
    def process_config(self, config_string):
        # VULNERABLE: Using yaml.load instead of yaml.safe_load
        config = yaml.load(config_string, Loader=yaml.Loader)
        return self.apply_config(config)
    
    def process_pickled_data(self, pickled_data):
        # VULNERABLE: Unpickling user-controlled data
        data = pickle.loads(pickled_data)
        return self.process_data(data)
```

**Attack Payload Examples:**

Attackers can craft payloads that execute arbitrary code, such as:
- **Code execution via eval**: Payloads containing Python code that gets executed through `eval()` or `exec()`
- **Object injection via Pickle**: Serialized Python objects that execute code when unpickled, such as calling `os.system()` or `subprocess.Popen()`
- **YAML code execution**: YAML payloads using special tags like `!!python/object/apply` that execute code during deserialization
- **Data exfiltration**: Code that reads environment variables, configuration files, or database credentials and sends them to attacker-controlled servers

### Impact

- **Remote Code Execution:** Attackers can execute arbitrary commands on the server
- **Data Exfiltration:** Sensitive data, environment variables, and files can be stolen
- **System Compromise:** Complete control over the application server
- **Privilege Escalation:** Code execution with application privileges
- **Lateral Movement:** Compromised server can be used to attack other systems

### CVSS Breakdown

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network | Exploitable remotely via API |
| Attack Complexity | Medium | Requires knowledge of serialization format |
| Privileges Required | None | No authentication needed |
| User Interaction | None | No user interaction required |
| Scope | Changed | Can affect entire system |
| Confidentiality | High | Can exfiltrate sensitive data |
| Integrity | High | Can modify system state |
| Availability | High | Can cause service disruption |

## Remediation

### Immediate Actions

1. **Upgrade immediately** to version 3.2.1 or later:
   ```bash
   pip install --upgrade json-parser
   ```

2. **Audit all deserialization** code in your application

3. **Review and restrict** data processing endpoints

### Fixed Code Example

The fixed version uses safe deserialization methods with validation:

```python
import json
import yaml

class DataProcessor:
    def process_json_data(self, json_string):
        # FIXED: Use safe JSON parsing only
        try:
            if len(json_string) > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError("Input too large")
            
            # FIXED: Use standard json.loads (safe)
            data = json.loads(json_string)
            
            # Validate data structure
            if not self.validate_data_structure(data):
                raise ValueError("Invalid data structure")
            
            return self.handle_data(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
    
    def process_config(self, config_string):
        # FIXED: Use yaml.safe_load instead of yaml.load
        try:
            config = yaml.safe_load(config_string)
            
            if not isinstance(config, dict):
                raise ValueError("Config must be a dictionary")
            
            # Whitelist allowed configuration keys
            allowed_keys = ['timeout', 'retries', 'max_connections']
            filtered_config = {
                k: v for k, v in config.items() 
                if k in allowed_keys
            }
            
            return self.apply_config(filtered_config)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
    
    def validate_data_structure(self, data):
        """Validate data structure to prevent object injection"""
        if not isinstance(data, (dict, list, str, int, float, bool, type(None))):
            return False
        
        # Check for dangerous keys
        dangerous_keys = ['__class__', '__init__', '__new__', '__reduce__']
        
        def check_dict(d):
            for key, value in d.items():
                if any(dk in str(key).lower() for dk in dangerous_keys):
                    return False
                if isinstance(value, dict):
                    if not check_dict(value):
                        return False
                elif isinstance(value, list):
                    if not check_list(value):
                        return False
            return True
        
        def check_list(l):
            for item in l:
                if isinstance(item, dict):
                    if not check_dict(item):
                        return False
                elif isinstance(item, list):
                    if not check_list(item):
                        return False
            return True
        
        if isinstance(data, dict):
            return check_dict(data)
        elif isinstance(data, list):
            return check_list(data)
        
        return True
```

### Additional Security Measures

1. **Input Validation:** Validate all input data before deserialization, implement strict schema validation, use whitelisting for allowed data structures
2. **Size Limits:** Enforce maximum input size limits to prevent resource exhaustion attacks
3. **Schema Validation:** Use JSON schema validation libraries to ensure data matches expected structure
4. **Never Use Pickle for User Data:** Never use `pickle.loads()` with user-controlled input; use JSON or other safe formats instead
5. **Sandboxing:** If custom deserialization is necessary, use restricted execution environments with limited APIs

### Deserialization Safety Comparison

| Method | Safety | Use Case | Notes |
|--------|--------|----------|-------|
| json.loads() | Safe | Standard JSON | Recommended for most cases |
| yaml.safe_load() | Safe | YAML configs | Use instead of yaml.load() |
| pickle.loads() | Unsafe | Internal only | Never use with user input |
| eval() | Unsafe | Never | Avoid completely |
| exec() | Unsafe | Never | Avoid completely |

### Remediation Timeline

| Date | Action |
|------|--------|
| 2024-03-05 | Vulnerability discovered during code review |
| 2024-03-07 | Vendor notified |
| 2024-03-10 | CVE assigned and advisory published |
| 2024-03-10 | Fixed version 3.2.1 released |
| 2024-03-24 | Recommended patch deadline (14 days) |

## Testing for Insecure Deserialization

Security testing should verify that malicious payloads containing executable code or object injection attempts are rejected. Test cases should include:
- Payloads with `eval()` or `exec()` calls
- Pickle payloads with malicious `__reduce__` methods
- YAML payloads with code execution tags
- Payloads attempting to access dangerous properties like `__class__` or `__reduce__`

All such payloads should be rejected with appropriate error messages, and no code should be executed.

## References

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [Python Pickle Security](https://docs.python.org/3/library/pickle.html#restricting-globals)
- [json-parser PyPI Package](https://pypi.org/project/json-parser/)
- [CVE-2024-1242 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1242)

## Credits

This vulnerability was discovered by independent security researcher during a security audit.
