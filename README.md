# Security Log Analyzer

A Python tool that parses server log files to detect suspicious activity and potential security threats.

## Features

- **Apache/Nginx access log parsing** (combined format)
- **Linux auth log parsing** (SSH brute-force detection)
- **Attack detection**: SQL injection, XSS, directory traversal, command injection, path probing, scanner/bot activity
- **Brute-force detection**: identifies IPs with excessive requests
- **Traffic analysis**: top IPs, paths, status codes
- **JSON export** for integration with other tools

## Installation

```bash
git clone https://github.com/SebMRX/log-analyzer.git
cd log-analyzer
```

No external dependencies — uses only Python standard library.

## Usage

```bash
# Analyze Apache/Nginx access log
python log_analyzer.py /var/log/apache2/access.log

# Analyze with more results
python log_analyzer.py access.log --top 20

# Analyze SSH auth log
python log_analyzer.py /var/log/auth.log --format auth

# Export report as JSON
python log_analyzer.py access.log --json report.json

# Try with included sample log
python log_analyzer.py sample_access.log
```

## Detected Attack Types

| Attack Type | Examples |
|-------------|----------|
| SQL Injection | `UNION SELECT`, `OR 1=1`, `DROP TABLE` |
| XSS | `<script>`, `onerror=`, `javascript:` |
| Directory Traversal | `../`, `/etc/passwd`, `%2e%2e` |
| Command Injection | `; cat /etc/passwd`, backtick execution |
| Path Probing | `.env`, `.git/`, `wp-admin`, `phpmyadmin` |
| Scanner Activity | Nikto, sqlmap, Nmap, DirBuster user agents |
| Brute Force | High request count + auth failures |

## Example Output

```
=================================================================
  SECURITY LOG ANALYSIS REPORT
=================================================================

  [Summary]
  Total entries      : 15,234
  Unique IPs         : 342
  Attack types found : 4
  Suspicious events  : 127

  [Detected Attacks]

    ▸ SQL Injection
      Events: 45  |  Unique IPs: 3
      - [172.16.0.5] /search?q=1'+OR+1=1--

    ▸ Path Probing
      Events: 38  |  Unique IPs: 12
      - [10.0.0.50] /.env
=================================================================
```

## License

MIT License
