# Log Analyzer

parses apache/nginx access logs and linux auth logs to find suspicious activity

## detects

- sql injection attempts
- xss attacks
- directory traversal
- command injection
- path probing (.env, .git, wp-admin etc)
- scanner tools (nikto, sqlmap, nmap useragents)
- brute force (high request count from same ip)
- failed ssh logins

## usage

```
python log_analyzer.py access.log
python log_analyzer.py /var/log/auth.log --format auth
python log_analyzer.py access.log --top 20
python log_analyzer.py access.log --json report.json
```

theres a sample log file included to test with:
```
python log_analyzer.py sample_access.log
```

no dependencies, python3 only
