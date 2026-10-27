# PHP2Shell Research Lab v0.1

Defensive, offline PHP version assessor for CVE-2026-109618 and CVE-2026-109619.

## Usage

```bash
python3 app.py 8.3.35
python3 app.py 8.3.36
python3 -m unittest -v
```

The tool does not send network requests, exploit PHP, or execute OS commands. It cannot confirm whether a particular remote server is vulnerable or whether RCE is possible. Distribution security backports can make version-only checks inaccurate. Confirm the PHP version used by the web server, not just the CLI.

## Roadmap

- Offline PHP source-diff summaries
- ASan/GDB log import for isolated experiments
- Child-process monitoring log analysis
- JSON reports
