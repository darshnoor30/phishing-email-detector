# Explainable Phishing Email Detector

[![CI](https://github.com/darshnoor30/phishing-email-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/darshnoor30/phishing-email-detector/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg)](LICENSE)

An offline, explainable phishing-triage tool with a reusable Python engine, a CLI,
and a Tkinter desktop interface. Instead of returning an unexplained label, it
shows the language and URL signals that contributed to a normalized risk score.

> This is a defensive, rule-based learning project—not an email gateway, machine-
> learning classifier, or guarantee that a message is safe or malicious.

## Why it stands out

- **Explainable results:** every score includes weighted evidence and next steps.
- **URL-aware analysis:** detects IP-address hosts, cleartext HTTP, punycode,
  shorteners, suspicious top-level domains, encoded URLs, and excessive subdomains.
- **Privacy first:** analysis is deterministic, local, and uses no network requests.
- **Multiple interfaces:** use the engine as a package, from the terminal, or in a GUI.
- **Engineering hygiene:** typed code, import-safe entry points, automated tests,
  linting, CI, security guidance, and an MIT license.

## Quick start

Python 3.11 or newer is required. The detector itself uses only the standard library.

```bash
git clone https://github.com/darshnoor30/phishing-email-detector.git
cd phishing-email-detector
python main.py --text "Urgent: verify your password at http://198.51.100.8/login"
```

Analyze a saved message or return JSON:

```bash
python main.py --file examples/message.txt
python main.py --text "Your account needs verification" --json
```

Launch the desktop interface:

```bash
python gui.py
```

## Example result

```text
Risk: Critical (88/100)
Summary: Multiple high-confidence phishing indicators are present.

Indicators:
- Credential request (+26): Found credential-related language.
- Urgency pressure (+18): Found urgency language.
- IP-address link (+30): Link uses an IP address instead of a named domain.
- Cleartext HTTP link (+14): At least one link does not use HTTPS.
```

Scores are capped at 100 and grouped into Low, Medium, High, and Critical risk.
The rules favor transparent reasoning over claims of perfect detection.

## Use as a Python package

```python
from phishing_detector import analyze_email

result = analyze_email("Confirm your password at http://198.51.100.8/login")
print(result.severity, result.score)
for indicator in result.indicators:
    print(indicator.title, indicator.evidence)
```

## Quality checks

```bash
python -m pip install -r requirements-dev.txt
ruff check .
ruff format --check .
pytest
```

## Detection scope

The current engine examines social-engineering language and URL structure. It does
not parse attachments, authenticate senders with SPF/DKIM/DMARC, inspect message
headers, follow redirects, or query reputation services. Those are deliberate,
documented boundaries rather than hidden limitations.

## Responsible use

Use only with messages you are authorized to inspect. Do not click or visit URLs
found in suspicious emails. See [SECURITY.md](SECURITY.md) for vulnerability reports.

## License

Released under the [MIT License](LICENSE).
