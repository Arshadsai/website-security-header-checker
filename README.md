# Website Security Header Checker

A Python-based cybersecurity tool that checks public HTTPS websites for the presence of common HTTP security headers and generates reports in TXT and JSON formats.

## Overview

HTTP security headers help website owners configure browser-side protections. This tool retrieves a website's HTTP response, examines four security headers, identifies missing headers, and provides basic recommendations.

This project was developed to practise Python programming, HTTP requests, security-header analysis, input validation, automated testing, and report generation.

## Features

- Accepts public HTTPS website URLs.
- Checks four commonly used security headers.
- Identifies present and missing headers.
- Provides recommendations for missing headers.
- Handles HTTP redirects with destination validation.
- Rejects HTTP URLs and several non-public destinations.
- Generates human-readable TXT reports.
- Generates structured JSON reports.
- Includes automated unit tests.

## Security Headers Checked

| Header | Purpose |
|---|---|
| Strict-Transport-Security | Encourages browsers to use HTTPS. |
| Content-Security-Policy | Restricts the resources a webpage can load. |
| X-Content-Type-Options | Helps prevent MIME-type sniffing. |
| X-Frame-Options | Helps control whether a page can be embedded in a frame. |

## Technologies Used

- Python 3
- Requests
- JSON
- Socket and IP address validation
- Python `unittest`

## Project Structure

```text
website_security_header_checker/
├── checker.py
├── test_checker.py
├── security_report.txt
├── security_report.json
└── README.md
```

The report files are generated when the checker runs. They may be excluded from version control if they are only demonstration outputs.

## Installation

**1. Install Python 3.11 or a compatible Python 3 version.**

**2. Install the dependency:**

```bash
python -m pip install requests
```

**3. Run the checker:**

```bash
python checker.py
```

Enter a public HTTPS URL when prompted, for example:

```text
https://example.com
```

## Running Tests

Run the automated tests using:

```bash
python -m unittest -v test_checker.py
```

The test suite covers header analysis, URL validation, connection-error handling, and redirect handling. The current test suite contains eight tests.

## Generated Reports

The tool generates two files:

- `security_report.txt` — a readable summary of the website's HTTP status, header findings, and recommendations.
- `security_report.json` — structured data containing the website information, report timestamp, header results, and summary metrics.

The header-presence score represents only the proportion of checked headers that are present. It is **not a comprehensive website security rating**.

## Limitations

- Checks only four security headers.
- Header presence does not guarantee that a header is configured correctly.
- Does not perform penetration testing, vulnerability scanning, or a complete security audit.
- DNS validation followed by a separate HTTP request does not fully eliminate DNS-rebinding or server-side request forgery risks.
- Intended for local educational use; it is not hardened for deployment as a public scanning service.

## Future Improvements

- Add more security-header checks.
- Improve report summaries and recommendations.
- Add a user-friendly web interface.
- Add more automated tests for edge cases.
- Improve network-level protections before considering any public deployment.

## Disclaimer

This project is intended for educational purposes. Use it only to assess websites you own or have permission to test. It does not guarantee that a website is secure.
