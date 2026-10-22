
import ipaddress
import json
import socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "purpose": "Encourages browsers to use HTTPS.",
        "recommendation": "Configure HSTS after HTTPS is correctly set up.",
    },
    "Content-Security-Policy": {
        "purpose": "Controls which resources a webpage can load.",
        "recommendation": "Define a CSP suited to the website.",
    },
    "X-Content-Type-Options": {
        "purpose": "Helps prevent MIME-type sniffing.",
        "recommendation": "Consider setting this to nosniff.",
    },
    "X-Frame-Options": {
        "purpose": "Helps control whether a page can be framed.",
        "recommendation": "Consider this header or CSP frame-ancestors.",
    },
}

MAX_REDIRECTS = 5
TIMEOUT_SECONDS = 10


def validate_public_https_url(url):
    """Accept HTTPS URLs that resolve only to public IP addresses."""
    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() != "https":
            return False, "Only HTTPS URLs are accepted."

        if not parsed.hostname:
            return False, "The URL must include a hostname."

        if parsed.username or parsed.password:
            return False, "Embedded credentials are not allowed."

        if parsed.port not in (None, 443):
            return False, "Only the standard HTTPS port (443) is allowed."

        hostname = parsed.hostname.rstrip(".").lower()

        if hostname == "localhost" or hostname.endswith(".localhost"):
            return False, "Localhost destinations are not allowed."

        if hostname.endswith(".local"):
            return False, "Local network hostnames are not allowed."

        try:
            addresses = [ipaddress.ip_address(hostname)]
        except ValueError:
            results = socket.getaddrinfo(
                hostname, 443, type=socket.SOCK_STREAM
            )
            addresses = [
                ipaddress.ip_address(result[4][0])
                for result in results
            ]

        if not addresses:
            return False, "The hostname has no usable IP addresses."

        if any(not address.is_global for address in addresses):
            return False, "Non-public IP destinations are not allowed."

        return True, "URL accepted."

    except (ValueError, OSError):
        return False, "The URL is invalid or its hostname could not be resolved."


def fetch_public_website(url):
    """Fetch a page while checking each redirect destination."""
    current_url = url

    with requests.Session() as session:
        session.trust_env = False

        for redirect_count in range(MAX_REDIRECTS + 1):
            valid, message = validate_public_https_url(current_url)

            if not valid:
                raise ValueError(message)

            response = session.get(
                current_url,
                timeout=TIMEOUT_SECONDS,
                allow_redirects=False,
                stream=True,
                headers={
                    "User-Agent": "EducationalSecurityHeaderChecker/1.0"
                },
            )

            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                response.close()

                if not location:
                    raise ValueError(
                        "Redirect response has no Location header."
                    )

                if redirect_count == MAX_REDIRECTS:
                    raise ValueError("Too many redirects.")

                current_url = urljoin(current_url, location)
                continue

            return response

    raise ValueError("Could not complete the website request.")


def analyze_headers(response):
    """Build structured results for each security header."""
    results = {}
    present_count = 0

    for header, details in SECURITY_HEADERS.items():
        value = response.headers.get(header)
        is_present = bool(value)

        if is_present:
            present_count += 1

        results[header] = {
            "present": is_present,
            "value": value,
            "purpose": details["purpose"],
            "recommendation": (
                None if is_present else details["recommendation"]
            ),
        }

    total = len(SECURITY_HEADERS)

    return {
        "headers": results,
        "headers_present": present_count,
        "headers_missing": total - present_count,
        "header_presence_score": round(present_count / total * 100),
        "score_note": (
            "Measures header presence only; it does not prove website security."
        ),
    }


def save_reports(report_data):
    """Save the same report as readable text and structured JSON."""
    header_results = report_data["analysis"]["headers"]

    lines = [
        "=" * 55,
        "WEBSITE SECURITY HEADER CHECKER",
        "=" * 55,
        f"Website: {report_data['website']}",
        f"HTTP Status Code: {report_data['http_status']}",
        f"Report time (UTC): {report_data['report_time_utc']}",
        "",
        "SECURITY HEADER ANALYSIS",
        "-" * 55,
    ]

    for header, details in header_results.items():
        if details["present"]:
            lines.extend([
                "",
                f"[PRESENT] {header}",
                f"Value: {details['value']}",
            ])
        else:
            lines.extend([
                "",
                f"[MISSING] {header}",
                f"Purpose: {details['purpose']}",
                f"Recommendation: {details['recommendation']}",
            ])

    analysis = report_data["analysis"]

    lines.extend([
        "",
        "-" * 55,
        "SUMMARY",
        "-" * 55,
        f"Headers present: {analysis['headers_present']}/4",
        f"Headers missing: {analysis['headers_missing']}/4",
        f"Header presence score: {analysis['header_presence_score']}/100",
        "",
        "NOTE: This score measures header presence only.",
        "It does not prove that a website is secure.",
    ])

    with open("security_report.txt", "w", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")

    with open("security_report.json", "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4, ensure_ascii=False)
        file.write("\n")


def check_website(url):
    url = url.strip()

    valid, message = validate_public_https_url(url)

    if not valid:
        print(f"\nURL rejected: {message}")
        return

    response = None

    try:
        response = fetch_public_website(url)

        report_data = {
            "website": response.url,
            "http_status": response.status_code,
            "report_time_utc": datetime.now(timezone.utc).isoformat(),
            "analysis": analyze_headers(response),
        }

        save_reports(report_data)

        analysis = report_data["analysis"]

        print("\n" + "=" * 50)
        print("WEBSITE SECURITY HEADER CHECKER")
        print("=" * 50)
        print(f"Website: {report_data['website']}")
        print(f"HTTP Status Code: {report_data['http_status']}")
        print(
            f"Headers present: {analysis['headers_present']}/"
            f"{len(SECURITY_HEADERS)}"
        )
        print(
            f"Headers missing: {analysis['headers_missing']}/"
            f"{len(SECURITY_HEADERS)}"
        )
        print(
            f"Header presence score: "
            f"{analysis['header_presence_score']}/100"
        )
        print("\nReports saved:")
        print("- security_report.txt")
        print("- security_report.json")
        print("\nReminder: header presence alone does not prove security.")

    except (requests.RequestException, ValueError) as error:
        print("\nCould not safely check the website.")
        print(f"Reason: {error}")

    except OSError as error:
        print("\nCould not save the reports.")
        print(f"Reason: {error}")

    finally:
        if response is not None:
            response.close()


if __name__ == "__main__":
    website_url = input("Enter a public HTTPS website URL: ")
    check_website(website_url)
