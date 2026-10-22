
import unittest
from unittest.mock import Mock, patch, mock_open
from io import StringIO
from contextlib import redirect_stdout

import requests
import checker


class TestWebsiteSecurityHeaderChecker(unittest.TestCase):

    def make_response(self, headers=None, status_code=200, url="https://example.com/"):
        response = Mock()
        response.url = url
        response.status_code = status_code
        response.headers = headers or {}
        response.is_redirect = status_code in (301, 302, 303, 307, 308)
        response.is_permanent_redirect = status_code in (301, 308)
        return response

    @patch("builtins.open", new_callable=mock_open)
    @patch("checker.fetch_public_website")
    def test_all_headers_present(self, mock_fetch, mock_file):
        mock_fetch.return_value = self.make_response({
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })

        with redirect_stdout(StringIO()) as output:
            checker.check_website("https://example.com")

        result = output.getvalue()
        self.assertIn("Headers present: 4/4", result)
        self.assertIn("Header presence score: 100/100", result)
        mock_fetch.assert_called_once()

    @patch("builtins.open", new_callable=mock_open)
    @patch("checker.fetch_public_website")
    def test_all_headers_missing(self, mock_fetch, mock_file):
        mock_fetch.return_value = self.make_response({})

        with redirect_stdout(StringIO()) as output:
            checker.check_website("https://example.com")

        result = output.getvalue()
        self.assertIn("Headers present: 0/4", result)
        self.assertIn("Headers missing: 4/4", result)
        self.assertIn("Header presence score: 0/100", result)

    @patch("checker.fetch_public_website")
    def test_http_url_is_rejected(self, mock_fetch):
        with redirect_stdout(StringIO()) as output:
            checker.check_website("http://example.com")

        mock_fetch.assert_not_called()
        self.assertIn("URL rejected", output.getvalue())
        self.assertIn("Only HTTPS", output.getvalue())

    @patch("checker.fetch_public_website")
    def test_invalid_url_is_rejected(self, mock_fetch):
        with redirect_stdout(StringIO()) as output:
            checker.check_website("not-a-url")

        mock_fetch.assert_not_called()
        self.assertIn("URL rejected", output.getvalue())

    @patch("checker.fetch_public_website")
    def test_local_ip_is_rejected(self, mock_fetch):
        with redirect_stdout(StringIO()) as output:
            checker.check_website("https://127.0.0.1")

        mock_fetch.assert_not_called()
        self.assertIn("Non-public IP", output.getvalue())

    @patch("checker.fetch_public_website")
    def test_connection_error_is_handled(self, mock_fetch):
        mock_fetch.side_effect = requests.ConnectionError(
            "Test connection failure"
        )

        with redirect_stdout(StringIO()) as output:
            checker.check_website("https://example.com")

        self.assertIn("Could not safely check", output.getvalue())

    @patch("checker.validate_public_https_url", return_value=(True, "URL accepted."))
    @patch("checker.requests.Session")
    def test_normal_page_is_requested_once(self, mock_session_class, mock_validate):
        session = mock_session_class.return_value.__enter__.return_value
        response = self.make_response({"X-Content-Type-Options": "nosniff"})
        response.is_redirect = False
        response.is_permanent_redirect = False
        session.get.return_value = response

        result = checker.fetch_public_website("https://example.com")

        self.assertIs(result, response)
        session.get.assert_called_once()
        response.close.assert_not_called()

    @patch("checker.validate_public_https_url")
    @patch("checker.requests.Session")
    def test_rejected_redirect_destination_is_not_requested(
        self, mock_session_class, mock_validate
    ):
        session = mock_session_class.return_value.__enter__.return_value

        redirect_response = self.make_response(
            {"Location": "https://127.0.0.1"},
            status_code=302,
        )
        session.get.return_value = redirect_response

        mock_validate.side_effect = [
            (True, "URL accepted."),
            (False, "Non-public IP destinations are not allowed."),
        ]

        with self.assertRaisesRegex(ValueError, "Non-public IP"):
            checker.fetch_public_website("https://example.com")

        # Only the original destination was requested.
        session.get.assert_called_once()
        redirect_response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
