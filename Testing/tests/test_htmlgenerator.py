import json
import unittest
from html.parser import HTMLParser

from htmlgenerator import generate_PDF, generate_report


# ---------------------------------------------------------------------------
# Helper: extract all <pre> block text values from generated HTML
# ---------------------------------------------------------------------------

class PreBlocks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.blocks = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        if tag == "pre":
            self.current = ""

    def handle_data(self, data):
        if self.current is not None:
            self.current += data

    def handle_endtag(self, tag):
        if tag == "pre" and self.current is not None:
            self.blocks.append(self.current)
            self.current = None


def pdf_blocks(data):
    """Return the list of <pre> text blocks from generate_PDF."""
    parser = PreBlocks()
    parser.feed(generate_PDF(data))
    return parser.blocks


# ---------------------------------------------------------------------------
# generate_PDF tests (existing, unchanged expectations)
# ---------------------------------------------------------------------------

class EmptyPDFResultsTests(unittest.TestCase):
    def test_empty_result_sections(self):
        for data in (
            {},
            {"flags": [], "strace": [], "gtfo": [], "timeouts": []},
            {"flags": None, "strace": "", "gtfo": None, "timeouts": ""},
        ):
            with self.subTest(data=data):
                self.assertEqual(
                    pdf_blocks({"/example/binary": data}), ["No results available"] * 4
                )

    def test_nonempty_results_remain_and_escaped(self):
        data = {
            "flags": [{"string": "<flag>", "severity": "low"}],
            "strace": ["trace"],
            "gtfo": ["match"],
            "timeouts": ["timeout"],
        }
        self.assertEqual(
            pdf_blocks({"/example/binary": data}),
            ["<flag> (low)\n", "trace", "match", "timeout"],
        )
        self.assertIn("&lt;flag&gt;", generate_PDF({"/example/binary": data}))
        self.assertNotIn(
            "No results available", generate_PDF({"/example/binary": data})
        )

    def test_mixed_sections_and_multiple_binaries(self):
        self.assertEqual(
            pdf_blocks({"/a": {"strace": ["trace"]}, "/b": {"gtfo": ["match"]}}),
            [
                "No results available",
                "trace",
                "No results available",
                "No results available",
                "No results available",
                "No results available",
                "match",
                "No results available",
            ],
        )

    def test_no_binaries(self):
        self.assertIn("No results available", generate_PDF({}))


# ---------------------------------------------------------------------------
# generate_report (interactive HTML) tests — covers Issue #7
# ---------------------------------------------------------------------------

class ReportTimeoutTests(unittest.TestCase):
    """Verify that timeout data is embedded in the interactive HTML report."""

    def _embedded_data(self, b_exp):
        """
        The report embeds all binary data as JSON inside a
        <script id="all-data" type="application/json"> element so the JS
        render function can read it.  We parse that blob directly rather
        than trying to exercise the JS engine.
        """
        html = generate_report(b_exp)
        # Locate the JSON payload between the script tags
        start_marker = 'type="application/json">'
        end_marker = "</script>"
        start = html.index(start_marker) + len(start_marker)
        end = html.index(end_marker, start)
        return json.loads(html[start:end])

    def test_timeout_data_present_in_embedded_json(self):
        """Timeout value must appear in the embedded JSON data blob."""
        b_exp = {"/usr/bin/find": {"strings": [], "strace": [], "flags": [], "gtfo": [], "timeouts": "timeout"}}
        data = self._embedded_data(b_exp)
        self.assertEqual(data["/usr/bin/find"]["timeouts"], "timeout")

    def test_timeout_array_preserved_in_embedded_json(self):
        """Array-style timeout values must be preserved as-is."""
        b_exp = {"/usr/bin/env": {"strings": [], "strace": [], "flags": [], "gtfo": [], "timeouts": ["timeout", "timeout"]}}
        data = self._embedded_data(b_exp)
        self.assertEqual(data["/usr/bin/env"]["timeouts"], ["timeout", "timeout"])

    def test_no_timeout_preserved_in_embedded_json(self):
        """Empty timeouts must not silently disappear from the embedded JSON."""
        b_exp = {"/usr/bin/ls": {"strings": [], "strace": [], "flags": [], "gtfo": [], "timeouts": []}}
        data = self._embedded_data(b_exp)
        self.assertEqual(data["/usr/bin/ls"]["timeouts"], [])

    def test_report_contains_timeouts_key_in_json(self):
        """The word 'timeouts' must appear in the embedded JSON for every binary."""
        b_exp = {"/usr/bin/ping": {"timeouts": "timeout"}}
        html = generate_report(b_exp)
        # The JSON blob must include the key
        self.assertIn('"timeouts"', html)

    def test_report_structure_contains_select_and_results(self):
        """Basic smoke test: report must have a binary selector and a results div."""
        b_exp = {"/usr/bin/sudo": {"strings": [], "strace": [], "flags": [], "gtfo": [], "timeouts": []}}
        html = generate_report(b_exp)
        self.assertIn('id="binary-select"', html)
        self.assertIn('id="results"', html)

    def test_report_generated_for_multiple_binaries(self):
        """All binaries must appear as <option> elements in the selector."""
        b_exp = {
            "/usr/bin/alpha": {"timeouts": "timeout"},
            "/usr/bin/beta": {"timeouts": []},
        }
        html = generate_report(b_exp)
        self.assertIn("alpha", html)
        self.assertIn("beta", html)


if __name__ == "__main__":
    unittest.main()
