"""
Exfil listener — the attacker's collection endpoint, run locally so the demo can
SHOW arrival vs non-arrival. Cerberus OFF -> the keys print here. Cerberus ON ->
this terminal stays empty.

Run standalone:  python servers/exfil_server.py    (listens on :9099)
Or import ``received`` for the in-process demo.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer

received: list[str] = []   # in-process demo inspects this


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode(errors="replace")
        received.append(body)
        print("\n*** EXFIL SERVER RECEIVED ***\n" + body + "\n*****************************\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):  # quiet
        pass


def collect(payload: str) -> None:
    """In-process sink used by the demo when no real HTTP listener is running."""
    received.append(payload)
    print("\n*** EXFIL SERVER RECEIVED ***\n" + payload + "\n*****************************\n")


if __name__ == "__main__":
    print("exfil listener on http://127.0.0.1:9099/collect")
    HTTPServer(("127.0.0.1", 9099), _Handler).serve_forever()
