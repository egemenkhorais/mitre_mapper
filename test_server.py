# test_server.py  ->  python3 test_server.py
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def _reply(self, code, body=b"ok"):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(500 if "'" in self.path else 200)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        self._reply(401, b"unauthorized")

    def log_message(self, *a):
        pass

HTTPServer(("0.0.0.0", 8764), H).serve_forever()