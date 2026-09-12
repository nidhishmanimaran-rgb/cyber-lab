from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "lab_session=demo")
        self.end_headers()
        self.wfile.write(
            b"""<!doctype html>
<html><head><title>CCC Vulnerable Lab</title></head>
<body>
<h1>Cyber Command Center Local WebSec Lab</h1>
<p>This local-only lab intentionally omits several security headers for defensive scanner training.</p>
<form><input name="demo" value=""><button>Submit</button></form>
</body></html>"""
        )


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8000), LabHandler)
    print("Local vulnerable lab running at http://127.0.0.1:8000")
    server.serve_forever()
