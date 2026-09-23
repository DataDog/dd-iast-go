import http.server, sys, os
out = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def _ok(self, body=b'{}'):
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if self.path.startswith('/info'):
            return self._ok(b'{"endpoints":["/v0.4/traces"],"client_drop_p0s":false}')
        self._ok()
    def do_PUT(self): self.do_POST()
    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        data = self.rfile.read(n) if n else b''
        if 'traces' in self.path:
            with open(out, 'ab') as f: f.write(data + b'\n==TRACE==\n')
        self._ok(b'{"rate_by_service":{}}')
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
