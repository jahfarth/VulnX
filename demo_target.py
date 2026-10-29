"""Intentionally minimal local HTTP fixture, not a vulnerable production app.
Only a fixed HTML response is served. No local files or directory listings.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<h1>VulnX local demo fixture</h1><p>This page intentionally omits the checked response headers for a configuration-check demonstration.</p>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), DemoHandler)
    print(f'Demo target: http://127.0.0.1:{server.server_port} - Ctrl+C to stop', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
