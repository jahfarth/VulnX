"""Intentionally minimal local HTTP fixture, not a vulnerable production app.
Default mode serves only a fixed HTML response. No local files or directory listings.
--expose-test-fixtures mode serves clearly synthetic, fake sensitive files so the
VulnX exposure checks can be demonstrated and verified locally. Every value in that
mode is invented placeholder content, never a real credential.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_PAGE = b'<h1>VulnX local demo fixture</h1><p>This page intentionally omits the checked response headers for a configuration-check demonstration.</p>'

# Synthetic fixture content only. These are fake demonstration values, not real secrets.
SYNTHETIC_FIXTURES = {
    '/.env': b'TEST_DATABASE_PASSWORD=fake-not-real\nTEST_API_KEY=DEMO-0000-NOT-REAL\nTEST_SECRET_KEY=synthetic-fixture-value\n',
    '/.git/HEAD': b'ref: refs/heads/main\n',
    '/phpinfo.php': b'<html><head><title>phpinfo()</title></head><body><h1>PHP Version 8.1 (synthetic fixture)</h1><p>phpinfo() demonstration output - not a real PHP runtime.</p></body></html>',
}

class DemoHandler(BaseHTTPRequestHandler):
    expose_fixtures = False
    def do_GET(self):
        if self.expose_fixtures:
            if self.path == '/':
                body = BASE_PAGE
            elif self.path in SYNTHETIC_FIXTURES:
                body = SYNTHETIC_FIXTURES[self.path]
            else:
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
        else:
            body = BASE_PAGE
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--expose-test-fixtures', action='store_true',
                        help='serve synthetic fake sensitive files (/.env, /.git/HEAD, /phpinfo.php) for local exposure-check verification')
    args = parser.parse_args()
    DemoHandler.expose_fixtures = args.expose_test_fixtures
    server = ThreadingHTTPServer(('127.0.0.1', args.port), DemoHandler)
    mode = 'with synthetic test exposures' if args.expose_test_fixtures else 'fixed HTML only'
    print(f'Demo target ({mode}): http://127.0.0.1:{server.server_port} - Ctrl+C to stop', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
