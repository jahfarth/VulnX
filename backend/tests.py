"""Local tests. Run from backend: python -m unittest -v tests"""
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import db
from app.main import app
from app.scanner import validate_loopback_target

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        if self.path == '/protected':
            self.send_header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'")
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        self.wfile.write(b'local fixture')
    def log_message(self, *args): pass

class ExposedHandler(BaseHTTPRequestHandler):
    """Serves clearly synthetic fake sensitive files; 404 for everything else."""
    FIXTURES = {
        '/.env': b'TEST_DATABASE_PASSWORD=fake-not-real\nTEST_API_KEY=DEMO-0000-NOT-REAL\n',
        '/.git/HEAD': b'ref: refs/heads/main\n',
        '/phpinfo.php': b'<html><title>phpinfo()</title><h1>PHP Version 8.1 (synthetic fixture)</h1></html>',
    }
    def do_GET(self):
        if self.path in self.FIXTURES or self.path == '/':
            body = self.FIXTURES.get(self.path, b'<h1>fixture root</h1>')
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
    def log_message(self, *args): pass

class NotFoundHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header('Content-Length', '0')
        self.end_headers()
    def log_message(self, *args): pass

class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.exposed = ThreadingHTTPServer(('127.0.0.1', 0), ExposedHandler)
        cls.notfound = ThreadingHTTPServer(('127.0.0.1', 0), NotFoundHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread2 = threading.Thread(target=cls.exposed.serve_forever, daemon=True)
        cls.thread3 = threading.Thread(target=cls.notfound.serve_forever, daemon=True)
        cls.thread.start(); cls.thread2.start(); cls.thread3.start()
        cls.target = f'http://127.0.0.1:{cls.server.server_port}'
        cls.exposed_target = f'http://127.0.0.1:{cls.exposed.server_port}'
        cls.notfound_target = f'http://127.0.0.1:{cls.notfound.server_port}'
    @classmethod
    def tearDownClass(cls):
        for srv, thr in ((cls.server, cls.thread), (cls.exposed, cls.thread2), (cls.notfound, cls.thread3)):
            srv.shutdown(); srv.server_close(); thr.join()
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dbpatch = patch.object(db, 'DB_PATH', Path(self.temp.name) / 'test.sqlite3')
        self.dbpatch.start()
        self.client = TestClient(app)
        self.client.__enter__()
    def tearDown(self):
        self.client.__exit__(None,None,None)
        self.dbpatch.stop(); self.temp.cleanup()
    def test_health(self):
        self.assertEqual(self.client.get('/api/health').json()['status'], 'ok')
    def test_unreachable_target_does_not_save(self):
        s = socket.socket(); s.bind(('127.0.0.1',0)); port = s.getsockname()[1]; s.close()
        r = self.client.post('/api/scans', json={'target':f'http://127.0.0.1:{port}'})
        self.assertEqual(r.status_code,400)
        self.assertIn('Start its web server',r.json()['detail'])
        self.assertEqual(self.client.get('/api/scans').json(), [])
    def test_scan_save_reload(self):
        r = self.client.post('/api/scans', json={'target':self.target})
        self.assertEqual(r.status_code,200)
        data = r.json()
        self.assertEqual(data['total_findings'],5)
        self.assertTrue(all(f['severity'] in ('Low','Informational') for f in data['findings']))
        self.assertTrue(all(f['priority']=='P4 - Low' for f in data['findings']))
        self.assertEqual(len(self.client.get('/api/scans').json()),1)
        self.assertEqual(len(self.client.get(f'/api/scans/{data["id"]}').json()['findings']),5)
    def test_protected_headers_not_reported_missing(self):
        data = self.client.post('/api/scans',json={'target':self.target+'/protected'}).json()
        self.assertEqual([f['title'] for f in data['findings']],['Target uses HTTP rather than HTTPS'])
    def test_reject_external_and_invalid_targets(self):
        for target in ['http://example.com','http://192.168.1.1','file:///tmp/test','http://a:b@127.0.0.1','http://127.0.0.1:bad']:
            with self.subTest(target=target):
                self.assertEqual(self.client.post('/api/scans',json={'target':target}).status_code,400)
    def test_simulated_demo_is_separate_and_persisted(self):
        data = self.client.post('/api/demos').json()
        self.assertEqual(data['assessment_kind'],'simulated')
        self.assertEqual(data['status'],'Simulated')
        self.assertEqual({f['severity'] for f in data['findings']},{'High','Critical'})
        self.assertTrue(all(f['title'].startswith('SIMULATED:') for f in data['findings']))
        saved = self.client.get(f'/api/scans/{data["id"]}').json()
        self.assertEqual(saved['assessment_kind'],'simulated')
        self.assertEqual(self.client.get('/api/scans').json()[0]['assessment_kind'],'simulated')

    def test_exposed_files_detected_with_redacted_evidence(self):
        data = self.client.post('/api/scans', json={'target': self.exposed_target}).json()
        by_title = {f['title']: f for f in data['findings']}
        env = by_title.get('Exposed environment configuration file (.env)')
        git = by_title.get('Exposed Git repository metadata')
        php = by_title.get('Exposed PHP debug information page (phpinfo)')
        self.assertIsNotNone(env); self.assertIsNotNone(git); self.assertIsNotNone(php)
        self.assertEqual(env['severity'], 'High')
        self.assertEqual(git['severity'], 'High')
        self.assertEqual(php['severity'], 'Medium')
        # key names are reported, secret values are never reproduced
        self.assertIn('TEST_DATABASE_PASSWORD', env['evidence'])
        self.assertIn('redacted', env['evidence'])
        all_evidence = ' '.join(f['evidence'] for f in data['findings'])
        self.assertNotIn('fake-not-real', all_evidence)
        self.assertNotIn('DEMO-0000-NOT-REAL', all_evidence)
        self.assertIn('ref: refs/heads/main', git['evidence'])

    def test_no_exposure_findings_when_paths_404(self):
        data = self.client.post('/api/scans', json={'target': self.notfound_target}).json()
        for f in data['findings']:
            self.assertNotIn('Exposed', f['title'])

    def test_catch_all_route_is_not_reported_as_exposure(self):
        # The basic Handler returns the same body for every path; probes must not fire.
        data = self.client.post('/api/scans', json={'target': self.target}).json()
        for f in data['findings']:
            self.assertNotIn('Exposed', f['title'])

    def test_missing_scan(self):
        self.assertEqual(self.client.get('/api/scans/999').status_code,404)

if __name__ == '__main__': unittest.main()
