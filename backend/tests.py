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

class AppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.target = f'http://127.0.0.1:{cls.server.server_port}'
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
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

    def test_missing_scan(self):
        self.assertEqual(self.client.get('/api/scans/999').status_code,404)

if __name__ == '__main__': unittest.main()
