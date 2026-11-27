import copy
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import threading
import unittest
from haproxy_studio.healthcheck import check
from haproxy_studio.settings import DEFAULTS

class HealthcheckTests(unittest.TestCase):
    def test_custom_port_and_base_path_use_local_listener(self):
        seen=[]
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path);self.send_response(200);self.end_headers();self.wfile.write(b'{"ok":true}')
            def log_message(self,*args):pass
        with ThreadingHTTPServer(('127.0.0.1',0),Handler) as server:
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            try:
                settings=copy.deepcopy(DEFAULTS);settings.update(bind='0.0.0.0',port=server.server_port,base_path='/custom-studio')
                check(settings);self.assertEqual(['/custom-studio/api/health'],seen)
            finally:server.shutdown();worker.join(5)
    def test_200_with_wrong_payload_is_not_a_healthy_studio(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'{"ok":false}')
            def log_message(self,*args):pass
        with ThreadingHTTPServer(('127.0.0.1',0),Handler) as server:
            worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
            try:
                settings=copy.deepcopy(DEFAULTS);settings.update(port=server.server_port)
                with self.assertRaises(ValueError):check(settings)
            finally:server.shutdown();worker.join(5)
