import copy
import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from haproxy_studio.core import Engine, Conflict, mask, unmask, sections
from haproxy_studio.settings import DEFAULTS, executable, load
from haproxy_studio.web import Application
VALID=b'global\n    maxconn 100\ndefaults\n    mode http\n    timeout connect 5s\n    timeout client 5s\n    timeout server 5s\nfrontend entry\n    bind 127.0.0.1:18080\n    default_backend app\nbackend app\n    server web 127.0.0.1:18081 check\n'
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.file=self.root/'haproxy.cfg';self.file.write_bytes(VALID)
        self.extra=self.root/'extra';self.extra.mkdir()
        self.settings=copy.deepcopy(DEFAULTS);self.settings.update(config_file=str(self.file),extra_config_dir=str(self.extra),state_dir=str(self.root/'state'),haproxy_binary=executable('auto'),read_only=False)
        self.engine=Engine(self.settings)
    def tearDown(self):self.tmp.cleanup()
    def test_secret_and_legacy_byte_roundtrip(self):
        raw=VALID+b'# legacy: \xf2\n    stats auth admin:private-value\n';content,hidden=mask(raw)
        self.assertNotIn('private-value',content);self.assertEqual(raw,unmask(content,hidden))
        with self.assertRaises(ValueError):unmask(content.replace(next(iter(hidden)),''),hidden)
    def test_extra_file_conflict(self):
        revision=self.engine.snapshot()[1];(self.extra/'add.cfg').write_text('# changed\n')
        with self.assertRaises(Conflict):self.engine.preview(VALID.decode(),revision)
    def test_failed_reload_restores_original(self):
        before,revision=self.engine.snapshot();draft=dict(raw=VALID+b'# changed\n',revision=revision,reason='edit')
        results=[subprocess.CompletedProcess([],1,b'',b''),subprocess.CompletedProcess([],0,b'',b''),subprocess.CompletedProcess([],0,b'',b'')]
        with patch.object(self.engine,'validate',return_value=dict(ok=True)),patch.object(self.engine,'command',side_effect=results):
            with self.assertRaisesRegex(ValueError,'Старый файл восстановлен'):self.engine.apply(draft)
        self.assertEqual(before,self.file.read_bytes());self.assertEqual(1,len(list((self.engine.state/'backups').glob('*/haproxy.cfg'))))
    def test_external_edit_prevents_apply(self):
        revision=self.engine.snapshot()[1];self.file.write_bytes(VALID+b'# external\n')
        with self.assertRaises(Conflict):self.engine.apply(dict(raw=VALID,revision=revision,reason='edit'))
        self.assertTrue(self.file.read_bytes().endswith(b'# external\n'))
    def test_read_only_never_runs_validation(self):
        self.settings['read_only']=True
        with patch.object(self.engine,'command') as command:
            with self.assertRaises(ValueError):self.engine.validate(VALID)
            command.assert_not_called()
    def test_real_haproxy_validation(self):
        if not self.settings['haproxy_binary']:self.skipTest('HAProxy not installed')
        self.assertTrue(self.engine.validate(VALID)['ok'])
        result=self.engine.validate(VALID+b'    invalid-option private-diagnostic\n')
        self.assertFalse(result['ok']);self.assertNotIn('private-diagnostic',result['output']);self.assertEqual([],list(self.root.glob('.studio-check-*')))
    def test_backup_path_traversal_denied(self):
        with self.assertRaises(ValueError):self.engine.preview(None,self.engine.snapshot()[1],'../../secret')
    def test_runtime_failure_does_not_claim_zero(self):
        self.settings['runtime_socket']=str(self.root/'missing');data=self.engine.overview()
        self.assertIsNone(data['info']['CurrConns']);self.assertTrue(data['warning']);self.assertEqual([],data['rows'])
    def test_insecure_remote_origin_denied(self):
        file=self.root/'config.json';file.write_text(json.dumps(dict(public_url='http://example.org')))
        with self.assertRaises(ValueError):load(file)
    def test_shell_command_string_denied(self):
        file=self.root/'config.json';file.write_text(json.dumps(dict(reload_command='systemctl reload haproxy')))
        with self.assertRaises(ValueError):load(file)
    def test_distro_executable_detection(self):
        with patch('shutil.which',return_value='/usr/sbin/haproxy'):self.assertEqual('/usr/sbin/haproxy',executable('auto'))
    def test_comments_not_parsed_as_live_servers(self):
        data=sections(VALID+b'#backend old\n#    server ignored 127.0.0.1:1\n')
        self.assertEqual(['entry'],[s['name'] for s in data if s['type']=='frontend']);self.assertEqual('web',data[-1]['servers'][0]['name'])
    def test_http_authentication_csrf_origin_and_logout(self):
        self.file.write_bytes(VALID+b'    stats auth admin:private-value\n')
        app=Application(self.settings);server=ThreadingHTTPServer(('127.0.0.1',0),app.handler());thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        cookie='';csrf=''
        def request(path,data=None,origin='http://127.0.0.1:9130',with_csrf=True):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            headers={'Host':'127.0.0.1:9130','Origin':origin,'Cookie':cookie,'Content-Type':'application/json'}
            if with_csrf:headers['X-CSRF-Token']=csrf
            conn.request('POST' if data is not None else 'GET','/haproxy-admin/api/'+path,json.dumps(data) if data is not None else None,headers)
            response=conn.getresponse();body=json.loads(response.read());set_cookie=response.getheader('Set-Cookie');status=response.status;conn.close();return status,body,set_cookie
        try:
            self.assertEqual(401,request('config')[0])
            self.assertEqual(403,request('login',{},origin='https://evil.example')[0])
            password=(app.engine.state/'initial-password').read_text().strip();status,data,set_cookie=request('login',dict(username='admin',password=password))
            self.assertEqual(200,status);self.assertIn('HttpOnly',set_cookie);self.assertIn('SameSite=Strict',set_cookie);cookie=set_cookie.split(';')[0];csrf=data['csrf']
            status,data,_=request('config');self.assertEqual(200,status);self.assertNotIn('private-value',data['content'])
            self.assertEqual(403,request('preview',{},with_csrf=False)[0]);self.assertEqual(200,request('logout',{})[0]);self.assertEqual(401,request('config')[0])
            for _ in range(10):self.assertEqual(401,request('login',dict(username='admin',password='wrong'))[0])
            self.assertEqual(429,request('login',dict(username='admin',password='wrong'))[0])
        finally:server.shutdown();server.server_close();thread.join()
if __name__=='__main__':unittest.main()
