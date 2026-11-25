import copy
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from haproxy_studio.core import Engine,Conflict
from haproxy_studio.services import ServiceManager,PRESETS,clean,bindings
from haproxy_studio.certificates import upload
from haproxy_studio.settings import DEFAULTS,executable

BASE=b'global\n    maxconn 100\ndefaults\n    mode http\n    timeout connect 5s\n    timeout client 30s\n    timeout server 30s\nfrontend legacy\n    bind 127.0.0.1:18080\n    mode http\n    acl old_host hdr(host) -i legacy.example.test\n    default_backend old\nbackend old\n    mode http\n    server legacy 127.0.0.1:18081\n'

class ServicesFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not executable('auto'):raise unittest.SkipTest('HAProxy unavailable; distribution CI installs it')
        cls.crypto=tempfile.TemporaryDirectory();folder=Path(cls.crypto.name)
        if not shutil.which('openssl'):raise unittest.SkipTest('OpenSSL unavailable')
        for name in ['leaf','other']:
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(folder/(name+'.key')),'-out',str(folder/(name+'.crt')),'-days','2','-subj','/CN=app.example.test','-addext','subjectAltName=DNS:app.example.test,DNS:other.example.test'],capture_output=True,check=True)
        cls.cert=(folder/'leaf.crt').read_text();cls.key=(folder/'leaf.key').read_text();cls.other_key=(folder/'other.key').read_text()
    @classmethod
    def tearDownClass(cls):cls.crypto.cleanup()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.config=self.root/'haproxy.cfg';self.config.write_bytes(BASE);self.extra=self.root/'extra';self.extra.mkdir();self.certs=self.root/'certs';self.certs.mkdir();(self.certs/'leaf.pem').write_text(self.cert+self.key)
        self.settings=copy.deepcopy(DEFAULTS);self.settings.update(config_file=str(self.config),extra_config_dir=str(self.extra),certificate_dir=str(self.certs),state_dir=str(self.root/'state'),haproxy_binary=executable('auto'),read_only=False,runtime_socket=str(self.root/'missing.sock'))
        self.engine=Engine(self.settings);self.manager=ServiceManager(self.engine)
    def tearDown(self):self.temp.cleanup()
    def data(self,protocol='https',**changes):
        value=dict(naming='legacy',name='Проверка сервиса',protocol=protocol,domain='app.example.test',certificate='leaf.pem',backends=[dict(host='192.0.2.15',port=PRESETS[protocol][2])]);
        if protocol=='studio':
            config=self.root/'studio.json';config.write_text(json.dumps(dict(public_url='http://127.0.0.1:9130')));self.settings['_config_path']=str(config)
            value.update(backends=[dict(host='127.0.0.1',port=9130)],update_public_url=True)
        value.update(changes);return value
    def preview(self,data,action='upsert'):
        return self.manager.preview(data,self.engine.snapshot()[1],action,probe=False)
class ServicesTests(ServicesFixture):
    def test_every_preset_validates_with_installed_haproxy(self):
        if not self.settings['haproxy_binary']:self.skipTest('HAProxy not installed')
        for protocol in PRESETS:
            with self.subTest(protocol=protocol):
                result,draft=self.preview(self.data(protocol));self.assertTrue(result['ok'],result['output']);self.assertEqual(BASE,clean(draft['raw'])[0].encode())
    def test_shared_tls_certificate_and_redirect_preserve_baseline(self):
        original=BASE.replace(b'bind 127.0.0.1:18080',('bind 127.0.0.1:18443 ssl crt '+str(self.certs/'leaf.pem')).encode())
        original+=b'frontend clear\n    bind 127.0.0.1:18082\n    mode http\n    http-request redirect scheme https unless { ssl_fc }\n'
        self.config.write_bytes(original);(self.certs/'second.pem').write_text(self.cert+self.key)
        result,draft=self.preview(self.data(port=18443,http_port=18082,bind_address='127.0.0.1',certificate='second.pem'))
        self.assertTrue(result['ok'],result['output']);generated=draft['raw'].decode();self.assertIn('studio-tls-base',generated);self.assertIn('https://app.example.test:18443',generated);self.assertEqual(original,clean(draft['raw'])[0].encode())
    def test_edit_disable_and_delete_roundtrip(self):
        result,draft=self.preview(self.data('rdp',port=13389));self.assertTrue(result['ok']);self.config.write_bytes(draft['raw']);models=clean(draft['raw'])[1];model=models[0];model['backends'][0]['port']=3390
        result,draft=self.preview(model);self.assertTrue(result['ok']);self.assertIn(b':3390',draft['raw']);self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];model['enabled']=False
        result,draft=self.preview(model);self.assertTrue(result['ok']);self.assertNotIn(b'frontend studio_fe_',draft['raw']);self.config.write_bytes(draft['raw']);identifier=clean(draft['raw'])[1][0]['id'];result,draft=self.preview(dict(id=identifier),'delete');self.assertTrue(result['ok']);self.assertEqual(BASE,draft['raw'])
    def test_complete_mail_defaults_and_starttls_modes(self):
        for protocol,port in [('smtp',25),('submission',587),('smtps',465),('imap',143),('imaps',993),('pop3',110),('pop3s',995),('sieve',4190)]:
            with self.subTest(protocol=protocol):
                model=self.manager.normalize(self.data(protocol),'a'*16)
                self.assertEqual(port,model['port']);self.assertEqual(port,model['backends'][0]['port'])
                if protocol in ('smtp','submission','imap','pop3','sieve'):
                    self.assertEqual('plain',model['tls_mode'])
                    with self.assertRaises(ValueError):self.manager.normalize(self.data(protocol,tls_mode='terminate'),'a'*16)
                else:
                    self.assertEqual('passthrough',model['tls_mode'])
                    self.assertEqual('terminate',self.manager.normalize(self.data(protocol,tls_mode='terminate'),'a'*16)['tls_mode'])

    def test_existing_owned_port_is_not_probed_as_new(self):
        _,draft=self.preview(self.data('rdp',port=13389));self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];model['name']='Новое имя'
        with patch('socket.socket',side_effect=AssertionError('must not bind existing managed port')):
            result,_=self.manager.preview(model,self.engine.snapshot()[1],probe=True)
        self.assertTrue(result['ok'])
    def test_managed_block_tamper_rejected(self):
        _,draft=self.preview(self.data('http'));broken=draft['raw'].replace(b'weight 1',b'weight 2')
        with self.assertRaisesRegex(ValueError,'изменён вручную'):clean(broken)
    def test_injection_and_protocol_validation(self):
        invalid=[dict(domain='example.test\nbackend injected'),dict(backends=[dict(host='127.0.0.1;id',port=80)]),dict(port='443\nbind :1'),dict(path='/good\nhttp-request allow'),dict(allowed_ips='0.0.0.0/0\nhttp-request allow'),dict(protocol='rdp',tls_mode='terminate'),dict(protocol='smtp',tls_mode='terminate')]
        for changes in invalid:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):self.preview(self.data(**changes))
    def test_recently_closed_listener_can_be_republished(self):
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',0));listener.listen(1);port=listener.getsockname()[1]
            client=socket.create_connection(('127.0.0.1',port));accepted,_=listener.accept();accepted.close();client.recv(1);client.close()
        checked,_=self.manager.preview(self.data('tcp',port=port,bind_address='127.0.0.1'),self.engine.snapshot()[1],probe=True)
        self.assertTrue(checked['ok'])

    def test_cross_protocol_bind_conflict(self):
        with self.assertRaisesRegex(ValueError,'несовместимым'):self.preview(self.data('rdp',port=18080,bind_address='127.0.0.1'))
    def test_domain_collision_and_nonoverlapping_paths(self):
        _,draft=self.preview(self.data('http',port=18080,bind_address='127.0.0.1'));self.config.write_bytes(draft['raw'])
        with self.assertRaisesRegex(ValueError,'пересекаются'):self.preview(self.data('http',port=18080,bind_address='127.0.0.1',path='/app'))
    def test_manual_domain_root_blocked_path_extension_allowed(self):
        with self.assertRaisesRegex(ValueError,'ручными правилами'):self.preview(self.data('http',port=18080,bind_address='127.0.0.1',domain='legacy.example.test'))
        result,draft=self.preview(self.data('http',port=18080,bind_address='127.0.0.1',domain='legacy.example.test',path='/app',strip_prefix=True));self.assertTrue(result['ok']);self.assertIn(b'replace-path ^/app',draft['raw'])
    def test_manual_domain_on_other_port_allowed(self):
        result,_=self.preview(self.data('http',port=18083,domain='legacy.example.test'));self.assertTrue(result['ok'])
    def test_backup_only_pool_and_loop_prevented(self):
        for value in [self.data('http',backends=[dict(host='192.0.2.1',port=80,backup=True)]),self.data('rdp',backends=[dict(host='127.0.0.1',port=3389)])]:
            with self.assertRaises(ValueError):self.preview(value)
    def test_certificate_domain_key_and_path_validation(self):
        with self.assertRaisesRegex(ValueError,'не покрывает'):self.preview(self.data(domain='wrong.example.test'))
        with self.assertRaises(ValueError):self.preview(self.data(certificate='../leaf.pem'))
        with self.assertRaisesRegex(ValueError,'не подходят'):upload(self.engine,dict(certificate=self.cert,key=self.other_key,label='Mismatch'))
    def test_imported_certificate_has_private_permissions_and_no_key_in_response(self):
        result=upload(self.engine,dict(certificate=self.cert,key=self.key,label='Рабочий сертификат'))
        file=self.certs/result['name'];self.assertEqual(0o600,file.stat().st_mode&0o777);self.assertIn('PRIVATE KEY',file.read_text());self.assertNotIn('PRIVATE KEY',json.dumps(result));self.assertEqual('Рабочий сертификат',next(c['label'] for c in result['certificates'] if c['name']==result['name']))
    def test_options_real_haproxy_validation(self):
        result,draft=self.preview(self.data(upstream_tls=True,upstream_name='app.example.test',health='http',health_path='/health',balance='leastconn',hsts=True,allowed_ips='192.0.2.10 10.0.0.0/8',proxy_protocol=True,maxconn=100,strip_prefix=True,path='/api'))
        self.assertTrue(result['ok'],result['output']);self.assertIn(b'verifyhost app.example.test',draft['raw']);self.assertIn(b'send-proxy-v2',draft['raw']);self.assertIn(b'deny_status 403',draft['raw'])
    def test_pkcs12_import_and_wrong_password(self):
        import base64
        folder=Path(self.crypto.name);pfx=self.root/'bundle.pfx'
        subprocess.run(['openssl','pkcs12','-export','-in',str(folder/'leaf.crt'),'-inkey',str(folder/'leaf.key'),'-out',str(pfx),'-passout','stdin'],input=b'test-passphrase\n',capture_output=True,check=True)
        encoded=base64.b64encode(pfx.read_bytes()).decode()
        with self.assertRaisesRegex(ValueError,'PFX/P12'):upload(self.engine,dict(pfx_base64=encoded,password='wrong',label='Test'))
        result=upload(self.engine,dict(pfx_base64=encoded,password='test-passphrase',label='PFX import'))
        self.assertTrue(result['ok']);self.assertNotIn('PRIVATE KEY',json.dumps(result))
    def test_observation_mode_blocks_upload_and_publication(self):
        self.settings['read_only']=True
        with self.assertRaises(ValueError):self.preview(self.data())
        with self.assertRaises(ValueError):upload(self.engine,dict(certificate=self.cert,key=self.key,label='No write'))
    def test_revision_conflict_does_not_touch_config(self):
        revision=self.engine.snapshot()[1];self.config.write_bytes(BASE+b'# external\n')
        with self.assertRaises(Conflict):self.manager.preview(self.data(),revision,probe=False)
        self.assertEqual(BASE+b'# external\n',self.config.read_bytes())

if __name__=='__main__':unittest.main()
