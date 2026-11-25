import copy
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean
from haproxy_studio.importer import Importer,active
from haproxy_studio.discovery import discover
from haproxy_studio.diagnostics import result,ssl_issues,compatibility
from haproxy_studio.web import Application

class InfrastructureTests(ServicesFixture):
    def test_anonymized_real_topologies_are_discovered_without_mutation(self):
        for file,expected in [('direct-tls.cfg',54),('mixed-tls.cfg',24)]:
            raw=(Path(__file__).parent/'fixtures'/file).read_bytes()
            self.assertEqual(expected,len(discover(raw)))
            self.assertIsInstance(Importer(self.manager).discover(raw.decode())[2],list)

    def test_unrelated_escaped_stats_realm_does_not_block_import(self):
        from test_importer import ImportTests
        source=ImportTests.manual(self)+b'listen stats\n    bind 127.0.0.1:19000\n    stats enable\n    stats realm HAProxy-04\\ Statistics\n'
        candidates=Importer(self.manager).discover(source.decode())[2]
        self.assertEqual(1,len(candidates))
        self.assertEqual(['stats','realm','HAProxy-04 Statistics'],active(dict(name='stats',lines=[(9,'stats realm "HAProxy-04 Statistics" # comment')]))[0][1])
    def test_root_redirect_does_not_require_matching_publication_prefix(self):
        checked,draft=self.preview(self.data(path='/portal',root_redirect='/portal/',redirect=False))
        self.assertTrue(checked['ok'],checked['output'])
        line=next(l for l in draft['raw'].decode().splitlines() if 'redirect location /portal/' in l)
        self.assertNotIn('_path',line);self.assertIn('{ path / }',line)
    def test_generated_http_requests_precede_backend_choices(self):
        first=self.manager.normalize(self.data(redirect=False),'a'*16)
        second=self.manager.normalize(self.data(domain='other.example.test',name='Other',redirect=False),'b'*16)
        raw,_=self.manager.render(BASE.decode(),[first,second],probe=False)
        check=self.engine.validate(raw);self.assertTrue(check['ok'],check['output']);self.assertNotIn('will still be processed before',check['output'])
        self.assertEqual(BASE,clean(raw)[0].encode())
    def test_manual_backend_shared_dependencies_remain_visible_without_import(self):
        source=BASE+b'frontend second\n    bind 127.0.0.1:18090\n    mode http\n    default_backend old\n'
        rows=discover(source)
        self.assertEqual(2,len(rows));self.assertEqual({'legacy','second'},{r['frontend'] for r in rows});self.assertEqual({'old'},{r['backend'] for r in rows})
    def test_aws_lc_dh_fix_is_explicit_and_keeps_tls_policy(self):
        raw=BASE.replace(b'    maxconn 100',b'    maxconn 100\n    ssl-dh-param-file /absent/dh.pem\n    tune.ssl.default-dh-param 2048\n    ssl-default-bind-options ssl-min-ver TLSv1.2')
        self.config.write_bytes(raw)
        build=dict(aws_lc=True,ssl_library='Built with AWS-LC 3.3.0')
        with patch('haproxy_studio.diagnostics.compatibility',return_value=build):
            checked,draft=self.engine.compatibility_preview(self.engine.snapshot()[1])
        self.assertTrue(checked['ok'],checked['output']);self.assertEqual(raw,self.config.read_bytes());self.assertIn(b'ssl-min-ver TLSv1.2',draft['raw']);self.assertEqual(2,len(ssl_issues(raw,build)));self.assertEqual([],ssl_issues(raw,dict(aws_lc=False)))
    def test_diagnostics_severity_section_and_secrets(self):
        raw=b'global\ndefaults\n    stats auth admin:very-secret\n'
        completed=subprocess.CompletedProcess([],1,b'',b'[ALERT] parsing [/tmp/test:3] : stats auth admin:very-secret\n[WARNING] warning\n[NOTICE] notice\n')
        report=result(completed,raw)
        self.assertNotIn('very-secret',json.dumps(report));self.assertFalse(report['ok']);self.assertEqual('defaults',report['diagnostics'][0]['section']);self.assertEqual(3,report['diagnostics'][0]['line'])
    def test_fullchain_import_keeps_intermediates_and_checks_order(self):
        from haproxy_studio.certificates import upload
        folder=self.root/'chain';folder.mkdir()
        def run(*args):subprocess.run(['openssl',*map(str,args)],capture_output=True,check=True)
        root=Path(self.crypto.name)
        run('req','-new','-newkey','rsa:2048','-nodes','-keyout',folder/'ca.key','-out',folder/'ca.csr','-subj','/CN=Intermediate')
        (folder/'extensions').write_text('basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')
        run('x509','-req','-in',folder/'ca.csr','-CA',root/'leaf.crt','-CAkey',root/'leaf.key','-set_serial','11','-out',folder/'ca.crt','-days','1','-extfile',folder/'extensions')
        run('req','-new','-key',root/'other.key','-out',folder/'site.csr','-subj','/CN=app.example.test')
        (folder/'extensions').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:app.example.test\n')
        run('x509','-req','-in',folder/'site.csr','-CA',folder/'ca.crt','-CAkey',folder/'ca.key','-set_serial','12','-out',folder/'site.crt','-days','1','-extfile',folder/'extensions')
        leaf=(folder/'site.crt').read_text();ca=(folder/'ca.crt').read_text();anchor=(root/'leaf.crt').read_text();self.settings['ca_bundle']=str(root/'leaf.crt')
        result=upload(self.engine,dict(certificate=leaf,key=self.other_key,ca_bundle=ca+anchor,label='Full chain'))
        self.assertEqual([],result['warnings']);self.assertEqual(3,(self.certs/result['name']).read_text().count('BEGIN CERTIFICATE'))
        partial=upload(self.engine,dict(certificate=leaf,key=self.other_key,label='Incomplete'));self.assertTrue(partial['warnings'])
        with self.assertRaisesRegex(ValueError,'порядок'):upload(self.engine,dict(certificate=leaf+anchor+ca,key=self.other_key,label='Wrong order'))
    def test_partial_pool_edit_preserves_unknown_flags_comments_and_shared_routes(self):
        from haproxy_studio.resources import Resources
        raw=BASE.replace(b'server legacy 127.0.0.1:18081',b'server legacy 127.0.0.1:18081 check weight 7 # retain me')+b'frontend another\n    bind 127.0.0.1:18092\n    mode http\n    default_backend old\n'
        self.config.write_bytes(raw);resource=Resources(self.engine);pool=resource.backends()['backends'][0]
        checked,draft=resource.edit_pool(dict(id=pool['id'],revision=self.engine.snapshot()[1],servers=[dict(name='legacy',host='192.0.2.10',port=8088)]))
        self.assertTrue(checked['ok'],checked['output']);self.assertEqual(raw.replace(b'127.0.0.1:18081',b'192.0.2.10:8088'),draft['raw']);self.assertEqual(raw,self.config.read_bytes());self.assertIn('another',checked['warnings'][0])
    def test_certificate_rotation_preview_apply_backup_and_rollback(self):
        from haproxy_studio.resources import Resources
        replacement=self.certs/'new.pem';replacement.write_text((Path(self.crypto.name)/'other.crt').read_text()+self.other_key)
        target=self.certs/'leaf.pem';previous=target.read_bytes()
        raw=BASE.replace(b'bind 127.0.0.1:18080',('bind 127.0.0.1:18443 ssl crt '+str(target)).encode());self.config.write_bytes(raw)
        resource=Resources(self.engine);checked,draft=resource.replace_certificate(dict(name='leaf.pem',replacement='new.pem',revision=self.engine.snapshot()[1]))
        self.assertTrue(checked['ok'],checked['output']);self.assertEqual(previous,target.read_bytes());self.assertNotIn('PRIVATE KEY',json.dumps(checked))
        self.settings.update(reload_command=['/bin/false'],health_command=['/bin/true'])
        with self.assertRaises(ValueError):self.engine.apply(draft)
        self.assertEqual(previous,target.read_bytes());self.assertEqual(raw,self.config.read_bytes())
        checked,draft=resource.replace_certificate(dict(name='leaf.pem',replacement='new.pem',revision=self.engine.snapshot()[1]));self.settings['reload_command']=['/bin/true'];
        with patch('haproxy_studio.certificate_probe.verify',side_effect=ValueError('different fingerprint')):
            with self.assertRaises(ValueError):self.engine.apply(draft)
        self.assertEqual(previous,target.read_bytes())
        checked,draft=resource.replace_certificate(dict(name='leaf.pem',replacement='new.pem',revision=self.engine.snapshot()[1]));
        with patch('haproxy_studio.certificate_probe.verify',return_value=1):result=self.engine.apply(draft)
        self.assertEqual(replacement.read_bytes(),target.read_bytes());self.assertEqual(previous,(self.engine.state/'backups'/result['backup']/'certificate.pem').read_bytes());self.assertEqual(raw,self.config.read_bytes())
    def test_certificate_overlap_blocks_ambiguous_append(self):
        (self.certs/'new.pem').write_text((Path(self.crypto.name)/'other.crt').read_text()+self.other_key)
        self.config.write_bytes(BASE.replace(b'bind 127.0.0.1:18080',('bind 127.0.0.1:18443 ssl crt '+str(self.certs/'leaf.pem')).encode()))
        with self.assertRaisesRegex(ValueError,'пересекается'):self.preview(self.data(certificate='new.pem',port=18443,bind_address='127.0.0.1',redirect=False))
    def test_self_publication_is_detected_without_special_preset(self):
        with self.assertRaisesRegex(ValueError,'Обнаружена публикация самой панели'):self.preview(self.data(backends=[dict(host='127.0.0.1',port=9130)]))
        unit=(Path(__file__).parents[1]/'deploy/haproxy-studio.service').read_text()
        self.assertIn('ReadWritePaths=/etc/haproxy /etc/haproxy-studio ',unit)
    def test_studio_requires_reviewed_origin_change(self):
        value=self.data('studio');value['update_public_url']=False
        with self.assertRaisesRegex(ValueError,'Подтвердите'):self.preview(value)
        value['update_public_url']=True;checked,draft=self.preview(value)
        self.assertTrue(checked['ok'],checked['output']);self.assertEqual('https://app.example.test',draft['studio_origin']['origin']);self.assertEqual('/haproxy-admin',clean(draft['raw'])[1][0]['path'])
        self.assertEqual('http://127.0.0.1:9130',self.settings['public_url'])
    def test_studio_settings_installed_only_after_successful_reload(self):
        value=self.data('studio');checked,draft=self.preview(value)
        self.settings.update(reload_command=['/bin/true'],health_command=['/bin/true'])
        with patch('haproxy_studio.selfpublish.probe'):
            result=self.engine.apply(draft)
        self.assertEqual('https://app.example.test',result['public_url']);self.assertEqual('https://app.example.test',json.loads(Path(self.settings['_config_path']).read_text())['public_url'])
    def test_origin_only_update_does_not_reload_haproxy(self):
        value=self.data('studio');checked,draft=self.preview(value);self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];model['update_public_url']=True
        checked,draft=self.preview(model);self.assertTrue(checked['changed']);self.assertEqual(self.config.read_bytes(),draft['raw']);self.settings.update(reload_command=['/bin/false'],health_command=['/bin/false'])
        with patch('haproxy_studio.selfpublish.probe'):result=self.engine.apply(draft)
        self.assertEqual('https://app.example.test',result['public_url']);self.assertIn('reload не требовался',result['message'])
    def test_studio_reload_failure_preserves_origin(self):
        value=self.data('studio');checked,draft=self.preview(value);self.settings.update(reload_command=['/bin/false'],health_command=['/bin/true'])
        with self.assertRaises(ValueError):self.engine.apply(draft)
        self.assertEqual(BASE,self.config.read_bytes());self.assertEqual('http://127.0.0.1:9130',json.loads(Path(self.settings['_config_path']).read_text())['public_url'])
    def test_studio_probe_failure_rolls_back_haproxy_and_preserves_settings(self):
        value=self.data('studio');checked,draft=self.preview(value);self.settings.update(reload_command=['/bin/true'],health_command=['/bin/true'])
        with patch('haproxy_studio.selfpublish.probe',side_effect=ValueError('unavailable')):
            with self.assertRaises(ValueError):self.engine.apply(draft)
        self.assertEqual(BASE,self.config.read_bytes());self.assertEqual('http://127.0.0.1:9130',self.settings['public_url'])
    def test_application_canonical_slash_and_host_after_origin_change(self):
        app=Application(self.settings);server=ThreadingHTTPServer(('127.0.0.1',0),app.handler());thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            for host,expected in [('127.0.0.1:9130',302),('attacker.invalid',403)]:
                conn=http.client.HTTPConnection('127.0.0.1',server.server_port);conn.request('GET','/haproxy-admin?tab=services',headers={'Host':host});response=conn.getresponse();response.read();self.assertEqual(expected,response.status)
                if expected==302:self.assertEqual('/haproxy-admin/?tab=services',response.getheader('Location'))
                conn.close()
            app.settings['public_url']='https://app.example.test'
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port);conn.request('GET','/haproxy-admin/',headers={'Host':'app.example.test'});response=conn.getresponse();response.read();self.assertEqual(200,response.status);conn.close()
        finally:server.shutdown();server.server_close();thread.join()
    def test_rdweb_proxy_redirect_actual_https_and_other_requests(self):
        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(self.path.encode())
            do_POST=do_GET
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Backend);thread=threading.Thread(target=server.serve_forever);thread.start();proxy=None
        try:
            with socket.socket() as free:free.bind(('127.0.0.1',0));port=free.getsockname()[1]
            checked,draft=self.preview(self.data('rdwebproxy',port=port,redirect=False,bind_address='127.0.0.1',upstream_tls=False,health='none',backends=[dict(host='127.0.0.1',port=server.server_port)],rdweb_client='html5'))
            self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw']);proxy=subprocess.Popen([self.settings['haproxy_binary'],'-db','-f',str(self.config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                except OSError:
                    if time.monotonic()>deadline:raise
                    time.sleep(.03)
            from haproxy_studio.certificate_probe import verify
            self.assertEqual(1,verify(self.engine,dict(target=str(self.certs/'leaf.pem'))))
            for method,path,host,expected in [('GET','/','app.example.test',302),('GET','/?source=mail','app.example.test',302),('HEAD','/','app.example.test',302),('POST','/','app.example.test',200),('GET','/RDWeb/Pages/','app.example.test',200),('GET','/','unknown.example.test',503)]:
                conn=http.client.HTTPSConnection('127.0.0.1',port,context=ssl._create_unverified_context(),timeout=3);conn.request(method,path,headers={'Host':host});response=conn.getresponse();response.read();self.assertEqual(expected,response.status)
                if expected==302:self.assertEqual('/RDWeb/webclient/'+('?source=mail' if '?' in path else ''),response.getheader('Location'))
                conn.close()
        finally:
            if proxy:proxy.terminate();proxy.wait(timeout=5)
            server.shutdown();server.server_close();thread.join()
