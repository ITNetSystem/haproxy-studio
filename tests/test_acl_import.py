import http.client
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from test_services import ServicesFixture,BASE
from haproxy_studio.importer import Importer
from haproxy_studio.services import clean
from haproxy_studio.resources import Resources

class ACLImportTests(ServicesFixture):
    def source(self):
        return BASE.split(b'frontend legacy')[0]+b'''frontend public
    bind 127.0.0.1:18443
    mode http
    acl org_a hdr(host),lower,field(1,:) -i app.example.test
    acl org_b hdr(host),lower,field(1,:) -i other.example.test
    acl portal path_beg /owa
    acl blocked path_beg /private
    http-request deny if blocked
    use_backend shared if org_a portal
    # other rules retain priority
    use_backend special if org_b blocked
    use_backend shared if org_b portal
    default_backend fallback
backend shared
    mode http
    balance source
    timeout server 500ms
    option httpchk GET /owa/healthcheck.htm
    http-check expect status 200
    server mailbox 192.0.2.15:443 ssl verify none check inter 500ms slowstart 30s # keep all flags
backend special
    mode http
    server other 192.0.2.20:8080
backend fallback
    mode http
    server other 192.0.2.21:8080
'''
    def scan(self,source):
        self.config.write_bytes(source);value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);return value,report
    def adopt(self,source,targets=None):
        value,report=self.scan(source)
        selected=[c['id'] for c in report['candidates'] if targets is None or c['backend'] in targets]
        self.assertTrue(selected,report)
        checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=selected))
        self.assertTrue(checked['ok'],checked['output']);return checked,draft
    def test_shared_acl_pool_is_single_and_keeps_unknown_parameters_verbatim(self):
        raw=self.source();checked,draft=self.adopt(raw,['shared']);models=clean(draft['raw'])[1]
        self.assertEqual(1,len(models));self.assertEqual({'app.example.test','other.example.test'},set(models[0]['domains']));self.assertEqual('shared',models[0]['import_pool'])
        pool=raw[raw.index(b'\nbackend shared\n')+1:raw.index(b'\nbackend special\n')+1]
        self.assertIn(pool,draft['raw']);self.assertEqual(1,draft['raw'].count(b'backend shared\n'));self.assertIn(b'http-request deny if blocked',draft['raw']);self.assertIn(b'acl portal path_beg /owa',draft['raw']);self.assertEqual(raw,self.config.read_bytes());self.assertEqual(2,len(models[0]['import_acl']['slots']))
        text=draft['raw'].decode();self.assertLess(text.index('use_backend shared if st_'),text.index('use_backend special'));self.assertGreater(text.rindex('use_backend shared if st_'),text.index('use_backend special'))
    def test_or_and_bounded_negation_and_repeated_acl_definitions(self):
        raw=self.source().replace(b'use_backend shared if org_a portal',b'use_backend shared if org_a !org_b portal or org_b portal').replace(b'    use_backend shared if org_b portal\n',b'')
        checked,draft=self.adopt(raw,['shared']);model=clean(draft['raw'])[1][0];self.assertEqual({'app.example.test','other.example.test'},set(model['domains']));self.assertEqual(2,len(model['import_acl']['slots'][0]['terms']))
    def test_negation_without_positive_domain_and_inline_conditions_stay_manual(self):
        for condition in (b'!org_a',b'{ path_beg /owa }'):
            raw=self.source().replace(b'use_backend shared if org_a portal',b'use_backend shared if '+condition).replace(b'    use_backend shared if org_b portal\n',b'')
            _,report=self.scan(raw);self.assertFalse(any(c['backend']=='shared' for c in report['candidates']))
    def test_inline_domain_acl_and_case_sensitivity_are_preserved(self):
        source=self.source().replace(b'use_backend shared if org_a portal',b'use_backend shared if { hdr(host) -m str app.example.test } portal').replace(b'use_backend shared if org_b portal',b'use_backend shared if { hdr(host) -i other.example.test } portal')
        _,draft=self.adopt(source,['shared']);model=clean(draft['raw'])[1][0];terms=[s['terms'][0] for s in model['import_acl']['slots']];self.assertEqual([False,True],[t['ignore_case'] for t in terms]);text=draft['raw'].decode();self.assertIn('hdr(host) app.example.test',text);self.assertIn('hdr(host) -i other.example.test',text)
    def test_repeated_named_acl_entries_are_or_combined(self):
        source=self.source().replace(b'    acl org_b hdr(host),lower,field(1,:) -i other.example.test',b'    acl org_b hdr(host),lower,field(1,:) -i other.example.test\n    acl org_b hdr(host),lower,field(1,:) -i third.example.test')
        _,draft=self.adopt(source,['shared']);self.assertEqual({'app.example.test','other.example.test','third.example.test'},set(clean(draft['raw'])[1][0]['domains']))
    def test_edit_domains_noop_disable_delete_and_name_migration_keep_shared_pool(self):
        _,draft=self.adopt(self.source(),['shared']);self.config.write_bytes(draft['raw']);model=self.manager.catalog()['services'][0]
        checked,again=self.preview(model);self.assertFalse(checked['changed']);self.assertEqual(draft['raw'],again['raw'])
        model['aliases']=[];checked,changed=self.preview(model);self.assertTrue(checked['ok']);generated=[m[4] for m in __import__('haproxy_studio.services',fromlist=['BLOCK']).BLOCK.finditer(changed['raw'].decode()) if m[2].startswith('aclroute')];self.assertFalse(any('other.example.test' in text for text in generated))
        self.config.write_bytes(draft['raw']);renamed,_=self.manager.preview_names(self.engine.snapshot()[1]);self.assertFalse(renamed['changed'])
        model['enabled']=False;checked,disabled=self.preview(model);self.assertTrue(checked['ok']);self.assertIn(b'backend shared\n',disabled['raw']);self.assertNotIn(b'use_backend shared if st_',disabled['raw']);self.config.write_bytes(disabled['raw']);self.assertTrue(next(p for p in Resources(self.engine).backends()['backends'] if p['name']=='shared')['blocked'])
        self.config.write_bytes(draft['raw']);checked,deleted=self.preview(dict(id=model['id']),'delete');self.assertTrue(checked['ok']);self.assertIn(b'backend shared\n',deleted['raw']);self.assertIn(b'use_backend special if org_b blocked',deleted['raw'])
    def test_other_frontend_can_adopt_same_pool_without_copying_it(self):
        raw=self.source()+b'frontend second\n    bind 127.0.0.1:19443\n    mode http\n    acl site hdr(host),lower,field(1,:) -i app.example.test\n    use_backend shared if site\n'
        _,draft=self.adopt(raw,['shared']);models=clean(draft['raw'])[1];self.assertEqual(2,len(models));self.assertEqual(1,draft['raw'].count(b'backend shared\n'))
        self.config.write_bytes(draft['raw']);overview=self.engine.overview()
        for model in models:
            route=next(s for s in overview['sections'] if s['name']==model['import_acl']['frontend'])
            self.assertTrue(any(c['service_id']==model['id'] for c in route['route_cards']))
    def test_sequential_import_keeps_pool_and_does_not_offer_owned_routes_twice(self):
        source=self.source()+b'frontend second\n bind 127.0.0.1:19443\n mode http\n acl site hdr(host),lower,field(1,:) -i app.example.test\n use_backend shared if site\n'
        value,report=self.scan(source);first=next(c for c in report['candidates'] if c['backend']=='shared' and c['frontend']=='public')
        checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[first['id']]));self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw'])
        value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);remaining=[c for c in report['candidates'] if c['backend']=='shared'];self.assertEqual(1,len(remaining));self.assertEqual('second',remaining[0]['frontend'])
        checked,second=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[remaining[0]['id']]));self.assertTrue(checked['ok'],checked['output']);self.assertEqual(1,second['raw'].count(b'backend shared\n'));self.assertEqual(2,len(clean(second['raw'])[1]))
    def test_shared_address_editor_shows_all_dependents_and_keeps_exact_flags(self):
        _,draft=self.adopt(self.source(),['shared']);self.config.write_bytes(draft['raw']);catalog=Resources(self.engine).backends();pool=next(p for p in catalog['backends'] if p['name']=='shared')
        self.assertTrue(pool['blocked']);self.assertFalse(pool['edit_blocked'])
        checked,edit=Resources(self.engine).edit_pool(dict(id=pool['id'],revision=catalog['revision'],servers=[dict(name='mailbox',host='192.0.2.55',port=8443)]));self.assertTrue(checked['ok']);self.assertIn(b'192.0.2.55:8443 ssl verify none check inter 500ms slowstart 30s # keep all flags',edit['raw'])
        self.config.write_bytes(edit['raw']);model=self.manager.catalog()['services'][0];self.assertEqual('192.0.2.55',model['backends'][0]['host']);checked,again=self.preview(model);self.assertTrue(checked['ok']);self.assertFalse(checked['changed'])
    def test_different_acl_profiles_do_not_guess_where_new_domains_belong(self):
        raw=self.source().replace(b'use_backend shared if org_b portal',b'use_backend shared if org_b !portal');_,draft=self.adopt(raw,['shared']);self.config.write_bytes(draft['raw']);model=self.manager.catalog()['services'][0];model['aliases'].append('new.example.test')
        with self.assertRaisesRegex(ValueError,'разные дополнительные ACL'):self.preview(model)
        model['import_domain_template']='other.example.test';checked,changed=self.preview(model);self.assertTrue(checked['ok']);self.assertIn(b'new.example.test other.example.test',changed['raw']);self.assertIn(b' !portal',changed['raw'])
    def test_raw_pool_and_inherited_timeouts_need_not_fit_typed_pool_schema(self):
        raw=self.source().replace(b'timeout connect 5s',b'timeout connect 500ms');_,draft=self.adopt(raw,['shared']);self.assertIn(b'timeout connect 500ms',draft['raw']);self.assertIn(b'timeout server 500ms',draft['raw'])
    def test_real_anonymized_mail_topologies_can_adopt_domain_path_acls(self):
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(self.root/'wild.key'),'-out',str(self.root/'wild.crt'),'-days','1','-subj','/CN=*.example.test','-addext','subjectAltName=DNS:*.example.test'],capture_output=True,check=True)
        (self.certs/'wild.pem').write_bytes((self.root/'wild.crt').read_bytes()+(self.root/'wild.key').read_bytes())
        import re
        for file in ('direct-tls.cfg','mixed-tls.cfg'):
            raw=(Path(__file__).parent/'fixtures'/file).read_text();raw=re.sub(r'crt /etc/haproxy/certificates/\S+',lambda _: 'crt '+str(self.certs/'wild.pem'),raw)
            candidates=Importer(self.manager).discover(raw)[2];shared=[c for c in candidates if c.get('anchors')];self.assertGreater(len(shared),5,(file,len(shared)))
    def test_conditional_sni_bridge_proxy_and_shared_http_pool_keep_real_tls_behavior(self):
        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'MAIL')
            def log_message(self,*args):pass
        backend=ThreadingHTTPServer(('127.0.0.1',0),Backend);thread=threading.Thread(target=backend.serve_forever);thread.start();proxy=None
        def free():
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
        public=free();local=free()
        raw=BASE.split(b'frontend legacy')[0]+('frontend outer\n bind 127.0.0.1:'+str(public)+'\n mode tcp\n tcp-request inspect-delay 5s\n tcp-request content accept if { req.ssl_hello_type 1 }\n acl first req_ssl_sni -i app.example.test\n acl second req.ssl_sni -i other.example.test\n use_backend bridge if first or second\n default_backend reject\nbackend bridge\n mode tcp\n server local 127.0.0.1:'+str(local)+' send-proxy-v2\nbackend reject\n mode tcp\n server reject 127.0.0.1:9\nfrontend inner\n bind 127.0.0.1:'+str(local)+' ssl crt '+str(self.certs/'leaf.pem')+' accept-proxy\n mode http\n acl first hdr(host),lower,field(1,:) -i app.example.test\n acl second hdr(host),lower,field(1,:) -i other.example.test\n acl owa path_beg /owa\n use_backend shared if first owa or second owa\nbackend shared\n mode http\n server mailbox 127.0.0.1:'+str(backend.server_port)+'\n').encode()
        def stop():
            nonlocal proxy
            if proxy:proxy.terminate();proxy.wait(timeout=5);proxy=None
        def probe(config):
            nonlocal proxy
            self.config.write_bytes(config);proxy=subprocess.Popen([self.settings['haproxy_binary'],'-db','-f',str(self.config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);deadline=time.monotonic()+5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',public),timeout=.1):break
                except OSError:
                    if time.monotonic()>deadline:raise
                    time.sleep(.03)
            replies=[]
            for host in ('app.example.test','other.example.test'):
                for path in ('/owa','/other'):
                    with socket.create_connection(('127.0.0.1',public),timeout=3) as sock:
                        with ssl._create_unverified_context().wrap_socket(sock,server_hostname=host) as tls:
                            tls.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode());chunks=[]
                            while True:
                                data=tls.recv(4096)
                                if not data:break
                                chunks.append(data)
                    packet=b''.join(chunks);head,body=packet.split(b'\r\n\r\n',1);replies.append((head.split(b'\r\n')[0],body))
            stop();return replies
        try:
            before=probe(raw);_,draft=self.adopt(raw,['shared','bridge']);models=clean(draft['raw'])[1];self.assertEqual(2,len(models));inner=next(m for m in models if m['import_pool']=='shared');self.assertEqual(public,inner['port']);self.assertEqual(local,inner['import_acl']['listener_port']);after=probe(draft['raw']);self.assertEqual(before,after)
        finally:stop();backend.shutdown();backend.server_close();thread.join()
    def test_actual_routing_before_and_after_import_with_interleaved_rules(self):
        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(self.server.marker)
            def log_message(self,*args):pass
        servers=[];threads=[];proxy=None
        def stop():
            nonlocal proxy
            if proxy:proxy.terminate();proxy.wait(timeout=5);proxy=None
        try:
            for marker in (b'SHARED',b'SPECIAL',b'FALLBACK'):
                server=ThreadingHTTPServer(('127.0.0.1',0),Backend);server.marker=marker;servers.append(server);thread=threading.Thread(target=server.serve_forever);thread.start();threads.append(thread)
            with socket.socket() as free:free.bind(('127.0.0.1',0));port=free.getsockname()[1]
            raw=self.source().replace(b'127.0.0.1:18443',('127.0.0.1:'+str(port)).encode()).replace(b'192.0.2.15:443 ssl verify none check inter 500ms slowstart 30s',('127.0.0.1:'+str(servers[0].server_port)).encode()).replace(b'192.0.2.20:8080',('127.0.0.1:'+str(servers[1].server_port)).encode()).replace(b'192.0.2.21:8080',('127.0.0.1:'+str(servers[2].server_port)).encode())
            def probe(config):
                nonlocal proxy
                self.config.write_bytes(config);proxy=subprocess.Popen([self.settings['haproxy_binary'],'-db','-f',str(self.config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                deadline=time.monotonic()+5
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                    except OSError:
                        if time.monotonic()>deadline:raise
                        time.sleep(.03)
                answers=[]
                for host in ('app.example.test','other.example.test','unknown.example.test'):
                    for path in ('/owa','/owa/mail','/private','/other'):
                        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3);conn.request('GET',path,headers={'Host':host});response=conn.getresponse();answers.append((response.status,response.read()));conn.close()
                stop();return answers
            before=probe(raw);_,draft=self.adopt(raw,['shared']);after=probe(draft['raw']);self.assertEqual(before,after)
        finally:
            stop()
            for server in servers:server.shutdown();server.server_close()
            for thread in threads:thread.join()
