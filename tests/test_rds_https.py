import socket
import socketserver
import ssl
import subprocess
import threading
import time
from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean

class RdsHttpsTests(ServicesFixture):
    def legacy_sni(self):
        return BASE+b'frontend existing_sni\n    bind 127.0.0.1:18443\n    mode tcp\n    tcp-request inspect-delay 5s\n    tcp-request content accept if { req.ssl_hello_type 1 }\n    acl old_name req.ssl_sni -i old.example.test\n    use_backend old_tls if old_name\n    default_backend old_tls\nbackend old_tls\n    mode tcp\n    server original 192.0.2.20:443\n'
    def test_https_defaults_native_tls_and_affinity(self):
        for protocol in ('rdgateway','rdweb'):
            model=self.manager.normalize(self.data(protocol),'a'*16)
            self.assertEqual(443,model['port']);self.assertEqual(443,model['backends'][0]['port']);self.assertEqual('passthrough',model['tls_mode']);self.assertTrue(model['sni_routing']);self.assertEqual(['app.example.test'],model['domains']);self.assertEqual('source',model['balance'])
            checked,draft=self.preview(self.data(protocol));self.assertTrue(checked['ok']);self.assertNotIn(b'send-proxy',draft['raw']);self.assertNotIn(b' ssl ',draft['raw']);self.assertNotIn(b'persist rdp-cookie',draft['raw']);self.assertNotIn(b':3389',draft['raw'])
            self.assertIn(('timeout tunnel '+str(28800 if protocol=='rdgateway' else 3600)+'s').encode(),draft['raw'])
        self.assertTrue(any('UDP/3391' in w for w in self.preview(self.data('rdgateway'))[0]['warnings']))
    def test_existing_sni_frontend_and_fallback_are_preserved(self):
        original=self.legacy_sni();self.config.write_bytes(original)
        checked,draft=self.preview(self.data('rdgateway',port=18443,bind_address='127.0.0.1'));self.assertTrue(checked['ok'],checked['output']);self.assertEqual(1,draft['raw'].count(b'bind 127.0.0.1:18443'));self.assertIn(b'default_backend old_tls',draft['raw']);self.assertIn(b'backend old_tls',draft['raw']);self.assertEqual(original,clean(draft['raw'])[0].encode())
    def test_roundtrip_edit_disable_delete_and_dedicated_ip(self):
        checked,draft=self.preview(self.data('rdweb',sni_routing=False));self.assertTrue(checked['ok']);self.assertNotIn(b'req.ssl_sni',draft['raw']);self.config.write_bytes(draft['raw'])
        model=clean(draft['raw'])[1][0];model['name']='Portal updated';checked,draft=self.preview(model);self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw'])
        model=clean(draft['raw'])[1][0];model['enabled']=False;checked,draft=self.preview(model);self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw']);checked,draft=self.preview(dict(id=model['id']),'delete');self.assertTrue(checked['ok']);self.assertEqual(BASE,draft['raw'])
        checked,draft=self.preview(self.data('rdgateway'));self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];checked,_=self.preview(model);self.assertTrue(checked['ok'])
    def test_shared_domain_and_existing_http_publication_are_not_hijacked(self):
        self.config.write_bytes(self.legacy_sni())
        with self.assertRaisesRegex(ValueError,'SNI-домен'):self.preview(self.data('rdgateway',domain='old.example.test',port=18443,bind_address='127.0.0.1'))
        original=self.legacy_sni()+b'frontend internal_http\n    bind 127.0.0.1:19443\n    mode http\n    acl web hdr(host) -i app.example.test\n    use_backend old if web\n'
        self.config.write_bytes(original)
        with self.assertRaisesRegex(ValueError,'перехватит'):self.preview(self.data('rdgateway',port=18443,bind_address='127.0.0.1'))
        self.config.write_bytes(self.legacy_sni().replace(b'    tcp-request inspect-delay 5s\n',b''))
        with self.assertRaisesRegex(ValueError,'inspect-delay'):self.preview(self.data('rdgateway',port=18443,bind_address='127.0.0.1'))
    def test_transport_override_missing_names_and_duplicate_roles_rejected(self):
        for protocol in ('rdgateway','rdweb'):
            for change in (dict(tls_mode='terminate'),dict(upstream_tls=True),dict(proxy_protocol=True),dict(health='tls'),dict(health='http'),dict(domain='',sni_domains='')):
                with self.subTest(protocol=protocol,change=change):
                    with self.assertRaises(ValueError):self.preview(self.data(protocol,**change))
        checked,draft=self.preview(self.data('rdgateway'));self.config.write_bytes(draft['raw'])
        with self.assertRaisesRegex(ValueError,'SNI-домен'):self.preview(self.data('rdweb'))
    def test_existing_terminated_https_listener_is_not_changed_to_passthrough(self):
        original=BASE+('frontend terminated\n    bind 127.0.0.1:18443 ssl crt '+str(self.certs/'leaf.pem')+'\n    mode http\n    default_backend old\n').encode();self.config.write_bytes(original)
        with self.assertRaisesRegex(ValueError,'несовместимым'):self.preview(self.data('rdgateway',port=18443,bind_address='127.0.0.1'))
        self.assertEqual(original,self.config.read_bytes())
    def test_real_tls_sni_and_rpc_or_web_payload_survive_unchanged(self):
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                try:
                    packet=self.request.recv(4096)
                    if packet:self.request.sendall(self.server.marker+packet)
                except OSError:pass
        servers=[];threads=[];proxy=None
        try:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(self.certs/'leaf.pem'))
            for marker in (b'GATEWAY:',b'PORTAL:'):
                server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Echo);server.daemon_threads=True;server.marker=marker;server.socket=context.wrap_socket(server.socket,server_side=True);servers.append(server)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread)
            with socket.socket() as free:free.bind(('127.0.0.1',0));port=free.getsockname()[1]
            checked,draft=self.preview(self.data('rdgateway',port=port,bind_address='127.0.0.1',health='none',backends=[dict(host='127.0.0.1',port=servers[0].server_address[1])]))
            self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw'])
            checked,draft=self.preview(self.data('rdweb',domain='other.example.test',port=port,bind_address='127.0.0.1',health='none',backends=[dict(host='127.0.0.1',port=servers[1].server_address[1])]))
            self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw'])
            with (self.root/'proxy.log').open('wb') as log:proxy=subprocess.Popen([self.settings['haproxy_binary'],'-db','-f',str(self.config)],stdout=log,stderr=log)
            deadline=time.monotonic()+4
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:
                    if time.monotonic()>deadline:raise
                    time.sleep(.03)
            client_context=ssl.create_default_context(cadata=self.cert)
            for name,method,path,marker in [('app.example.test','RPC_IN_DATA','/rpc/rpcproxy.dll',b'GATEWAY:'),('app.example.test','RDG_OUT_DATA','/remoteDesktopGateway/',b'GATEWAY:'),('other.example.test','GET','/RDWeb/',b'PORTAL:')]:
                packet=(method+' '+path+' HTTP/1.1\r\nHost: '+name+'\r\nAuthorization: NTLM synthetic-test-only\r\n\r\n').encode()
                with socket.create_connection(('127.0.0.1',port),timeout=3) as raw:
                    with client_context.wrap_socket(raw,server_hostname=name) as client:
                        client.sendall(packet);received=client.recv(4096)
                self.assertEqual(marker+packet,received)
        finally:
            if proxy:
                proxy.terminate()
                try:proxy.wait(timeout=3)
                except subprocess.TimeoutExpired:proxy.kill();proxy.wait()
            for server in servers:server.shutdown();server.server_close()
            for thread in threads:thread.join()

    def test_rdweb_standard_and_html5_addresses_are_persisted(self):
        from haproxy_studio.rdweb import path
        from haproxy_studio.routing import publications,describe
        from haproxy_studio.core import sections
        for mode,expected in [('standard','/RDWeb/'),('html5','/RDWeb/webclient/')]:
            checked,draft=self.preview(self.data('rdweb',rdweb_client=mode));self.assertTrue(checked['ok'],checked['output']);model=clean(draft['raw'])[1][0];self.assertEqual(expected,path(model));self.assertEqual(mode,model['rdweb_client']);items=publications([model],[],describe(draft['raw'],sections(draft['raw']),[model]));self.assertEqual(['https://app.example.test'+expected],items[0]['source']);self.assertTrue(any(expected in item for item in checked['summary']))
    def test_rdweb_defaults_and_gateway_combined_portal(self):
        from haproxy_studio.rdweb import path
        self.assertEqual('/RDWeb/',path(self.manager.normalize(self.data('rdweb'),'a'*16)))
        self.assertEqual('',path(self.manager.normalize(self.data('rdgateway'),'a'*16)))
        self.assertEqual('/RDWeb/webclient/',path(self.manager.normalize(self.data('rdgateway',rdweb_client='html5'),'a'*16)))
        for value in ('none','other','/custom/'):
            with self.assertRaises(ValueError):self.preview(self.data('rdweb',rdweb_client=value))
    def test_html5_selection_does_not_generate_http_rewrites_in_tcp_tunnel(self):
        checked,standard=self.preview(self.data('rdweb',rdweb_client='standard'));self.assertTrue(checked['ok']);self.config.write_bytes(standard['raw']);model=clean(standard['raw'])[1][0];model['rdweb_client']='html5';checked,html5=self.preview(model);self.assertTrue(checked['ok']);strip=lambda raw:'\n'.join(line for line in raw.decode().splitlines() if not line.startswith('#'))
        self.assertEqual(strip(standard['raw']),strip(html5['raw']))
    def test_old_rdweb_default_selection_does_not_cause_noop_reload(self):
        checked,draft=self.preview(self.data('rdweb'));self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];model['rdweb_client']='standard';checked,again=self.preview(model);self.assertFalse(checked['changed']);self.assertEqual(draft['raw'],again['raw'])
    def test_rdweb_can_redirect_plain_http_to_the_selected_portal(self):
        checked,draft=self.preview(self.data('rdweb',rdweb_client='standard',redirect=True,http_redirect_location='https://app.example.test/RDWeb/',redirect_code=302));self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'http-request redirect location https://app.example.test/RDWeb/ code 302',draft['raw']);self.assertIn(b'req.ssl_sni',draft['raw']);self.assertNotIn(b'ssl crt ',draft['raw'])
