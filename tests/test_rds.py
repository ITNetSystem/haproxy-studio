import ipaddress
import socket
import socketserver
import struct
import subprocess
import threading
import time
from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean

class RdsTests(ServicesFixture):
    def test_broker_defaults_and_native_transport(self):
        model=self.manager.normalize(self.data('rds'),'a'*16)
        self.assertEqual('broker',model['rds_mode']);self.assertEqual('leastconn',model['balance']);self.assertEqual(28800,model['timeout'])
        checked,draft=self.preview(self.data('rds'));self.assertTrue(checked['ok']);self.assertNotIn(b'persist rdp-cookie',draft['raw']);self.assertNotIn(b'send-proxy',draft['raw']);self.assertNotIn(b' ssl ',draft['raw'])
        self.assertTrue(any('Session Host' in w for w in checked['warnings']))
    def test_token_mode_validates_and_roundtrips(self):
        checked,draft=self.preview(self.data('rds',rds_mode='token',port=13389,backends=[dict(host='192.0.2.10',port=3389),dict(host='192.0.2.11',port=3389)]))
        self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'persist rdp-cookie',draft['raw']);self.assertIn(b'req.rdp_cookie_cnt gt 0',draft['raw']);self.assertEqual(BASE,clean(draft['raw'])[0].encode())
        self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];self.assertEqual('token',model['rds_mode']);model['name']='RDS edited'
        checked,draft=self.preview(model);self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw']);model['enabled']=False
        checked,draft=self.preview(model);self.assertTrue(checked['ok']);self.assertNotIn(b'persist rdp-cookie',draft['raw']);self.config.write_bytes(draft['raw'])
        checked,draft=self.preview(dict(id=model['id']),'delete');self.assertTrue(checked['ok']);self.assertEqual(BASE,draft['raw'])
    def test_rds_rejects_incompatible_transport_and_invalid_token_pool(self):
        changes=[dict(tls_mode='terminate'),dict(upstream_tls=True),dict(proxy_protocol=True),dict(health='tls'),dict(rds_mode='injected\nbackend x'),dict(rds_mode='token',backends=[dict(host='rdsh.example.test',port=3389)]),dict(rds_mode='token',backends=[dict(host='2001:db8::1',port=3389)])]
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):self.preview(self.data('rds',**change))
    def test_rdp_has_no_rds_persistence(self):
        checked,draft=self.preview(self.data('rdp'));self.assertTrue(checked['ok']);self.assertNotIn(b'persist rdp-cookie',draft['raw']);self.assertNotIn('rds_mode',clean(draft['raw'])[1][0])
    def test_real_haproxy_routes_rdp_tokens_to_selected_session_host(self):
        class Marker(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                try:
                    packet=self.request.recv(4096)
                    if packet:self.request.sendall(self.server.marker+packet)
                except OSError:pass
        servers=[];threads=[];proxy=None
        try:
            for marker in (b'HOST-A:',b'HOST-B:'):
                server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Marker);server.daemon_threads=True;server.marker=marker;servers.append(server)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread)
            with socket.socket() as free:
                free.bind(('127.0.0.1',0));port=free.getsockname()[1]
            checked,draft=self.preview(self.data('rds',rds_mode='token',port=port,bind_address='127.0.0.1',health='none',backends=[dict(host='127.0.0.1',port=s.server_address[1]) for s in servers]))
            self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw'])
            with (self.root/'haproxy.log').open('wb') as log:
                proxy=subprocess.Popen([self.settings['haproxy_binary'],'-db','-f',str(self.config)],stdout=log,stderr=log)
            deadline=time.monotonic()+4
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:
                    if time.monotonic()>deadline:raise
                    time.sleep(.03)
            for index in (1,0,1,0):
                target=servers[index]
                token=str(int.from_bytes(ipaddress.IPv4Address('127.0.0.1').packed,'little'))+'.'+str(socket.htons(target.server_address[1]))+'.0000'
                cookie=('Cookie: msts='+token+'\r\n').encode()
                packet=b'\x03\x00'+struct.pack('!H',11+len(cookie))+b'\x06\xe0\x00\x00\x00\x00\x00'+cookie
                with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
                    client.settimeout(3);client.sendall(packet);received=client.recv(4096)
                self.assertEqual(target.marker+packet,received)
        finally:
            if proxy:
                proxy.terminate()
                try:proxy.wait(timeout=3)
                except subprocess.TimeoutExpired:proxy.kill();proxy.wait()
            for server in servers:server.shutdown();server.server_close()
            for thread in threads:thread.join()
