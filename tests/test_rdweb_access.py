import socket,ssl,subprocess,threading,time,http.client
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean

class RdWebAccessTests(ServicesFixture):
    def test_default_both_is_noop_and_strict_selects_matching_start_page(self):
        checked,draft=self.preview(self.data('rdwebproxy'));self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];checked,again=self.preview(dict(model,rdweb_access='both'));self.assertEqual(draft['raw'],again['raw'])
        for access,path in [('standard','/RDWeb/'),('html5','/RDWeb/webclient/')]:
            checked,draft=self.preview(dict(model,rdweb_access=access));self.assertTrue(checked['ok'],checked['output']);self.assertEqual(path,clean(draft['raw'])[1][0]['root_redirect'])
        for protocol in ('rdgateway','rdweb','https'):
            with self.assertRaises(ValueError):self.preview(self.data(protocol,rdweb_access='html5'))
    def test_real_path_filter_cannot_be_bypassed_by_case_encoding_or_traversal(self):
        class Portal(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.end_headers();self.wfile.write(b'upstream portal')
            def log_message(self,*args):pass
        upstream=ThreadingHTTPServer(('127.0.0.1',0),Portal);thread=threading.Thread(target=upstream.serve_forever,daemon=True);thread.start()
        try:
            for access in ('both','standard','html5'):
                with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
                with socket.socket() as sock:sock.bind(('127.0.0.1',0));http_port=sock.getsockname()[1]
                checked,draft=self.preview(self.data('rdwebproxy',port=port,bind_address='127.0.0.1',redirect=access=='standard',http_port=http_port,http_exceptions=['/RDWeb'] if access=='standard' else [],health='none',rdweb_access=access,backends=[dict(host='127.0.0.1',port=upstream.server_port)],upstream_tls=False));self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw'])
                proxy=subprocess.Popen([self.settings['haproxy_binary'],'-db','-f',str(self.config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                def fetch(path,tls=True):
                    c=http.client.HTTPSConnection('127.0.0.1',port,context=ssl._create_unverified_context(),timeout=3) if tls else http.client.HTTPConnection('127.0.0.1',http_port,timeout=3)
                    try:c.request('GET',path,headers={'Host':'app.example.test'});r=c.getresponse();r.read();return r.status,r.getheader('Location')
                    finally:c.close()
                try:
                    for _ in range(50):
                        try:fetch('/health');break
                        except OSError:time.sleep(.03)
                    classic='/RDWeb/Pages/en-US/Default.aspx';html='/RDWeb/webclient/index.html'
                    self.assertEqual(403 if access=='html5' else 200,fetch(classic)[0]);self.assertEqual(403 if access=='standard' else 200,fetch(html)[0]);self.assertEqual(200,fetch('/RDWeb/Feed/webfeed.aspx')[0]);self.assertEqual(200,fetch('/rpc/rpcproxy.dll')[0]);self.assertEqual(302,fetch('/')[0])
                    if access=='standard':
                        self.assertEqual(403,fetch(html,False)[0]);self.assertEqual(200,fetch('/RDWeb/Feed/webfeed.aspx',False)[0])
                    if access!='both':
                        blocked='webclient' if access=='standard' else 'pages'
                        for value in ['/RDWeb/'+blocked.upper()+'/index.html','/RDWeb/%'+format(ord(blocked[0]),'02x')+blocked[1:]+'/index.html','/RDWeb/%25'+format(ord(blocked[0]),'02x')+blocked[1:]+'/index.html','/RDWeb/foo/../'+blocked+'/index.html','/RDWeb\\'+blocked+'\\index.html','/RDWeb//'+blocked+'/index.html','/RDWeb/'+blocked+'./index.html','/RDWeb/'+blocked+'%20/index.html','/RDWeb/'+blocked+'%00/index.html']:
                            with self.subTest(access=access,path=value):self.assertEqual(403,fetch(value)[0])
                finally:proxy.terminate();proxy.communicate(timeout=4)
                self.config.write_bytes(BASE)
        finally:upstream.shutdown();upstream.server_close();thread.join()
