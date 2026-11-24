from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean

class PreserveTests(ServicesFixture):
    def layered(self,proxy=True):
        return BASE+('frontend external_tls\n    bind 127.0.0.1:18443\n    mode tcp\n    tcp-request inspect-delay 5s\n    tcp-request content accept if { req.ssl_hello_type 1 }\n    default_backend tls_bridge\nbackend tls_bridge\n    mode tcp\n    server terminator 127.0.0.1:19443'+(' send-proxy-v2' if proxy else '')+'\nfrontend local_https\n    bind 127.0.0.1:19443 '+('accept-proxy ' if proxy else '')+'ssl crt '+str(self.certs/'leaf.pem')+'\n    mode http\n    http-request set-header X-Forwarded-Proto https\n    http-request deny deny_status 421\n').encode()
    def test_layered_https_uses_original_proxy_destination_and_keeps_headers_before_allow(self):
        original=self.layered();self.config.write_bytes(original)
        checked,draft=self.preview(self.data(port=18443,bind_address='127.0.0.1',https_frontend='local_https',redirect=False,forward_headers=False));self.assertTrue(checked['ok'],checked['output']);text=draft['raw'].decode()
        self.assertIn('{ dst_port 18443 }',text);self.assertNotIn('{ dst_port 19443 }',text)
        self.assertLess(text.index('http-request set-header X-Forwarded-Proto https'),text.index('http-request allow if'))
        self.assertEqual(original,clean(draft['raw'])[0].encode());self.assertEqual(1,text.count('bind 127.0.0.1:18443'))
    def test_local_bridge_without_proxy_uses_local_destination(self):
        self.config.write_bytes(self.layered(False));checked,draft=self.preview(self.data(port=18443,bind_address='127.0.0.1',https_frontend='local_https',redirect=False));self.assertTrue(checked['ok']);self.assertIn(b'{ dst_port 19443 }',draft['raw']);self.assertIn(b'X-Forwarded-Port %[ssl_fc,iif(18443,80)]',draft['raw'])
    def test_bridge_must_be_proven_and_proxy_options_must_match(self):
        for source in (self.layered().replace(b'server terminator 127.0.0.1:19443',b'server terminator 192.0.2.1:19443'),self.layered().replace(b'accept-proxy ssl',b'ssl')):
            self.config.write_bytes(source)
            with self.assertRaises(ValueError):self.preview(self.data(port=18443,bind_address='127.0.0.1',https_frontend='local_https'))
    def test_redirect_only_underscore_host_and_legacy_code(self):
        checked,draft=self.preview(self.data('http',domain='_discovery.example.test',backends=[],http_action='redirect',http_host_match='raw',redirect_code=302));self.assertTrue(checked['ok'],checked['output']);self.assertNotIn(b'backend studio_be_',draft['raw']);self.assertIn(b'hdr(host) -i _discovery.example.test',draft['raw']);self.assertIn(b'redirect scheme https code 302',draft['raw'])
    def test_path_only_https_redirect_is_not_applied_to_http_upgrade(self):
        checked,draft=self.preview(self.data(path='/admin',canonical_slash=True,redirect_root=True,root_redirect='/admin/',reject_other_paths=True,http_redirect_mode='scheme',http_redirect_all_paths=True));self.assertTrue(checked['ok']);text=draft['raw'].decode();model=clean(draft['raw'])[1][0]
        self.assertEqual('/admin/',model['root_redirect']);self.assertIn('redirect scheme https code 301',text);self.assertIn('redirect location /admin/ code 302',text)
        # The HTTP upgrade condition does not require /admin; it preserves all original paths.
        redirect=next(line for line in text.splitlines() if 'redirect scheme https code 301' in line)
        self.assertNotIn('_path',redirect)
    def test_cookie_health_tls_and_tunnel_policy_survive_noop_edit(self):
        data=self.data(upstream_tls=True,upstream_verify=False,upstream_sni=False,upstream_tls_version='TLSv1.2',forward_headers=False,health='http',health_http_version='1.0',health_host='',cookie_name='GW',backends=[dict(host='192.0.2.1',port=443,cookie_value='first')],tunnel_timeout=3600,timeout=900,imported=True,redirect_code=302)
        checked,draft=self.preview(data);self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];checked,edited=self.preview(model);self.assertTrue(checked['ok']);self.assertEqual(draft['raw'],edited['raw']);text=edited['raw'].decode()
        self.assertIn('cookie GW insert nocache',text);self.assertIn('cookie first',text);self.assertIn('ver HTTP/1.0\n',text);self.assertNotIn(' hdr Host ',text);self.assertNotIn(' sni str(',text);self.assertIn('ssl-min-ver TLSv1.2 ssl-max-ver TLSv1.2',text);self.assertIn('timeout tunnel 3600s',text)
    def test_legacy_prefix_health_routes_and_no_default_backend(self):
        checked,draft=self.preview(self.data('exchange',root_redirect='',routes=[dict(path='/ecp/',match='prefix',health_path='/ecp/healthcheck.htm',action='backend')],fallback_status=503));self.assertTrue(checked['ok'],checked['output']);text=draft['raw'].decode();self.assertIn('path_beg -i /ecp/',text);self.assertIn('deny deny_status 503',text)
        models=clean(draft['raw'])[1];self.assertEqual('prefix',models[0]['routes'][0]['match']);self.assertNotIn('backend studio_be_'+models[0]['id']+'\n',text)
    def test_tls_passthrough_can_own_an_http_upgrade_without_reencrypting(self):
        checked,draft=self.preview(self.data('tls',port=443,sni_routing=True,sni_domains='app.example.test',redirect=True,http_redirect_mode='scheme',health='tls',health_tls_verify=True,health_tls_name='app.example.test',proxy_protocol=True,health_send_proxy=True));self.assertTrue(checked['ok'],checked['output']);text=draft['raw'].decode();self.assertIn('redirect scheme https code 301',text);self.assertIn('check-send-proxy',text);self.assertIn('verifyhost app.example.test check-sni app.example.test',text);self.assertIn('send-proxy-v2',text)
    def test_edit_preserves_order_of_multiple_services(self):
        first,draft=self.preview(self.data('http',domain='first.example.test'));self.config.write_bytes(draft['raw'])
        second,draft=self.preview(self.data('http',domain='second.example.test'));self.config.write_bytes(draft['raw'])
        models=clean(draft['raw'])[1]
        checked,edited=self.preview(models[0]);self.assertTrue(checked['ok']);self.assertFalse(checked['changed']);self.assertEqual(draft['raw'],edited['raw'])
    def test_unsafe_values_are_rejected(self):
        invalid=[dict(cookie_name='bad name'),dict(https_frontend='x\nbackend injected'),dict(http_redirect_location='https://x.test/%[src]'),dict(health_http_version='3.0'),dict(upstream_tls_version='TLSv1.0'),dict(http_redirect_mode='raw config'),dict(redirect_code=304)]
        for change in invalid:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):self.preview(self.data(**change))
