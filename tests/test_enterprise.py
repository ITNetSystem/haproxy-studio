from pathlib import Path
import copy
import unittest
import test_services as fixtures
from haproxy_studio.services import clean
from haproxy_studio.enterprise import route_key

class EnterpriseTests(fixtures.ServicesFixture):
    def compile(self,data):return self.manager.preview(data,self.engine.snapshot()[1],probe=False)
    def test_domains_and_redirect_keep_alias(self):
        result,draft=self.compile(self.data(aliases='other.example.test',http_exceptions='/test /acme',root_redirect='/owa',security_headers=True))
        self.assertTrue(result['ok'],result['output']);text=draft['raw'].decode();self.assertIn('app.example.test other.example.test',text);self.assertIn('https://%[req.hdr(host),field(1,:)]',text);self.assertIn('exception',text);self.assertIn('X-Frame-Options SAMEORIGIN',text);self.assertEqual(fixtures.BASE,clean(draft['raw'])[0].encode())
    def test_every_alias_needs_certificate(self):
        with self.assertRaisesRegex(ValueError,'не покрывает'):self.compile(self.data(aliases='uncovered.example.test'))
    def test_exchange_per_component_pools(self):
        result,draft=self.compile(self.data('exchange'));self.assertTrue(result['ok'],result['output']);text=draft['raw'].decode();self.assertEqual(8,len(clean(draft['raw'])[1][0]['routes']));self.assertIn('http-check expect status 200',text);self.assertIn('/microsoft-server-activesync/healthcheck.htm',text);self.assertIn('timeout server 3600s',text);self.assertIn('http-request deny deny_status 403',text);self.assertIn('redirect location /owa',text)
    def test_path_pool_override_and_inheritance(self):
        data=self.data('exchange',routes=[dict(path='/owa',backends=[dict(host='192.0.2.22',port=8443)],health_path='/owa/healthcheck.htm'),dict(path='/ews',health_path='/ews/healthcheck.htm')]);_,draft=self.compile(data);model=clean(draft['raw'])[1][0];self.assertFalse(model['routes'][0]['inherit_pool']);self.assertTrue(model['routes'][1]['inherit_pool']);model['backends'][0]['host']='192.0.2.55';updated=self.manager.normalize(model,model['id']);self.assertEqual('192.0.2.22',updated['routes'][0]['backends'][0]['host']);self.assertEqual('192.0.2.55',updated['routes'][1]['backends'][0]['host'])
    def shared(self,mode='terminate'):
        first=self.data('smtps',port=16465,tls_mode=mode,sni_routing=True,sni_domains='app.example.test',sni_default=True);result,draft=self.compile(first);self.assertTrue(result['ok'],result['output']);self.config.write_bytes(draft['raw']);second=self.data('smtps',name='Other',port=16465,tls_mode=mode,sni_routing=True,sni_domains='other.example.test');result,draft=self.compile(second);self.assertTrue(result['ok'],result['output']);return draft
    def test_tls_terminated_sni_shares_listener(self):
        draft=self.shared();text=draft['raw'].decode();self.assertEqual(1,text.count('bind 0.0.0.0:16465'));self.assertIn('ssl_fc_sni -i app.example.test',text);self.assertIn('ssl_fc_sni -i other.example.test',text);self.assertNotIn('req.ssl_sni',text);self.assertEqual(fixtures.BASE,clean(draft['raw'])[0].encode())
    def test_passthrough_sni_uses_clienthello(self):
        text=self.shared('passthrough')['raw'].decode();self.assertIn('tcp-request inspect-delay 5s',text);self.assertIn('req.ssl_sni -i other.example.test',text);self.assertNotIn('bind 0.0.0.0:16465 ssl',text)
    def test_sni_duplicates_and_duplicate_fallback_rejected(self):
        draft=self.shared();self.config.write_bytes(draft['raw'])
        with self.assertRaisesRegex(ValueError,'SNI-домен'):self.compile(self.data('smtps',port=16465,sni_routing=True,sni_domains='other.example.test',tls_mode='terminate'))
        with self.assertRaisesRegex(ValueError,'fallback'):self.compile(self.data('smtps',port=16465,sni_routing=True,sni_domains='new.example.test',sni_default=True,tls_mode='passthrough'))
    def test_starttls_never_promises_sni_routing(self):
        for protocol in ['smtp','submission','imap','pop3']:
            with self.subTest(protocol=protocol):
                with self.assertRaisesRegex(ValueError,'SNI требует'):self.compile(self.data(protocol,sni_routing=True,sni_domains='app.example.test'))
    def test_smtp_ehlo_and_tls_checks(self):
        result,draft=self.compile(self.data('smtp',health='smtp',smtp_ehlo='probe.example.test'));self.assertTrue(result['ok']);self.assertIn(b'option smtpchk EHLO probe.example.test',draft['raw'])
        result,draft=self.compile(self.data('imaps',health='tls'));self.assertTrue(result['ok']);self.assertIn(b'check-ssl verify none',draft['raw'])
    def test_case_insensitive_and_specific_path(self):
        result,draft=self.compile(self.data(path_ignore_case=True,routes=[dict(path='/Autodiscover',health_path='/autodiscover/healthcheck.htm'),dict(path='/Autodiscover/special',health_path='/special')],health_status='200'))
        self.assertTrue(result['ok']);text=draft['raw'].decode();self.assertIn('path -i /Autodiscover',text);rules=[line for line in text.splitlines() if 'use_backend studio_be_' in line];model=clean(draft['raw'])[1][0];self.assertIn('_r'+route_key(model,model['routes'][1])+' if',rules[0]);self.assertIn('_r'+route_key(model,model['routes'][0])+' if',rules[1])
    def test_reject_form_injection(self):
        changes=[dict(aliases='good.example.test\nhttp-request allow'),dict(root_redirect='https://example.test/%[req.hdr(host)]'),dict(routes=[dict(path='/../secret')]),dict(routes=[dict(path='/owa',health_status='200\nbackend evil')]),dict(smtp_ehlo='x;id'),dict(routes=[dict(path='/owa'),dict(path='/OWA')],path_ignore_case=True)]
        for item in changes:
            with self.subTest(item=item):
                with self.assertRaises(ValueError):self.compile(self.data(**item))
    def test_component_identity_survives_reordering(self):
        data=self.data('exchange');_,draft=self.compile(data);model=clean(draft['raw'])[1][0];key=route_key(model,model['routes'][4]);model['routes']=list(reversed(model['routes']));self.assertEqual(key,route_key(model,model['routes'][3]));text=self.manager.backend(model);self.assertIn('backend studio_be_'+model['id']+'_r'+key,text)

    def test_existing_tcp_tls_can_be_extended_without_replacement(self):
        extra=('frontend existing_mail\n    bind 127.0.0.1:16465 ssl crt '+str(self.certs/'leaf.pem')+'\n    mode tcp\n    default_backend old_mail\nbackend old_mail\n    mode tcp\n    server old 192.0.2.1:465\n').encode();original=fixtures.BASE+extra;self.config.write_bytes(original)
        result,draft=self.compile(self.data('smtps',port=16465,bind_address='127.0.0.1',tls_mode='terminate',sni_routing=True,sni_domains='app.example.test'));self.assertTrue(result['ok'],result['output']);self.assertEqual(original,clean(draft['raw'])[0].encode());self.assertIn(b'ssl_fc_sni -i app.example.test',draft['raw'])

if __name__=='__main__':unittest.main()
