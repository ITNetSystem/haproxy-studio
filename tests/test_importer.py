import copy
from unittest.mock import patch
from test_services import ServicesFixture,BASE
from haproxy_studio.importer import Importer
from haproxy_studio.services import clean
from haproxy_studio.core import Conflict

class ImportTests(ServicesFixture):
    def manual(self,tls=False,tcp=False):
        mode='tcp' if tcp else 'http'
        acl='req.ssl_sni' if tcp else 'hdr(host),lower,field(1,:)'
        bind=' ssl crt '+str(self.certs/'leaf.pem') if tls else ''
        return BASE.split(b'frontend legacy')[0]+('frontend public\n    bind 127.0.0.1:18443'+bind+'\n    mode '+mode+'\n'+('    tcp-request inspect-delay 5s\n    tcp-request content accept if { req.ssl_hello_type 1 }\n' if tcp else '')+'    acl site '+acl+' -i app.example.test\n    use_backend website if site\nbackend website\n    mode '+mode+'\n    balance leastconn\n    server original 192.0.2.15:8080 check inter 5s\n').encode()
    def scan(self,raw=None,**extra):
        if raw is not None:self.config.write_bytes(raw)
        value=dict(revision=self.engine.snapshot()[1],**extra);return value,Importer(self.manager).scan(value)
    def preview_import(self,value,report,**extra):
        value=dict(value,fingerprint=report['fingerprint'],selected=[c['id'] for c in report['candidates']],**extra)
        return Importer(self.manager).preview(value)
    def test_http_import_keeps_unrelated_rules_and_becomes_editable(self):
        source=self.manual()+b'backend untouched\n    mode http\n    server old 192.0.2.99:80\n';value,report=self.scan(source)
        self.assertEqual(1,len(report['candidates']),report);checked,draft=self.preview_import(value,report,names={report['candidates'][0]['id']:'Сайт компании'})
        self.assertTrue(checked['ok'],checked['output']);self.assertEqual(source,self.config.read_bytes());self.assertIn(b'backend untouched\n    mode http\n    server old 192.0.2.99:80\n',draft['raw']);self.assertNotIn(b'backend website\n',draft['raw'])
        self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];self.assertEqual('Сайт компании',model['name']);self.assertEqual('original',model['backends'][0]['name']);checked,edited=self.preview(model);self.assertTrue(checked['ok']);self.assertEqual(draft['raw'],edited['raw'])
    def test_inline_and_backend_comments_survive_import(self):
        source=self.manual().replace(b'acl site hdr',b'acl site hdr').replace(b'-i app.example.test\n',b'-i app.example.test # domain explanation\n').replace(b'    server original',b'    # server explanation\n    server original').replace(b'check inter 5s\n',b'check inter 5s # check explanation\n')
        value,report=self.scan(source);self.assertEqual(1,len(report['candidates']),report)
        checked,draft=self.preview_import(value,report);self.assertTrue(checked['ok'],checked['output'])
        for comment in (b'# domain explanation',b'# server explanation',b'# check explanation'):self.assertIn(comment,draft['raw'])
    def test_https_uses_existing_certificate_and_listener(self):
        value,report=self.scan(self.manual(tls=True));self.assertEqual(1,len(report['candidates']),report);checked,draft=self.preview_import(value,report);self.assertTrue(checked['ok'],checked['output']);self.assertEqual(1,draft['raw'].count(b'bind 127.0.0.1:18443'))
    def test_sni_import_preserves_tcp_inspection_and_backend_tls(self):
        value,report=self.scan(self.manual(tcp=True));self.assertEqual(1,len(report['candidates']),report);checked,draft=self.preview_import(value,report);self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'tcp-request inspect-delay 5s',draft['raw']);self.assertIn(b'req.ssl_sni',draft['raw'])
    def test_default_tcp_port_import_keeps_frontend_policy(self):
        source=self.manual(tcp=True).replace(b'    acl site req.ssl_sni -i app.example.test\n    use_backend website if site',b'    default_backend website')
        value,report=self.scan(source);self.assertEqual(1,len(report['candidates']),report);checked,draft=self.preview_import(value,report);self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'default_backend be_website',draft['raw']);self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];checked,edited=self.preview(model);self.assertTrue(checked['ok']);self.assertEqual(draft['raw'],edited['raw'])
    def test_http_redirect_import_has_no_backend_and_keeps_legacy_status(self):
        source=(self.manual().split(b'\nbackend website')[0]+b'\n').replace(b'use_backend website if site',b'http-request redirect scheme https code 302 if site')
        value,report=self.scan(source);self.assertEqual(1,len(report['candidates']),report);checked,draft=self.preview_import(value,report);self.assertTrue(checked['ok'],checked['output']);model=clean(draft['raw'])[1][0];self.assertEqual('redirect',model['http_action']);self.assertEqual(302,model['redirect_code']);self.assertEqual([],model['backends'])
    def test_rewrites_after_routes_remain_manual_and_global_redirect_is_preserved(self):
        value,report=self.scan(self.manual().replace(b'backend website',b'    http-request set-header X-Test value\nbackend website'));self.assertFalse(report['candidates']);self.assertTrue(report['preserved'])
        source=self.manual().replace(b'    acl site',b'    http-request redirect scheme https code 301\n    acl site');value,report=self.scan(source);self.assertEqual(1,len(report['candidates']));checked,draft=self.preview_import(value,report);self.assertTrue(checked['ok']);self.assertIn(b'http-request redirect scheme https code 301',draft['raw']);self.assertLess(draft['raw'].index(b'http-request redirect scheme https'),draft['raw'].index(b'use_backend website if st_'))
    def test_accept_proxy_requires_manual_destination_mapping(self):
        value,report=self.scan(self.manual().replace(b'bind 127.0.0.1:18443',b'bind 127.0.0.1:18443 accept-proxy'));self.assertFalse(report['candidates']);self.assertTrue(report['preserved'])
    def test_imported_tcp_cannot_silently_leave_original_listener(self):
        source=self.manual(tcp=True).replace(b'    acl site req.ssl_sni -i app.example.test\n    use_backend website if site',b'    default_backend website')
        value,report=self.scan(source);checked,draft=self.preview_import(value,report);self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0];model['port']=19444
        with self.assertRaises(ValueError):self.preview(model)
    def test_unknown_backend_policy_is_preserved(self):
        source=self.manual().replace(b'    balance leastconn',b'    stick-table type ip size 100k expire 1h\n    balance leastconn');value,report=self.scan(source);self.assertEqual(1,len(report['candidates']));checked,draft=self.preview_import(value,report);self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'backend website\n',draft['raw']);self.assertIn(b'stick-table type ip size 100k expire 1h',draft['raw']);self.assertEqual(source,self.config.read_bytes())
    def test_shared_backend_and_complex_acl_are_not_guessed(self):
        for source in (self.manual().replace(b'backend website',b'    default_backend website\nbackend website'),self.manual().replace(b'if site',b'if site { path_beg /owa }'),self.manual().replace(b'    use_backend',b'    http-request deny if site\n    use_backend')):
            value,report=self.scan(source);self.assertEqual([],report['candidates']);self.assertTrue(report['preserved'])
    def test_partial_selection_keeps_unselected_pool_and_rules(self):
        source=self.manual().replace(b'backend website\n',b'    acl other hdr(host),lower,field(1,:) -i other.example.test\n    use_backend otherpool if other\nbackend website\n')+b'backend otherpool\n    mode http\n    server second 192.0.2.16:80 check\n'
        value,report=self.scan(source);self.assertEqual(2,len(report['candidates']),report);value.update(fingerprint=report['fingerprint'],selected=[report['candidates'][0]['id']]);checked,draft=Importer(self.manager).preview(value);self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'backend otherpool\n',draft['raw']);self.assertIn(b'use_backend otherpool if other',draft['raw'])
    def test_revision_source_fingerprint_and_selection_are_checked(self):
        value,report=self.scan(self.manual())
        with self.assertRaises(Conflict):Importer(self.manager).scan(dict(value,revision='outdated'))
        with self.assertRaises(Conflict):Importer(self.manager).preview(dict(value,fingerprint='changed',selected=[]))
        for selection in ([],['unknown'],[report['candidates'][0]['id']]*2):
            with self.assertRaises(ValueError):Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=selection))
    def test_uploaded_file_requires_explicit_replacement_confirmation(self):
        original=self.config.read_bytes();value,report=self.scan(source='file',content=self.manual().decode())
        with self.assertRaises(ValueError):self.preview_import(value,report)
        checked,draft=self.preview_import(value,report,replace_confirm=True);self.assertTrue(checked['ok'],checked['output']);self.assertEqual(original,self.config.read_bytes());self.assertNotIn(b'frontend legacy',draft['raw'])
    def test_readonly_and_limits_are_enforced(self):
        value,report=self.scan(self.manual());self.settings['read_only']=True
        with self.assertRaises(ValueError):Importer(self.manager).scan(value)
        self.settings['read_only']=False
        for content in ('','x'*524289,'global\x00'):
            with self.assertRaises(ValueError):Importer(self.manager).scan(dict(value,source='file',content=content))
    def test_unknown_server_flags_and_inherited_pool_settings_are_not_dropped(self):
        for source in (self.manual().replace(b'check inter 5s',b'check inter 5s slowstart 30s'),self.manual().replace(b'    timeout client',b'    default-server inter 10s\n    timeout client')):
            value,report=self.scan(source);self.assertEqual(1,len(report['candidates']));checked,draft=self.preview_import(value,report);self.assertTrue(checked['ok'],checked['output']);self.assertIn(source[source.index(b'backend website\n'):],draft['raw']);self.assertEqual(source,self.config.read_bytes())
