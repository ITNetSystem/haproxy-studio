from test_services import ServicesFixture
from haproxy_studio.exchange_mail import preview
from haproxy_studio.exchange_groups import groups
from haproxy_studio.services import clean

class ExchangeMailTests(ServicesFixture):
    def test_bundle_create_edit_disable_delete_and_single_card(self):
        value=self.data('exchange',name='Company Exchange')
        value['exchange_mail']=[self.data(p,name=p.upper(),domain='',sni_routing=True,sni_domains=['app.example.test'],tls_mode='passthrough',redirect=False) for p in ('imaps','smtps')]
        checked,draft=preview(self.manager,value,self.engine.snapshot()[1]);self.assertTrue(checked['ok'],checked['output']);self.assertEqual(3,len(clean(draft['raw'])[1]));self.config.write_bytes(draft['raw'])
        base,models=clean(draft['raw']);g=groups(models,base,self.settings)[0];self.assertEqual(3,len(g['members']));root=next(m for m in models if m['protocol']=='exchange');self.assertTrue(all(m.get('exchange_parent')==root['id'] for m in models if m!=root))
        checked,again=preview(self.manager,root,self.engine.snapshot()[1]);self.assertTrue(checked['ok']);self.assertEqual(draft['raw'],again['raw'])
        checked,disabled=preview(self.manager,dict(root,enabled=False),self.engine.snapshot()[1]);self.assertTrue(checked['ok']);self.assertTrue(all(not m['enabled'] for m in clean(disabled['raw'])[1]))
        checked,deleted=preview(self.manager,root,self.engine.snapshot()[1],'delete');self.assertTrue(checked['ok']);self.assertEqual([],clean(deleted['raw'])[1])
    def test_ambiguous_domains_are_not_grouped(self):
        a=self.manager.normalize(self.data('exchange'),'a'*16);b=dict(a,id='b'*16);mail=self.manager.normalize(self.data('imaps',sni_routing=True,sni_domains=['app.example.test']),'c'*16)
        result=groups([a,b,mail],'',self.settings);self.assertTrue(all(mail['id'] not in g['members'] for g in result))
    def test_port_conflict_blocks_entire_bundle_without_writes(self):
        original=self.config.read_bytes();value=self.data('exchange');value['exchange_mail']=[self.data('imaps',port=18080,sni_routing=True,sni_domains=['app.example.test'])]
        with self.assertRaises(ValueError):preview(self.manager,value,self.engine.snapshot()[1])
        self.assertEqual(original,self.config.read_bytes())

    def test_recognized_tls_mail_joins_exchange_without_rewriting_transport(self):
        root=self.manager.normalize(self.data('exchange'),'a'*16)
        mail=self.manager.normalize(self.data('tls',port=465,sni_routing=True,sni_domains=['app.example.test'],tls_mode='terminate'),'b'*16)
        before=dict(mail)
        result=groups([root,mail],'',self.settings)
        self.assertEqual(['a'*16,'b'*16],result[0]['members'])
        self.assertEqual('SMTPS',result[0]['roles']['b'*16])
        self.assertEqual(before['protocol'],mail['protocol'])

    def test_imported_exchange_can_edit_new_native_mail_member(self):
        from test_exchange_groups import ExchangeGroupTests
        from haproxy_studio.importer import Importer
        from haproxy_studio.exchange_groups import preview as group_preview
        self.config.write_bytes(ExchangeGroupTests.source(self))
        request=dict(revision=self.engine.snapshot()[1]);scan=Importer(self.manager).scan(request)
        checked,draft=Importer(self.manager).preview(dict(request,fingerprint=scan['fingerprint'],selected=[c['id'] for c in scan['candidates']]))
        self.config.write_bytes(draft['raw']);root=clean(draft['raw'])[1][0]
        checked,added=self.preview(self.data('imaps',name='IMAPS Exchange',exchange_parent=root['id'],sni_routing=True,sni_domains=['app.example.test']))
        self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(added['raw']);catalog=self.manager.catalog();group=catalog['exchange_groups'][0]
        self.assertEqual(9,len(group['members']))
        checked,edited=group_preview(self.manager,dict(id=group['id'],revision=catalog['revision'],services=catalog['services']))
        self.assertTrue(checked['ok'],checked['output']);self.assertEqual(added['raw'],edited['raw'])
        old_models=clean(added['raw'])[1]
        checked,new=preview(self.manager,self.data('exchange',name='Independent Exchange',domain='other.example.test',exchange_mail=[]),self.engine.snapshot()[1])
        self.assertTrue(checked['ok'],checked['output']);self.assertEqual(old_models,clean(new['raw'])[1][:-1]);self.assertEqual(1,len(clean(new['raw'])[1])-len(old_models))

    def test_exchange_can_publish_starttls_143_and_587_without_sni(self):
        value=self.data('exchange');value['exchange_mail']=[self.data(p,name=p,domain='',certificate='',redirect=False) for p in ('imap','submission')]
        checked,draft=preview(self.manager,value,self.engine.snapshot()[1]);self.assertTrue(checked['ok'],checked['output'])
        base,models=clean(draft['raw']);mail=[m for m in models if m['protocol']!='exchange']
        self.assertEqual({143,587},{m['port'] for m in mail});self.assertTrue(all(m['tls_mode']=='plain' and not m['sni_routing'] and not m['upstream_tls'] for m in mail))
        self.assertEqual(3,len(groups(models,base,self.settings)[0]['members']))

    def test_manual_submission_shown_inside_exchange_without_claiming_import(self):
        from haproxy_studio.exchange_mail import attach_inventory
        from haproxy_studio.discovery import discover
        from haproxy_studio.services import bindings
        root=self.manager.normalize(self.data('exchange'),'a'*16)
        source=b'global\ndefaults\n mode tcp\n timeout connect 5s\n timeout client 30s\n timeout server 30s\nfrontend mail_smtp_587\n bind :587\n mode tcp\n use_backend submission_pool if { ssl_fc_sni app.example.test }\nbackend submission_pool\n mode tcp\n server mail 192.0.2.15:587\n'
        farms=groups([root],'',self.settings);items=discover(source,settings=self.settings);self.assertEqual(1,len(items));attach_inventory(farms,items,[root])
        self.assertEqual(farms[0]['id'],items[0]['exchange_group']);self.assertIn('ssl_fc_sni',items[0]['routing_issue']);self.assertEqual('manual',items[0]['management']);self.assertEqual(1,len(farms[0]['retained_mail']))

    def test_plain_mail_groups_by_unique_exchange_ip_ignoring_port(self):
        root=self.manager.normalize(self.data('exchange'),'a'*16)
        mail=self.manager.normalize(self.data('submission',certificate=''),'b'*16)
        self.assertEqual([],mail['domains'])
        self.assertEqual(['a'*16,'b'*16],groups([root,mail],'',self.settings)[0]['members'])
        other=dict(root,id='c'*16)
        self.assertTrue(all(mail['id'] not in g['members'] for g in groups([root,other,mail],'',self.settings)))
