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
