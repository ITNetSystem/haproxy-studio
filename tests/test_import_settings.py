import test_acl_import
from test_services import ServicesFixture
from haproxy_studio.import_settings import inspect, patch

class ImportedSettingsTests(ServicesFixture):
    source=test_acl_import.ACLImportTests.source
    def adopt_for_settings(self):
        from haproxy_studio.importer import Importer
        self.config.write_bytes(self.source());report=Importer(self.manager).scan(dict(revision=self.engine.snapshot()[1]));item=next(c for c in report['candidates'] if c['backend']=='shared')
        checked,draft=Importer(self.manager).preview(dict(revision=self.engine.snapshot()[1],fingerprint=report['fingerprint'],selected=[item['id']]))
        self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw']);return self.manager.catalog()['services'][0]
    def test_reads_actual_settings_and_noop_is_identical(self):
        m=self.adopt_for_settings();s=m['import_settings'];self.assertEqual('source',s['balance']);self.assertEqual('500ms',s['timeout_server']);self.assertEqual('/owa/healthcheck.htm',s['health_path']);self.assertEqual('500ms',s['servers'][0]['inter']);self.assertTrue(s['servers'][0]['ssl']);before=self.config.read_bytes();checked,draft=self.preview(m);self.assertFalse(checked['changed']);self.assertEqual(before,draft['raw'])
    def test_edit_pool_preserves_acls_options_and_shared_reference(self):
        m=self.adopt_for_settings();m['import_changes']=dict(confirm=True,balance='leastconn',timeout_server='60m',health_method='HEAD',health_path='/mapi/healthcheck.htm',health_status='201',servers=[dict(name='mailbox',host='192.0.2.99',port='444',weight='20',backup=False,inter='7s',rise='4',fall='5')]);before=self.config.read_bytes();checked,draft=self.preview(m);self.assertTrue(checked['ok'],checked['output']);self.assertNotIn('metadata_only',draft)
        raw=draft['raw'];self.assertIn(b'acl portal path_beg /owa',raw);self.assertIn(b'http-request deny if blocked',raw);self.assertIn(b'ssl verify none check inter 7s slowstart 30s',raw);self.assertIn(b'# keep all flags',raw);self.assertIn(b'192.0.2.99:444',raw);self.assertIn(b'option httpchk HEAD /mapi/healthcheck.htm',raw);self.assertIn(b'timeout server 60m',raw);self.assertEqual(1,raw.count(b'backend shared\n'));self.assertNotIn(b'import_changes',raw);self.assertEqual(before,self.config.read_bytes());self.config.write_bytes(raw);current=self.manager.catalog()['services'][0];self.assertEqual('leastconn',current['import_settings']['balance']);self.assertEqual('192.0.2.99',current['backends'][0]['host']);checked,again=self.preview(current);self.assertFalse(checked['changed'])
    def test_requires_confirmation(self):
        m=self.adopt_for_settings();m['import_changes']=dict(balance='leastconn')
        with self.assertRaisesRegex(ValueError,'Подтвердите'):self.preview(m)
    def test_rejects_directive_injection_and_server_rename(self):
        m=self.adopt_for_settings()
        for changes in [dict(timeout_server='5s\nbackend injected'),dict(health_path='/ok\nbackend injected'),dict(servers=[dict(name='new',host='192.0.2.5',port='443')]),dict(servers=[dict(name='mailbox',host='192.0.2.5',port='443',inter='5s\nbackend bad')])]:
            with self.subTest(changes=changes):
                m['import_changes']=dict(changes,confirm=True)
                with self.assertRaises(ValueError):self.preview(m)
    def test_complex_checks_and_quoted_servers_are_preserved(self):
        base=self.source().decode().replace('option httpchk GET /owa/healthcheck.htm','option httpchk GET /owa/healthcheck.htm HTTP/1.1').replace('slowstart 30s','sni "str(mail.example.test)" slowstart 30s');m=dict(import_pool='shared',name='Mail');s=inspect(base,m,[m]);self.assertIn('health_path',s['blocked']);self.assertTrue(s['servers'][0]['blocked'])
        with self.assertRaises(ValueError):patch(base,m,dict(confirm=True,health_path='/changed'),[m])
        with self.assertRaises(ValueError):patch(base,m,dict(confirm=True,servers=[dict(name='mailbox',host='192.0.2.99')]),[m])
        updated,_=patch(base,m,dict(confirm=True,timeout_server='1h'),[m]);self.assertIn('sni "str(mail.example.test)" slowstart 30s',updated)
    def test_inherited_values_remain_empty(self):
        base='defaults\n timeout server 10s\nbackend shared\n default-server inter 500ms\n server one 192.0.2.5:443\n';m=dict(import_pool='shared',name='Mail');s=inspect(base,m,[m]);self.assertEqual('',s['timeout_server']);self.assertEqual('',s['servers'][0]['inter']);self.assertFalse(s['servers'][0]['ssl']);updated,_=patch(base,m,dict(confirm=True,balance='source'),[m]);self.assertIn('default-server inter 500ms',updated);self.assertNotIn('timeout server 3600',updated)
    def test_ambiguous_option_value_is_not_treated_as_flag(self):
        base='backend shared\n server one 192.0.2.5:443 cookie backup check\n';m=dict(import_pool='shared',name='Mail');self.assertTrue(inspect(base,m)['servers'][0]['blocked'])

    def test_path_changes_are_scoped_to_this_publication(self):
        m=self.adopt_for_settings();self.assertEqual('portal',m['import_settings']['paths'][0]['name']);m['import_paths']={'portal':['/new-owa','/new-autodiscover']}
        checked,draft=self.preview(m);self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'acl portal path_beg /owa',draft['raw']);self.assertIn(b'/new-owa /new-autodiscover',draft['raw']);self.assertIn(b'http-request deny if blocked',draft['raw']);self.assertIn(b'use_backend special if org_b blocked',draft['raw']);self.assertNotIn('metadata_only',draft)
        self.config.write_bytes(draft['raw']);current=self.manager.catalog()['services'][0];self.assertEqual(['/new-owa','/new-autodiscover'],current['import_settings']['paths'][0]['values']);checked,again=self.preview(current);self.assertFalse(checked['changed'])
        current.pop('import_paths');checked,restored=self.preview(current);self.assertTrue(checked['ok']);self.assertNotIn(b'/new-owa',restored['raw'])
    def test_rejects_unknown_path_acl_and_injected_path(self):
        m=self.adopt_for_settings()
        for paths in [{'blocked':['/changed']},{'portal':['/ok\nbackend evil']},{'portal':[]}]:
            m['import_paths']=paths
            with self.subTest(paths=paths),self.assertRaises(ValueError):self.preview(m)

    def test_all_backup_retained_pool_can_be_reopened(self):
        m=self.adopt_for_settings();m['import_changes']=dict(confirm=True,servers=[dict(name='mailbox',backup=True)])
        checked,draft=self.preview(m);self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw']);current=self.manager.catalog()['services'][0];self.assertTrue(current['backends'][0]['backup']);checked,again=self.preview(current);self.assertFalse(checked['changed'])
    def test_protected_pool_settings_cannot_bypass_pool_editor(self):
        m=self.adopt_for_settings();self.config.write_bytes(self.config.read_bytes().replace(b'192.0.2.15:443',b'127.0.0.1:9130'));m=self.manager.catalog()['services'][0];self.assertTrue(m['import_pool_blocked']);m['import_changes']=dict(confirm=True,timeout_server='60m')
        with self.assertRaisesRegex(ValueError,'панель'):self.preview(m)
