from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean
from haproxy_studio.naming import backend_name,slug,references
from unittest.mock import patch

class NamingTests(ServicesFixture):
    def test_readable_backend_and_custom_server_names_round_trip(self):
        data=self.data(naming='readable',name='Сайт компании',backend_name='be_website',backends=[dict(name='web01',host='192.0.2.10',port=8080)])
        checked,draft=self.preview(data);self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'backend be_website\n',draft['raw']);self.assertIn(b'server web01 192.0.2.10:8080',draft['raw']);self.assertIn(b'use_backend be_website if ',draft['raw']);self.config.write_bytes(draft['raw']);checked,again=self.preview(clean(draft['raw'])[1][0]);self.assertFalse(checked['changed']);self.assertEqual(draft['raw'],again['raw'])
    def test_names_generated_from_cyrillic_and_actual_addresses(self):
        checked,draft=self.preview(self.data(naming='readable',name='Почта компании'));self.assertTrue(checked['ok']);self.assertIn(b'backend be_pochta_kompanii\n',draft['raw']);self.assertIn(b'server srv_192_0_2_15_80 ',draft['raw']);self.assertEqual('exchange_owa',slug('Exchange / OWA'))
    def test_new_api_publications_default_to_readable_but_legacy_edits_stay_legacy(self):
        data=self.data();data.pop('naming');checked,draft=self.preview(data);self.assertTrue(checked['ok']);self.assertIn(b'backend be_proverka_servisa\n',draft['raw'])
        checked,legacy=self.preview(self.data());self.config.write_bytes(legacy['raw']);checked,again=self.preview(clean(legacy['raw'])[1][0]);self.assertEqual(legacy['raw'],again['raw'])
    def test_exchange_route_names_and_inherited_server_names(self):
        checked,draft=self.preview(self.data('exchange',naming='readable',backend_name='be_exchange',fallback_status=503,backends=[dict(name='exch01',host='192.0.2.10',port=443)]));self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'backend be_exchange__owa\n',draft['raw']);self.assertIn(b'use_backend be_exchange__owa if ',draft['raw']);self.assertIn(b'server exch01 192.0.2.10:443',draft['raw']);self.assertNotIn(b'backend be_exchange\n',draft['raw'])
    def test_duplicate_and_unsafe_names_are_rejected(self):
        for name in ('bad name','x\nbackend injected','../bad','1bad'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):self.preview(self.data(naming='readable',backend_name=name))
        with self.assertRaises(ValueError):self.preview(self.data(naming='readable',backends=[dict(name='web',host='192.0.2.10',port=80),dict(name='web',host='192.0.2.11',port=80)]))
        with self.assertRaises(ValueError):self.preview(self.data(naming='readable',backend_name='old'))
    def test_bulk_rename_updates_manual_references_and_preserves_addresses_and_cookies(self):
        checked,draft=self.preview(self.data(cookie_name='SERVER',backends=[dict(host='192.0.2.10',port=80,cookie_value='stable')]));self.config.write_bytes(draft['raw']);old=backend_name(clean(draft['raw'])[1][0]);self.config.write_bytes(draft['raw']+('frontend manual\n    bind 127.0.0.1:18888\n    mode http\n    default_backend '+old+'\n').encode());before=self.config.read_bytes();checked,renamed=self.manager.preview_names(self.engine.snapshot()[1]);self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'default_backend be_proverka_servisa\n',renamed['raw']);self.assertIn(b'cookie stable',renamed['raw']);self.assertIn(b'192.0.2.10:80',renamed['raw']);self.assertNotIn(('backend '+old+'\n').encode(),renamed['raw']);self.assertEqual(before,self.config.read_bytes());self.config.write_bytes(renamed['raw']);checked,again=self.manager.preview_names(self.engine.snapshot()[1]);self.assertEqual(renamed['raw'],again['raw'])
    def test_unknown_manual_references_and_dynamic_maps_block_rename(self):
        for text in ('backend x\n    server x 192.0.2.1:80 track old/node1\n','frontend f\n    use_backend %[req.hdr(host),map(/tmp/map)]\n'):
            with self.assertRaises(ValueError):references(text,{'old':'be_new'})
        self.assertEqual('    use_backend be_new if a\n',references('    use_backend old if a\n',{'old':'be_new'}))
    def test_migration_resolves_name_collisions_without_hash_suffixes(self):
        checked,first=self.preview(self.data('http',name='Одинаково',domain='a.example.test'));self.config.write_bytes(first['raw']);checked,second=self.preview(self.data('http',name='Одинаково',domain='b.example.test'));self.config.write_bytes(second['raw']);checked,renamed=self.manager.preview_names(self.engine.snapshot()[1]);self.assertTrue(checked['ok'],checked['output']);self.assertEqual(['be_odinakovo','be_odinakovo_2'],[backend_name(m) for m in clean(renamed['raw'])[1]])
    def test_additional_file_reference_is_not_silently_rewritten(self):
        checked,draft=self.preview(self.data());self.config.write_bytes(draft['raw']);old=backend_name(clean(draft['raw'])[1][0]);(self.extra/'manual.cfg').write_text('frontend extra\n    bind 127.0.0.1:18888\n    mode http\n    default_backend '+old+'\n')
        with self.assertRaises(ValueError):self.manager.preview_names(self.engine.snapshot()[1])
    def test_runtime_labels_follow_real_names(self):
        checked,draft=self.preview(self.data(naming='readable',backend_name='be_site'));self.config.write_bytes(draft['raw']);model=clean(draft['raw'])[1][0]
        with patch.object(self.engine,'runtime',side_effect=lambda cmd:'Version: test\n' if cmd=='show info' else '# pxname,svname,status\nbe_site,srv_192_0_2_15_80,UP\n'):
            catalog=self.manager.catalog();self.assertEqual('Сервер доступен',catalog['service_status'][model['id']]);self.assertEqual('Проверка сервиса',catalog['runtime'][model['id']][0]['display_name'])
    def test_migration_changes_only_names_for_every_protocol(self):
        import re
        from haproxy_studio.services import PRESETS
        from haproxy_studio.naming import changes
        for protocol in PRESETS:
            with self.subTest(protocol=protocol):
                self.config.write_bytes(BASE);checked,draft=self.preview(self.data(protocol));self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw']);before=clean(draft['raw'])[1][0];checked,renamed=self.manager.preview_names(self.engine.snapshot()[1]);self.assertTrue(checked['ok'],checked['output']);after=clean(renamed['raw'])[1][0]
                def body(raw):
                    text=raw.decode();text='\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
                    return re.sub(r'(?m)^(\s*server)\s+\S+',r'\1 SERVER_NAME',text)
                restored=renamed['raw'].decode()
                for old,new in changes(before,after).items():restored=re.sub(r'(?<![\w.-])'+re.escape(new)+r'(?![\w.-])',old,restored)
                self.assertEqual(body(draft['raw']),body(restored.encode()))
