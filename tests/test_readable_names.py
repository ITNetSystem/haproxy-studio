import hashlib
from unittest.mock import patch
from types import SimpleNamespace
from test_services import ServicesFixture
from haproxy_studio.services import clean
from haproxy_studio.certificates import upload,certificate_stem
from haproxy_studio.certificate_names import preview
from haproxy_studio.core import Conflict

class ReadableNamesTests(ServicesFixture):
    def test_new_acls_readable_and_edit_stable(self):
        checked,draft=self.preview(self.data(name='Exchange PMIR',protocol='exchange'))
        self.assertTrue(checked['ok'],checked['output'])
        self.assertIn(b'acl acl_exchange_pmir_host ',draft['raw'])
        self.assertNotIn(b'acl st_',draft['raw'])
        self.config.write_bytes(draft['raw'])
        checked,again=self.preview(clean(draft['raw'])[1][0])
        self.assertEqual(draft['raw'],again['raw'])

    def test_upload_filename_label_collision_and_dedup(self):
        result=upload(self.engine,dict(certificate=self.cert,key=self.key,label='mail.example.ru'))
        self.assertEqual('mail.example.ru.pem',result['name'])
        self.assertEqual(0o600,(self.certs/result['name']).stat().st_mode&0o777)
        again=upload(self.engine,dict(certificate=self.cert,key=self.key,label='Another name'))
        self.assertEqual(result['name'],again['name'])
        other=(self.crypto.name+'/other.crt')
        from pathlib import Path
        second=upload(self.engine,dict(certificate=Path(other).read_text(),key=self.other_key,label='mail.example.ru'))
        self.assertEqual('mail.example.ru-2.pem',second['name'])
        self.assertEqual('pochta_kompanii',certificate_stem('Почта компании.pem'))
        self.assertNotIn('/',certificate_stem('../../bad.pem'))

    def rename_draft(self):
        checked,service=self.preview(self.data())
        self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(service['raw'])
        before=self.config.read_bytes()
        checked,draft=preview(self.engine,dict(name='leaf.pem',label='mail.example.ru',revision=self.engine.snapshot()[1]))
        self.assertTrue(checked['ok'],checked['output'])
        self.assertEqual(before,self.config.read_bytes());self.assertFalse((self.certs/'mail.example.ru.pem').exists())
        self.assertEqual('mail.example.ru.pem',clean(draft['raw'])[1][0]['certificate'])
        return before,draft

    def test_reviewed_rename_apply_keeps_old_pem_and_updates_model(self):
        _,draft=self.rename_draft()
        with patch.object(self.engine,'command',return_value=SimpleNamespace(returncode=0,stdout=b'',stderr=b'')),patch.object(self.engine,'runtime',return_value=''):
            result=self.engine.apply(draft)
        self.assertTrue(result['ok']);self.assertEqual((self.certs/'leaf.pem').read_bytes(),(self.certs/'mail.example.ru.pem').read_bytes())
        self.assertIn(str(self.certs/'mail.example.ru.pem').encode(),self.config.read_bytes())
        self.assertEqual(0o600,(self.certs/'mail.example.ru.pem').stat().st_mode&0o777)

    def test_failed_reload_rolls_back_alias_and_config(self):
        before,draft=self.rename_draft()
        original=self.engine.command
        def command(args,**kwargs):
            if args==self.settings['reload_command']:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'')
            return original(args,**kwargs)
        with patch.object(self.engine,'command',side_effect=command),patch.object(self.engine,'runtime',return_value=''):
            with self.assertRaises(ValueError):self.engine.apply(draft)
        self.assertEqual(before,self.config.read_bytes());self.assertFalse((self.certs/'mail.example.ru.pem').exists());self.assertTrue((self.certs/'leaf.pem').exists())

    def test_changed_source_and_occupied_target_reject_apply(self):
        _,draft=self.rename_draft()
        (self.certs/'mail.example.ru.pem').write_text('occupied')
        with self.assertRaises(Conflict):self.engine.apply(draft)
        (self.certs/'mail.example.ru.pem').unlink()
        (self.certs/'leaf.pem').write_text(self.cert+self.key+'\n')
        with self.assertRaises(Conflict):self.engine.apply(draft)

    def test_directory_loading_rejects_file_rename(self):
        self.config.write_bytes(self.config.read_bytes().replace(b'bind 127.0.0.1:18080',('bind 127.0.0.1:18443 ssl crt '+str(self.certs)+'/').encode()))
        with self.assertRaisesRegex(ValueError,'каталог crt'):preview(self.engine,dict(name='leaf.pem',label='mail',revision=self.engine.snapshot()[1]))

    def test_legacy_acls_migrate_only_after_review_and_manual_references_block(self):
        _,first=self.preview(self.data(name='Exchange PMIR',protocol='exchange'))
        base,models=clean(first['raw']);models[0].pop('acl_prefix')
        legacy,_=self.manager.render(base,models,probe=False);self.config.write_bytes(legacy)
        _,again=self.preview(clean(legacy)[1][0]);self.assertEqual(legacy,again['raw'])
        checked,draft=self.manager.preview_names(self.engine.snapshot()[1])
        self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'acl acl_exchange_pmir_host ',draft['raw']);self.assertEqual(legacy,self.config.read_bytes())
        self.config.write_bytes(legacy+('\nfrontend manual_acl\n bind 127.0.0.1:18888\n mode http\n http-request deny if st_'+models[0]['id']+'_host\n').encode())
        with self.assertRaisesRegex(ValueError,'ручное правило'):self.manager.preview_names(self.engine.snapshot()[1])

    def test_shared_tls_snapshot_and_extra_file_references_rename_together(self):
        from pathlib import Path
        original=self.config.read_bytes().replace(b'bind 127.0.0.1:18080',('bind 127.0.0.1:18443 ssl crt '+str(self.certs/'leaf.pem')).encode())
        self.config.write_bytes(original);(self.certs/'second.pem').write_text(self.cert+self.key)
        checked,service=self.preview(self.data(port=18443,http_port=18082,bind_address='127.0.0.1',certificate='second.pem',redirect=False))
        self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(service['raw'])
        extra=self.extra/'manual.cfg';extra.write_text('frontend extra_tls\n bind 127.0.0.1:18444 ssl crt '+str(self.certs/'leaf.pem')+'\n mode http\n default_backend old\n')
        checked,draft=preview(self.engine,dict(name='leaf.pem',label='renamed',revision=self.engine.snapshot()[1]))
        self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'renamed.pem',draft['files'][str(extra)])
        restored,_=clean(draft['raw']);self.assertIn('renamed.pem',restored);self.assertNotIn('leaf.pem',restored)
