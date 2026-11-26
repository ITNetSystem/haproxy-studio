import json
from pathlib import Path
import test_importer
from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean,block,packed
from haproxy_studio.importer import Importer

class AuditRegressions(ServicesFixture):
    manual=test_importer.ImportTests.manual
    def adopt(self,source):
        self.config.write_bytes(source);value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);self.assertEqual(1,len(report['candidates']),report['preserved']);checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[report['candidates'][0]['id']]));self.assertTrue(checked['ok'],checked['output']);self.assertEqual(source,self.config.read_bytes());self.config.write_bytes(draft['raw']);model=self.manager.catalog()['services'][0];checked,again=self.preview(model);self.assertEqual(draft['raw'],again['raw']);return model,draft
    def test_indented_section_headers_are_discovered_and_roundtrip(self):
        source=self.manual().replace(b'frontend public',b'  frontend public').replace(b'\nbackend website',b'\n\tbackend website');self.assertTrue(self.engine.validate(source)['ok']);self.adopt(source)
    def test_isolated_fractional_timeouts_and_different_server_policies_are_retained(self):
        source=self.manual().replace(b'timeout connect 5s',b'timeout connect 500ms').replace(b'check inter 5s',b'check inter 500ms slowstart 30s')+b'    server reserve 192.0.2.16:8080 check inter 3s backup weight 17\n';model,draft=self.adopt(source);self.assertEqual('website',model['import_pool']);self.assertIn(source[source.index(b'backend website\n'):],draft['raw']);self.assertIn(b'timeout connect 500ms',draft['raw'])
    def test_single_case_sensitive_host_acl_keeps_exact_matching(self):
        source=self.manual().replace(b'hdr(host),lower,field(1,:) -i',b'hdr(host) -m str');model,draft=self.adopt(source);self.assertFalse(model['import_acl']['slots'][0]['terms'][0]['ignore_case']);self.assertIn(b'hdr(host) app.example.test',draft['raw'])
    def test_crt_list_and_external_certificate_file_are_not_moved(self):
        external=self.root/'outside';external.mkdir();crt=external/'mail.bundle';crt.write_bytes((self.certs/'leaf.pem').read_bytes());listing=external/'cert-list.txt';listing.write_text(str(crt)+'\n')
        for option in ('crt '+str(crt),'crt-list '+str(listing),'crt '+str(self.certs)+'/'):
            with self.subTest(option=option):
                source=self.manual(tls=True).replace(('crt '+str(self.certs/'leaf.pem')).encode(),option.encode());model,draft=self.adopt(source);self.assertEqual('website',model['import_pool']);self.assertIn(option.encode(),draft['raw']);self.assertIn(b'backend website\n',draft['raw'])
    def test_relative_certificate_under_crt_base_is_retained(self):
        source=self.manual(tls=True).replace(b'    maxconn 100',('    maxconn 100\n    crt-base '+str(self.certs)).encode()).replace(('crt '+str(self.certs/'leaf.pem')).encode(),b'crt leaf.pem');model,draft=self.adopt(source);self.assertIn(b'crt leaf.pem',draft['raw']);self.assertEqual('website',model['import_pool'])
    def test_corrupt_or_duplicate_model_metadata_is_diagnosed(self):
        with self.assertRaisesRegex(ValueError,'объект'):clean(block('a'*16,'model','# studio-model '+packed([])+'\n').encode())
        model=dict(id='a'*16);owned=block('a'*16,'model','# studio-model '+packed(model)+'\n')
        with self.assertRaisesRegex(ValueError,'Повторяющийся'):clean((owned+owned).encode())

    def test_missing_retained_certificate_blocks_preview(self):
        source=self.manual(tls=True).replace(('crt '+str(self.certs/'leaf.pem')).encode(),('crt-list '+str(self.root/'missing-list.txt')).encode());self.config.write_bytes(source);value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);self.assertEqual(1,len(report['candidates']));checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[report['candidates'][0]['id']]));self.assertFalse(checked['ok']);self.assertEqual(source,self.config.read_bytes())
