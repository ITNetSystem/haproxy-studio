from pathlib import Path
import subprocess
from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean
from haproxy_studio.importer import Importer
from haproxy_studio.certificate_info import metadata

class PublicationSelectionTests(ServicesFixture):
    def expired(self,name='expired.pem',domain='unrelated.example.test'):
        valid=self.root/'temporary.crt';key=Path(self.crypto.name)/'leaf.key'
        subprocess.run(['openssl','req','-x509','-key',str(key),'-out',str(valid),'-days','2','-subj','/CN='+domain,'-addext','subjectAltName=DNS:'+domain],capture_output=True,check=True)
        target=self.certs/name
        request=self.root/'expired.csr';database=self.root/'index.txt';database.write_text('');serial=self.root/'serial';serial.write_text('01\n');config=self.root/'ca.cnf'
        config.write_text('[ca]\ndefault_ca=issuer\n[issuer]\ndatabase='+str(database)+'\nserial='+str(serial)+'\nnew_certs_dir='+str(self.root)+'\ndefault_md=sha256\npolicy=policy\nx509_extensions=extensions\n[policy]\ncommonName=supplied\n[extensions]\nsubjectAltName=DNS:'+domain+'\n')
        subprocess.run(['openssl','req','-new','-key',str(key),'-out',str(request),'-subj','/CN='+domain],capture_output=True,check=True)
        subprocess.run(['openssl','ca','-batch','-selfsign','-config',str(config),'-cert',str(valid),'-keyfile',str(key),'-in',str(request),'-out',str(target),'-notext','-startdate','20200101000000Z','-enddate','20200102000000Z'],capture_output=True,check=True)
        target.write_bytes(target.read_bytes()+key.read_bytes());self.assertTrue(metadata(self.engine,target)['expired']);return target
    def layered(self):
        return BASE.split(b'frontend legacy')[0]+('frontend HTTPS_sni_in_443\n bind 127.0.0.1:18443\n mode tcp\n tcp-request inspect-delay 5s\n tcp-request content accept if { req.ssl_hello_type 1 }\n default_backend bk_local_https_termination\nbackend bk_local_https_termination\n mode tcp\n server local 127.0.0.1:19443 send-proxy-v2\nfrontend HTTP_in_443\n bind 127.0.0.1:19443 ssl crt '+str(self.certs/'leaf.pem')+' accept-proxy\n mode http\n').encode()
    def test_rdweb_auto_selects_proven_local_https_listener(self):
        raw=self.layered();self.config.write_bytes(raw)
        checked,draft=self.preview(self.data('rdwebproxy',port=18443,bind_address='127.0.0.1',redirect=False))
        self.assertTrue(checked['ok'],checked['output']);model=clean(draft['raw'])[1][0];self.assertEqual('HTTP_in_443',model['https_frontend']);self.assertEqual(19443,model['listener_port']);self.assertEqual(18443,model['route_port']);self.assertIn(b'http-request redirect location /RDWeb/',draft['raw']);self.assertEqual(raw,clean(draft['raw'])[0].encode())
        self.config.write_bytes(draft['raw']);checked,again=self.preview(model);self.assertFalse(checked['changed'])
    def test_converting_existing_passthrough_rdweb_removes_old_sni_and_auto_selects_https(self):
        self.config.write_bytes(self.layered());checked,old=self.preview(self.data('rdweb',port=18443,bind_address='127.0.0.1',sni_domains='app.example.test'));self.assertTrue(checked['ok']);self.config.write_bytes(old['raw']);identifier=clean(old['raw'])[1][0]['id']
        checked,draft=self.preview(self.data('rdwebproxy',id=identifier,port=18443,bind_address='127.0.0.1',redirect=False));self.assertTrue(checked['ok'],checked['output']);self.assertEqual('HTTP_in_443',clean(draft['raw'])[1][0]['https_frontend']);self.assertNotIn(('acl st_'+identifier+'_sni').encode(),draft['raw'])
    def test_existing_imported_portal_can_be_explicitly_replaced_with_rdweb_proxy(self):
        from haproxy_studio.replacement import preview
        self.config.write_bytes(self.layered());checked,old=self.preview(self.data('https',port=18443,bind_address='127.0.0.1',https_frontend='HTTP_in_443',imported=True,redirect=False,root_redirect=''));self.assertTrue(checked['ok']);self.config.write_bytes(old['raw']);old_model=clean(old['raw'])[1][0]
        data=self.data('rdwebproxy',port=18443,bind_address='127.0.0.1',redirect=False)
        with self.assertRaisesRegex(ValueError,'Подтвердите'):preview(self.manager,data,self.engine.snapshot()[1],old_model['id'],False)
        checked,draft=preview(self.manager,data,self.engine.snapshot()[1],old_model['id'],True);self.assertTrue(checked['ok'],checked['output']);models=clean(draft['raw'])[1];self.assertEqual(1,len(models));self.assertEqual(old_model['id'],models[0]['id']);self.assertEqual('rdwebproxy',models[0]['protocol']);self.assertEqual('HTTP_in_443',models[0]['https_frontend']);self.assertIn(b'http-request redirect location /RDWeb/',draft['raw']);self.assertIn('TLS принимает HAProxy',' '.join(checked['summary']))
    def test_transport_bridge_is_not_offered_as_a_separate_legacy_tcp_service(self):
        self.config.write_bytes(self.layered());report=Importer(self.manager).scan(dict(revision=self.engine.snapshot()[1]));self.assertEqual([],report['candidates']);self.assertTrue(any('мост' in item['reason'] for item in report['preserved']))
    def test_tcp_443_without_verified_tls_bridge_is_not_guessed(self):
        self.config.write_bytes(self.layered().replace(b'127.0.0.1:19443 send-proxy-v2',b'192.0.2.4:19443 send-proxy-v2'))
        with self.assertRaisesRegex(ValueError,'не подтверждён'):self.preview(self.data('rdwebproxy',port=18443,bind_address='127.0.0.1',redirect=False))
    def test_unrelated_expired_certificate_does_not_block_website_certificate_check(self):
        old=self.expired();model=self.manager.normalize(self.data(certificates=['expired.pem']),'a'*16);self.manager.certificate_check(model)
        model=self.manager.normalize(self.data(domain='unrelated.example.test',certificate=old.name),'a'*16)
        with self.assertRaisesRegex(ValueError,'истёкший'):self.manager.certificate_check(model)
    def source(self,old):
        return BASE.split(b'frontend legacy')[0]+('frontend mail_https\n bind 127.0.0.1:18443 ssl crt '+str(old)+' crt '+str(self.certs/'leaf.pem')+'\n mode http\n acl first hdr(host),lower,field(1,:) -i app.example.test\n acl second hdr(host),lower,field(1,:) -i other.example.test\n use_backend shared if first\n use_backend shared if second\nbackend shared\n mode http\n server mailbox 192.0.2.5:443 ssl verify none check\n').encode()
    def test_expired_original_bind_certificate_is_one_warning_not_per_backend_rejection(self):
        old=self.expired(domain='app.example.test');raw=self.source(old);self.config.write_bytes(raw);value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value)
        self.assertEqual(1,len(report['candidates']),report);self.assertEqual(1,len(report['warnings']));self.assertIn('mail_https',report['warnings'][0]);self.assertIn('expired.pem',report['warnings'][0]);self.assertFalse(any('истёк' in x['reason'] for x in report['preserved']))
        checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[report['candidates'][0]['id']]));self.assertTrue(checked['ok'],checked['output']);self.assertEqual(raw,self.config.read_bytes());self.assertIn(('crt '+str(old)).encode(),draft['raw'])
        self.config.write_bytes(draft['raw']);checked,again=self.preview(self.manager.catalog()['services'][0]);self.assertTrue(checked['ok']);self.assertFalse(checked['changed'])
    def test_missing_original_certificate_still_allows_analysis_but_never_reload(self):
        raw=self.source(self.certs/'missing.pem');self.config.write_bytes(raw);value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);self.assertEqual(1,len(report['candidates']),report);self.assertEqual(1,len(report['warnings']))
        checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[report['candidates'][0]['id']]));self.assertFalse(checked['ok']);self.assertFalse(checked['baseline']['ok']);self.assertEqual(raw,self.config.read_bytes())
    def test_https_frontend_can_import_routes_selected_by_terminated_tls_sni(self):
        raw=self.source(self.certs/'leaf.pem').replace(b'use_backend shared if first',b'use_backend shared if { ssl_fc_sni -i app.example.test }').replace(b'use_backend shared if second',b'use_backend shared if { ssl_fc_sni -i other.example.test }');self.config.write_bytes(raw);value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);self.assertEqual(1,len(report['candidates']),report)
        checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[report['candidates'][0]['id']]));self.assertTrue(checked['ok'],checked['output']);self.assertEqual('ssl_fc_sni',clean(draft['raw'])[1][0]['import_acl']['fetch'])
    def test_new_imported_alias_still_requires_valid_matching_certificate(self):
        old=self.expired();raw=self.source(old);self.config.write_bytes(raw);value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[report['candidates'][0]['id']]));self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw']);model=self.manager.catalog()['services'][0];model['aliases'].append('new.example.test')
        with self.assertRaisesRegex(ValueError,'не покрывает'):self.preview(model)
