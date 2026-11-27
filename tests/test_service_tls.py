import copy
import json
from pathlib import Path
import subprocess
from unittest.mock import patch
from test_services import ServicesFixture,BASE
from haproxy_studio.service_tls import Resolver
from haproxy_studio.services import clean
from haproxy_studio.certificate_info import metadata

class ServiceTLSTests(ServicesFixture):
    def create_certificate(self,name,domains):
        folder=Path(self.temp.name);key=folder/(name+'.key');crt=folder/(name+'.crt')
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(crt),'-days','2','-subj','/CN='+domains[0],'-addext','subjectAltName='+','.join('DNS:'+n for n in domains)],check=True,capture_output=True)
        file=self.certs/(name+'.pem');file.write_bytes(crt.read_bytes()+key.read_bytes());return file
    def source(self,options):return BASE.replace(b'bind 127.0.0.1:18080',('bind 127.0.0.1:18443 ssl '+options).encode())
    def model(self,domain='app.example.test',**extra):return self.manager.normalize(self.data(domain=domain,port=18443,**extra),'a'*16)
    def test_each_domain_gets_its_bound_certificate_and_label(self):
        app=self.create_certificate('app',['app.example.test']);other=self.create_certificate('other',['other.example.test']);(self.engine.state/'certificate-labels.json').write_text(json.dumps({'app.pem':'App certificate'}))
        self.config.write_bytes(self.source('crt '+str(app)+' crt '+str(other)))
        report=Resolver(self.engine,self.config.read_bytes(),self.engine.certificates()['certificates']).model(self.model(aliases=['other.example.test']))
        self.assertEqual(['ok','ok'],[r['status'] for r in report['rows']]);self.assertEqual(['app.pem','other.pem'],[r['certificates'][0]['name'] for r in report['rows']]);self.assertEqual('App certificate',report['rows'][0]['certificates'][0]['label']);self.assertTrue(report['rows'][0]['certificates'][0]['not_after']);self.assertNotIn('PRIVATE KEY',json.dumps(report))
    def test_uploaded_but_unbound_certificate_is_not_selected(self):
        correct=self.create_certificate('unbound',['new.example.test']);raw=self.source('crt '+str(self.certs/'leaf.pem'))
        report=Resolver(self.engine,raw,self.engine.certificates()['certificates']).model(self.model('new.example.test'))
        self.assertEqual('missing',report['rows'][0]['status']);self.assertEqual([],report['rows'][0]['certificates'])
    def test_relative_crt_base_and_exact_certificate_preferred_to_wildcard(self):
        exact=self.create_certificate('exact',['app.example.test']);wild=self.create_certificate('wild',['*.example.test'])
        raw=self.source('crt wild.pem crt exact.pem').replace(b'global\n',('global\n crt-base '+str(self.certs)+'\n').encode())
        rows=Resolver(self.engine,raw).model(self.model(aliases=['foo.example.test','deep.foo.example.test']))['rows']
        self.assertEqual('exact.pem',rows[0]['certificates'][0]['name']);self.assertEqual(1,len(rows[0]['certificates']));self.assertEqual('wild.pem',rows[1]['certificates'][0]['name']);self.assertEqual('missing',rows[2]['status'])
    def test_crt_list_sni_filters_do_not_expose_excluded_domain(self):
        file=self.root/'cert-list';file.write_text(str(self.certs/'leaf.pem')+' [alpn h2,http/1.1] app.example.test !other.example.test\n')
        rows=Resolver(self.engine,self.source('crt-list '+str(file))).model(self.model(aliases=['other.example.test']))['rows']
        self.assertEqual('ok',rows[0]['status']);self.assertEqual('missing',rows[1]['status'])
    def test_directory_and_external_certificate_paths_supported(self):
        self.create_certificate('extra',['extra.example.test']);rows=Resolver(self.engine,self.source('crt '+str(self.certs))).model(self.model('extra.example.test'))['rows'];self.assertEqual('extra.pem',rows[0]['certificates'][0]['name'])
        external=self.root/'external.pem';external.write_bytes((self.certs/'leaf.pem').read_bytes());row=Resolver(self.engine,self.source('crt '+str(external))).model(self.model())['rows'][0];self.assertEqual('external.pem',row['certificates'][0]['name'])
    def test_same_algorithm_duplicates_are_marked_ambiguous(self):
        other=self.create_certificate('duplicate',['app.example.test']);rows=Resolver(self.engine,self.source('crt '+str(self.certs/'leaf.pem')+' crt '+str(other))).model(self.model())['rows'];self.assertEqual('ambiguous',rows[0]['status'])
    def test_expired_and_future_flags_only_apply_to_matching_bound_certificates(self):
        raw=self.source('crt '+str(self.certs/'leaf.pem'));info=self.engine.certificates()['certificates'][0];info['expired']=True
        row=Resolver(self.engine,raw,[info]).model(self.model())['rows'][0];self.assertEqual('expired',row['status'])
        info=dict(info,expired=False,not_yet_valid=True);row=Resolver(self.engine,raw,[info]).model(self.model())['rows'][0];self.assertEqual('not_yet_valid',row['status'])
    def test_unknown_sources_are_reported_without_guessed_selection(self):
        for options in ['crt /missing/certificate.pem','crt-list /missing/list','crt @store-name']:
            with self.subTest(options=options):
                row=Resolver(self.engine,self.source(options)).model(self.model())['rows'][0];self.assertEqual('unknown',row['status']);self.assertTrue(row['warnings'])
    def test_passthrough_starttls_and_application_modes_do_not_probe_servers(self):
        resolver=Resolver(self.engine,BASE)
        with patch.object(self.engine,'command',side_effect=AssertionError('No file or network probing here')):
            for protocol,mode in [('imaps','passthrough'),('submission','starttls'),('imap','starttls'),('rdp','application'),('ssh','application'),('http','plain')]:
                model=self.manager.normalize(self.data(protocol),'b'*16);report=resolver.model(model);self.assertEqual(mode,report['mode']);self.assertEqual([],report['rows'][0]['certificates'])
    def test_disabled_service_settings_cannot_leak_to_missing_active_listener(self):
        resolver=Resolver(self.engine,BASE);disabled=self.model(enabled=False);first=resolver.model(disabled);self.assertEqual('leaf.pem',first['rows'][0]['certificates'][0]['name'])
        second=resolver.model(self.model());self.assertEqual([],second['rows'][0]['certificates']);self.assertEqual('unknown',second['rows'][0]['status'])
    def test_shared_listener_metadata_and_host_checks_are_cached_per_request(self):
        resolver=Resolver(self.engine,self.source('crt '+str(self.certs/'leaf.pem')))
        original=self.engine.command
        with patch.object(self.engine,'command',side_effect=original) as calls:
            resolver.model(self.model());count=calls.call_count;resolver.model(self.model());self.assertEqual(count,calls.call_count)
    def test_unavailable_openssl_returns_unreadable_metadata(self):
        with patch.object(self.engine,'command',side_effect=FileNotFoundError):self.assertFalse(metadata(self.engine,self.certs/'leaf.pem')['readable'])

    def test_unrelated_expired_certificate_does_not_mark_other_domain_expired(self):
        app=self.create_certificate('app',['app.example.test']);other=self.create_certificate('other',['other.example.test']);raw=self.source('crt '+str(app)+' crt '+str(other));certs=self.engine.certificates()['certificates']
        for item in certs:
            if item['name']=='other.pem':item['expired']=True
        rows=Resolver(self.engine,raw,certs).model(self.model(aliases=['other.example.test']))['rows'];self.assertEqual('ok',rows[0]['status']);self.assertEqual('expired',rows[1]['status'])

    def test_rsa_and_ecdsa_are_shown_as_client_alternatives(self):
        key=self.root/'ec.key';crt=self.root/'ec.crt';target=self.certs/'ec.pem'
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1','-nodes','-keyout',str(key),'-out',str(crt),'-days','2','-subj','/CN=app.example.test','-addext','subjectAltName=DNS:app.example.test'],check=True,capture_output=True)
        target.write_bytes(crt.read_bytes()+key.read_bytes());row=Resolver(self.engine,self.source('crt '+str(target)+' crt '+str(self.certs/'leaf.pem'))).model(self.model())['rows'][0];self.assertEqual('alternatives',row['status']);self.assertEqual(2,len(row['certificates']))

    def test_layered_https_reports_the_local_tls_frontend_not_the_outer_tcp_entry(self):
        raw=BASE+('frontend outer\n bind :443\n mode tcp\n default_backend bridge\nbackend bridge\n mode tcp\n server local 127.0.0.1:8443\nfrontend inner\n bind 127.0.0.1:8443 ssl crt '+str(self.certs/'leaf.pem')+'\n mode http\n default_backend old\n').encode()
        model=self.model();model.update(port=443,listener_port=8443,https_frontend='inner');row=Resolver(self.engine,raw).model(model)['rows'][0];self.assertEqual('inner',row['frontend']);self.assertEqual(443,row['port']);self.assertEqual(8443,row['listener_port']);self.assertEqual('ok',row['status'])

    def test_legacy_unmanaged_tls_service_uses_its_actual_frontend(self):
        resolver=Resolver(self.engine,self.source('crt '+str(self.certs/'leaf.pem')))
        report=resolver.discovered(dict(frontend='legacy',ports=[18443],domains=['app.example.test'],classification=dict(id='https')))
        self.assertEqual('terminate',report['mode']);self.assertEqual('leaf.pem',report['rows'][0]['certificates'][0]['name'])
