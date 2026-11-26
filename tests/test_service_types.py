import copy
import unittest
from unittest.mock import patch
from pathlib import Path
from test_services import ServicesFixture,BASE
from haproxy_studio.services import PRESETS,bindings,clean
from haproxy_studio.service_types import classify
from haproxy_studio.importer import Importer

class ServiceTypeTests(unittest.TestCase):
    def model(self,kind='tcp',port=18000,**extra):
        value=dict(id='a'*16,name='Synthetic',protocol=kind,port=port,tls_mode='plain',backends=[dict(host='192.0.2.5',port=18000)],health_path='/',path='/');value.update(extra);return value
    def test_all_wizard_types_have_detection_examples(self):
        self.assertEqual(24,len(PRESETS))
        examples={
          'exchange':self.model('https',443,tls_mode='terminate',health_path='/mapi/healthcheck.htm'),
          'https':self.model('https',443,tls_mode='terminate'),
          'http':self.model('http',80),
          'websocket':self.model('https',443,name='WebSocket',tls_mode='terminate'),
          'rdgateway':self.model('tls',443,name='RD Gateway',tls_mode='passthrough'),
          'rdweb':self.model('tls',443,name='RD Web',tls_mode='passthrough'),
          'rdwebproxy':self.model('https',443,tls_mode='terminate',root_redirect='/RDWeb/webclient/'),
          'studio':self.model('https',443,tls_mode='terminate',backends=[dict(host='127.0.0.1',port=9130)]),
          'rds':self.model('tcp',3389,name='RDS broker'),
          'rdp':self.model('tcp',3389),
          'ssh':self.model('tcp',22),
          'smtp':self.model('tcp',25),
          'submission':self.model('tcp',587),
          'smtps':self.model('tls',465,tls_mode='passthrough'),
          'imap':self.model('tcp',143),
          'pop3':self.model('tcp',110),
          'sieve':self.model('tcp',4190),
          'imaps':self.model('tls',993,tls_mode='passthrough'),
          'pop3s':self.model('tls',995,tls_mode='passthrough'),
          'mysql':self.model('tcp',3306),
          'postgresql':self.model('tcp',5432),
          'redis':self.model('tcp',6379),
          'tcp':self.model('tcp',18000),
          'tls':self.model('tls',443,tls_mode='passthrough'),
        }
        self.assertEqual(set(PRESETS),set(examples))
        for expected,model in examples.items():
            with self.subTest(expected=expected):self.assertEqual(expected,classify(model)['id'])
    def test_explicit_wizard_selections_are_preserved_on_custom_ports(self):
        for kind in PRESETS:
            if kind in ('tcp','tls','http','https'):continue
            with self.subTest(kind=kind):self.assertEqual(kind,classify(self.model(kind,49100))['id'])
    def test_protocol_checks_take_precedence_over_ports(self):
        for option,expected in [('mysql-check','mysql'),('pgsql-check','postgresql'),('redis-check','redis'),('smtpchk EHLO synthetic','smtp')]:
            raw='backend shared\n mode tcp\n option '+option+'\n server node 192.0.2.1:18000\n';model=self.model(backend_name='shared')
            self.assertEqual(expected,classify(model,bindings(raw))['id'])
    def test_rds_tokens_and_websocket_upgrade(self):
        model=self.model(backend_name='shared');self.assertEqual('rds',classify(model,bindings('backend shared\n persist rdp-cookie\n'))['id'])
        model=self.model('https',443,tls_mode='terminate',backend_name='shared');self.assertEqual('websocket',classify(model,bindings('backend shared\n http-request set-header Upgrade websocket\n'))['id'])
    def test_opaque_443_does_not_claim_gateway_or_web_portal(self):
        result=classify(self.model('tls',443,tls_mode='passthrough'));self.assertEqual('tls',result['id']);self.assertEqual('unknown',result['confidence']);self.assertIn('rdgateway',result['candidates'])
    def test_only_service_scoped_paths_are_used(self):
        raw='frontend common\n bind :443 ssl crt example.pem\n mode http\n acl owa path_beg /owa\nbackend exchange\n option httpchk GET /owa/healthcheck.htm\nbackend ordinary\n option httpchk GET /health\n'
        model=self.model('https',443,tls_mode='terminate',backend_name='ordinary');self.assertEqual('https',classify(model,bindings(raw))['id'])
        model['backend_name']='exchange';self.assertEqual('exchange',classify(model,bindings(raw))['id'])
    def test_conflicting_standard_ports_are_ambiguous(self):
        result=classify(self.model('tcp',22,backends=[dict(host='192.0.2.1',port=5432)]));self.assertEqual('tcp',result['id']);self.assertEqual('unknown',result['confidence']);self.assertEqual({'ssh','postgresql'},set(result['candidates']))
    def test_rpc_endpoint_alone_is_not_claimed_as_rd_gateway(self):
        result=classify(self.model('https',443,tls_mode='terminate',path='/rpc/rpcproxy.dll'));self.assertEqual('unknown',result['confidence']);self.assertIn('rdgateway',result['candidates']);self.assertIn('exchange',result['candidates'])
    def test_no_inplace_mutation_or_secret_in_evidence(self):
        model=self.model('https',443,tls_mode='terminate',health_path='/owa/healthcheck.htm?token=private');before=copy.deepcopy(model);result=classify(model);self.assertEqual(before,model);self.assertEqual('exchange',result['id']);self.assertNotIn('private',str(result))
    def test_manual_override_retains_auto_result(self):
        model=self.model('https',443,tls_mode='terminate',health_path='/owa/healthcheck.htm',service_type_override='https');result=classify(model);self.assertEqual('https',result['id']);self.assertEqual('manual',result['source']);self.assertEqual('exchange',result['auto']['id'])

class ServiceTypeIntegrationTests(ServicesFixture):
    def source(self):
        return BASE.split(b'frontend legacy')[0]+b'frontend mail_web\n bind 127.0.0.1:18080\n mode http\n acl first hdr(host),lower,field(1,:) -i app.example.test\n acl second hdr(host),lower,field(1,:) -i other.example.test\n acl owa path_beg /owa\n use_backend shared if first owa\n use_backend shared if second owa\nbackend shared\n mode http\n option httpchk GET /owa/healthcheck.htm\n server mailbox 192.0.2.5:443 ssl verify none check\n'
    def adopt(self,types=None):
        self.config.write_bytes(self.source());value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);candidate=report['candidates'][0];self.assertEqual('exchange',candidate['classification']['id'])
        checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[candidate['id']],types={candidate['id']:types} if types else {}));self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw']);return draft
    def test_existing_import_is_classified_without_reimport_or_writes(self):
        draft=self.adopt();catalog=self.manager.catalog();model=catalog['services'][0];self.assertEqual('exchange',model['classification']['id']);self.assertEqual('http',model['protocol']);self.assertEqual(draft['raw'],self.config.read_bytes());self.assertNotIn('classification',clean(draft['raw'])[1][0])
        checked,again=self.preview(model);self.assertFalse(checked['changed']);self.assertEqual(draft['raw'],again['raw'])
        overview=self.engine.overview();self.assertEqual('exchange',overview['publications'][0]['classification']['id'])
    def test_override_from_import_and_later_change_only_affects_metadata(self):
        first=self.adopt('https');model=self.manager.catalog()['services'][0];self.assertEqual('https',model['classification']['id']);self.assertEqual('exchange',model['classification']['auto']['id']);model['service_type_override']='exchange';checked,changed=self.preview(model);self.assertTrue(checked['ok']);self.assertTrue(checked['changed']);strip=lambda raw:'\n'.join(l for l in raw.decode().splitlines() if not l.lstrip().startswith('#'))
        self.assertEqual(strip(first['raw']),strip(changed['raw']));self.assertEqual('http',clean(changed['raw'])[1][0]['protocol']);self.assertEqual([],clean(changed['raw'])[1][0]['routes']);self.assertIn(b'backend shared\n',changed['raw'])
    def test_invalid_override_is_rejected(self):
        self.adopt();model=self.manager.catalog()['services'][0];model['service_type_override']='arbitrary directives\nbackend injected'
        with self.assertRaises(ValueError):self.preview(model)

    def test_type_change_applies_without_runtime_or_reload(self):
        self.adopt();model=self.manager.catalog()['services'][0];model['service_type_override']='https'
        checked,draft=self.preview(model);self.assertTrue(checked['metadata_only'])
        self.settings['reload_command']=['/bin/false'];self.settings['health_command']=['/bin/false']
        with patch.object(self.engine,'runtime',side_effect=AssertionError('Runtime must not be called')):
            result=self.engine.apply(draft)
        self.assertTrue(result['metadata_only']);self.assertEqual('https',self.manager.catalog()['services'][0]['classification']['id'])
    def test_metadata_flag_cannot_skip_reload_for_routing_change(self):
        checked,initial=self.preview(self.data());self.config.write_bytes(initial['raw']);model=self.manager.catalog()['services'][0];model['backends'][0]['port']=444
        checked,draft=self.preview(model);draft['metadata_only']=True;before=self.config.read_bytes()
        with self.assertRaises(ValueError):self.engine.apply(draft)
        self.assertEqual(before,self.config.read_bytes())
