from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean,bindings
from haproxy_studio.starttls import inspect,preview
from haproxy_studio.core import Conflict

class StarttlsRepairTests(ServicesFixture):
    def source(self):
        return BASE+b'''frontend mail_smtp_587
 bind 127.0.0.1:587
 mode tcp
 log global
 option tcplog
 timeout client 1m
 use_backend dag_a if { ssl_fc_sni mail.a.example.test }
 use_backend dag_alias if { ssl_fc_sni alias.a.example.test }
 use_backend farm_b if { ssl_fc_sni mail.b.example.test }
 default_backend dag_a
backend dag_a
 mode tcp
 balance roundrobin
 option smtpchk EHLO haproxy-check
 server a1 192.0.2.15:587 check port 587
 server a2 192.0.2.16:587 check port 587
backend dag_alias
 mode tcp
 balance roundrobin
 option smtpchk EHLO haproxy-check
 server alias1 192.0.2.15:587 check port 587
 server alias2 192.0.2.16:587 check port 587
backend farm_b
 mode tcp
 option smtpchk EHLO haproxy-check
 server b 192.0.2.99:587 check port 587
'''
    def request(self):
        plan=inspect(self.manager)[0];self.assertEqual('',plan['error'])
        return dict(frontend=plan['frontend'],revision=self.engine.snapshot()[1],bindings=[dict(key=row['key'],address='127.0.0.1',port=19001+i) for i,row in enumerate(plan['rows'])])
    def test_inspect_deduplicates_alias_pools_without_splitting_dag(self):
        self.config.write_bytes(self.source());raw=self.config.read_bytes();plan=inspect(self.manager)[0]
        self.assertEqual('',plan['error']);self.assertEqual(2,len(plan['rows']));self.assertEqual(['dag_a','dag_alias'],plan['rows'][0]['pools']);self.assertEqual(2,len(plan['rows'][0]['servers']));self.assertEqual('127.0.0.1',plan['rows'][0]['address']);self.assertEqual('',plan['rows'][1]['address']);self.assertEqual(raw,self.config.read_bytes())
    def test_preview_uses_dedicated_endpoints_and_preserves_source_pools(self):
        self.config.write_bytes(self.source());raw=self.config.read_bytes();checked,draft=preview(self.manager,self.request())
        self.assertTrue(checked['ok'],checked['output']);self.assertEqual(raw,self.config.read_bytes());base,models=clean(draft['raw']);self.assertEqual(2,len(models));self.assertTrue(all(m['protocol']=='submission' and not m['sni_routing'] and m['tls_mode']=='plain' for m in models));self.assertEqual([2,1],[len(m['backends']) for m in models]);self.assertTrue(all(m['client_timeout']==60 and m['timeout']==30 and m['log_global'] for m in models));self.assertIn(b'timeout client 60s',draft['raw']);self.assertIn(b'timeout server 30s',draft['raw']);self.assertNotIn(b'ssl_fc_sni',draft['raw']);self.assertNotIn('mail_smtp_587',[s['name'] for s in bindings(base)]);self.assertIn(b'backend dag_alias\n',draft['raw']);self.assertIn(b'check port 587',draft['raw'])
    def test_duplicate_bindings_missing_destination_and_stale_request_rejected(self):
        self.config.write_bytes(self.source());request=self.request();request['bindings'][1].update(request['bindings'][0]);request['bindings'][1]['key']=inspect(self.manager)[0]['rows'][1]['key']
        with self.assertRaises(ValueError):preview(self.manager,request)
        request=self.request();request['bindings'][1]['address']=''
        with self.assertRaises(ValueError):preview(self.manager,request)
        request=self.request();request['revision']='stale'
        with self.assertRaises(Conflict):preview(self.manager,request)
    def test_additional_security_policy_blocks_automatic_replacement(self):
        self.config.write_bytes(self.source().replace(b' option tcplog',b' option tcplog\n tcp-request connection reject if { src 192.0.2.1 }'))
        plan=inspect(self.manager)[0];self.assertIn('tcp-request',plan['error'])
        with self.assertRaises(ValueError):preview(self.manager,dict(frontend=plan['frontend'],revision=self.engine.snapshot()[1],bindings=[]))
    def test_independent_healthcheck_port_is_not_dropped(self):
        self.config.write_bytes(self.source().replace(b'check port 587',b'check port 1587'));self.assertIn('healthcheck',inspect(self.manager)[0]['error'])
    def test_other_services_roundtrip_while_fixing_starttls(self):
        checked,old=self.preview(self.data('exchange',backends=[dict(host='192.0.2.15',port=443),dict(host='192.0.2.16',port=443)]));self.assertTrue(checked['ok']);old_models=clean(old['raw'])[1];self.config.write_bytes(old['raw']+self.source()[len(BASE):]);checked,draft=preview(self.manager,self.request());self.assertTrue(checked['ok'],checked['output']);self.assertEqual(old_models,clean(draft['raw'])[1][:len(old_models)])

    def test_failed_reload_restores_original_starttls_frontend(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        self.config.write_bytes(self.source());before=self.config.read_bytes();checked,draft=preview(self.manager,self.request());self.assertTrue(checked['ok'])
        original=self.engine.command
        def command(args,**kwargs):
            if args==self.settings['reload_command']:return SimpleNamespace(returncode=1,stdout=b'',stderr=b'')
            return original(args,**kwargs)
        with patch.object(self.engine,'command',side_effect=command),patch.object(self.engine,'runtime',return_value=''):
            with self.assertRaises(ValueError):self.engine.apply(draft)
        self.assertEqual(before,self.config.read_bytes())

    def test_mixed_anonymous_condition_is_not_mistaken_for_pure_sni(self):
        self.config.write_bytes(self.source().replace(b'{ ssl_fc_sni mail.a.example.test }',b'{ ssl_fc_sni mail.a.example.test } or { src 192.0.2.123 }'))
        self.assertIn('другое условие',inspect(self.manager)[0]['error'])

    def test_wildcard_conflict_names_destinations_before_render(self):
        from unittest.mock import patch
        self.config.write_bytes(self.source());request=self.request()
        for row in request['bindings']:row.update(address='*',port=587)
        with patch.object(self.manager,'render') as render:
            with self.assertRaisesRegex(ValueError,r'\*:587.*dag_a.*farm_b'):preview(self.manager,request)
            render.assert_not_called()
