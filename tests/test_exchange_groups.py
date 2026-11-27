import copy
from test_services import ServicesFixture,BASE
from haproxy_studio.importer import Importer
from haproxy_studio.services import clean,bindings
from haproxy_studio.exchange_groups import groups,preview
from haproxy_studio.core import Conflict

class ExchangeGroupTests(ServicesFixture):
    def source(self,tenant='acme',domain='app.example.test'):
        paths=['owa','autodiscover','mapi','Microsoft-Server-ActiveSync','ews','rpc','ecp','oab'];front='frontend exchange\n bind 127.0.0.1:18080\n mode http\n acl domain hdr(host),lower,field(1,:) -i '+domain+'\n';pools=''
        for path in paths:
            role='activesync' if path=='Microsoft-Server-ActiveSync' else path;name='be_exchange_'+tenant+'_'+role
            front+=' acl path_'+role+' path_beg -i /'+path+'\n use_backend '+name+' if domain path_'+role+'\n'
            pools+='backend '+name+'\n mode http\n timeout server 60m\n option httpchk GET /'+path.lower()+'/healthcheck.htm\n http-check expect status 200\n server mail 192.0.2.5:443 ssl verify none check inter 500ms slowstart 30s\n'
        return BASE.split(b'frontend legacy')[0]+(front+pools).encode()
    def adopt(self):
        self.config.write_bytes(self.source());value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);self.assertEqual(8,len(report['candidates']));checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[c['id'] for c in report['candidates']]));self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw']);return self.manager.catalog()
    def request(self,catalog,**extra):return dict(id=catalog['exchange_groups'][0]['id'],revision=catalog['revision'],services=catalog['services'],**extra)
    def test_existing_imports_are_one_group_without_writes_and_noop_is_exact(self):
        c=self.adopt();original=self.config.read_bytes();self.assertEqual(1,len(c['exchange_groups']));self.assertEqual(8,len(c['exchange_groups'][0]['members']));checked,draft=preview(self.manager,self.request(c));self.assertTrue(checked['ok'],checked['output']);self.assertFalse(checked['changed']);self.assertEqual(original,draft['raw']);self.assertEqual(original,self.config.read_bytes())
    def test_health_domains_and_paths_are_changed_in_one_draft(self):
        c=self.adopt();original=self.config.read_bytes();m=c['services'][0];m['import_changes']=dict(confirm=True,health_path='/owa/custom-health.htm',timeout_server='90m');m['aliases']=['other.example.test'];role=c['exchange_groups'][0]['roles'][m['id']];spec=m['import_settings']['paths'][0];m['import_paths']={spec['name']:['/custom-'+role]}
        checked,draft=preview(self.manager,self.request(c));self.assertTrue(checked['ok'],checked['output']);self.assertIn(b'timeout server 90m',draft['raw']);self.assertIn(b'other.example.test',draft['raw']);self.assertIn(b'/owa/custom-health.htm',draft['raw']);self.assertEqual(8,draft['raw'].count(b'slowstart 30s'));self.assertEqual(original,self.config.read_bytes());self.config.write_bytes(draft['raw']);self.assertEqual(1,len(self.manager.catalog()['exchange_groups']))
    def test_toggle_and_delete_preserve_backend_policies(self):
        c=self.adopt();before=self.config.read_bytes()
        for action in ('disable','delete'):
            checked,draft=preview(self.manager,self.request(c,action=action));self.assertTrue(checked['ok'],checked['output']);self.assertNotIn(b'use_backend be_exchange_',draft['raw']);self.assertEqual(8,draft['raw'].count(b'slowstart 30s'));self.assertEqual(before,self.config.read_bytes())
        self.assertEqual(8,len(clean(before)[1]))
    def test_stale_revision_missing_member_and_invalid_member_are_rejected(self):
        c=self.adopt()
        with self.assertRaises(Conflict):preview(self.manager,dict(self.request(c),revision='stale'))
        with self.assertRaises(ValueError):preview(self.manager,dict(self.request(c),services=c['services'][:-1]))
        broken=copy.deepcopy(c);broken['services'][-1]['import_changes']=dict(confirm=True,timeout_server='bad')
        with self.assertRaises(ValueError):preview(self.manager,self.request(broken))
        self.assertEqual(c['revision'],self.engine.snapshot()[1])
    def test_families_keep_different_role_domains_and_do_not_merge_other_farms(self):
        c=self.adopt();models=copy.deepcopy(c['services']);models[-1]['domains']=['unrelated.example.test'];base,_=clean(self.config.read_bytes());self.assertEqual(1,len(groups(models,base,self.settings)));self.assertIn('unrelated.example.test',groups(models,base,self.settings)[0]['domains'])
        models=copy.deepcopy(c['services']);models[-1]['import_pool']='be_exchange_other_oab';self.assertEqual(7,len(groups(models,base,self.settings)[0]['members']))
    def test_enable_after_disable_uses_same_group(self):
        c=self.adopt();checked,draft=preview(self.manager,self.request(c,action='disable'));self.config.write_bytes(draft['raw']);disabled=self.manager.catalog();self.assertFalse(disabled['exchange_groups'][0]['enabled']);checked,draft=preview(self.manager,self.request(disabled,action='enable'));self.assertTrue(checked['ok']);self.assertEqual(8,draft['raw'].count(b'use_backend be_exchange_'))
    def test_unknown_family_uses_current_pool_addresses_not_cached_metadata(self):
        c=self.adopt();base,models=clean(self.config.read_bytes())
        for i,m in enumerate(models):
            old=m['import_pool'];new='custom_'+str(i);base=base.replace('backend '+old+'\n','backend '+new+'\n');m['import_pool']=new;m['backends'][0]['host']='192.0.2.'+str(20+i)
        result=groups(models,base,self.settings);self.assertEqual(1,len(result));self.assertEqual(8,len(result[0]['members']))
    def test_readonly_group_cannot_be_changed(self):
        c=self.adopt();self.settings['read_only']=True
        with self.assertRaises(ValueError):preview(self.manager,self.request(c))

    def test_mail_attachment_uses_live_pool_ips_for_named_families(self):
        c=self.adopt();base,models=clean(self.config.read_bytes())
        for m in models:m['backends'][0]['host']='192.0.2.123'
        mail=self.manager.normalize(self.data('submission',certificate='',backends=[dict(host='192.0.2.5',port=587)]),'f'*16)
        result=groups(models+[mail],base,self.settings)
        self.assertEqual(1,len(result));self.assertIn(mail['id'],result[0]['members'])
