from test_services import ServicesFixture
from haproxy_studio.services import clean
from haproxy_studio.replacement import preview
from haproxy_studio.core import Conflict

class ReplacementTests(ServicesFixture):
    def portal(self):
        checked,draft=self.preview(self.data(name='Старый портал',port=18443,redirect=True,http_port=18081,http_redirect_location='https://app.example.test/RDWeb/',routes=[dict(path='/remoteDesktopGateway/',match='prefix',action='deny')],cookie_name='PORTAL',backends=[dict(host='192.0.2.15',port=443,cookie_value='stable')],upstream_tls=True,upstream_verify=False));self.assertTrue(checked['ok'],checked['output']);self.config.write_bytes(draft['raw']);return clean(draft['raw'])[1][0]
    def gateway(self,**changes):
        data=self.data('rdgateway',name='Новый шлюз',port=18443,domain='app.example.test',sni_domains='app.example.test',naming='readable');data.update(changes);return data
    def test_atomic_replacement_removes_conflict_and_http_denial_preserves_redirect(self):
        old=self.portal();before=self.config.read_bytes();checked,draft=preview(self.manager,self.gateway(),self.engine.snapshot()[1],old['id'],True)
        self.assertTrue(checked['ok'],checked['output']);models=clean(draft['raw'])[1];self.assertEqual(1,len(models));self.assertEqual(old['id'],models[0]['id']);self.assertEqual('rdgateway',models[0]['protocol']);self.assertFalse(models[0]['upstream_tls']);self.assertFalse(models[0]['proxy_protocol']);self.assertEqual([],models[0]['routes']);self.assertEqual('https://app.example.test/RDWeb/',models[0]['http_redirect_location']);self.assertTrue(models[0]['redirect']);self.assertTrue(any('/remoteDesktopGateway/' in w for w in checked['warnings']));self.assertTrue(any('Cookie' in w for w in checked['warnings']));self.assertEqual(before,self.config.read_bytes());self.assertEqual('service:replace',draft['reason'])
    def test_confirmation_and_revision_are_required(self):
        old=self.portal()
        with self.assertRaises(ValueError):preview(self.manager,self.gateway(),self.engine.snapshot()[1],old['id'],False)
        with self.assertRaises(Conflict):preview(self.manager,self.gateway(),'stale',old['id'],True)
    def test_wrong_domain_port_or_target_protocol_cannot_be_replaced(self):
        old=self.portal()
        for data in (self.gateway(sni_domains='other.example.test'),self.gateway(port=19443),self.gateway(protocol='rdp'),self.gateway(id=old['id'])):
            with self.assertRaises(ValueError):preview(self.manager,data,self.engine.snapshot()[1],old['id'],True)
    def test_http_redirect_can_be_removed_explicitly(self):
        old=self.portal();checked,draft=preview(self.manager,self.gateway(),self.engine.snapshot()[1],old['id'],True,False);self.assertTrue(checked['ok'],checked['output']);self.assertFalse(clean(draft['raw'])[1][0]['redirect'])
    def test_existing_ip_restriction_is_retained(self):
        old=self.portal();old['allowed_ips']='192.0.2.0/24';checked,draft=self.preview(old);self.config.write_bytes(draft['raw']);checked,draft=preview(self.manager,self.gateway(),self.engine.snapshot()[1],old['id'],True);self.assertTrue(checked['ok'],checked['output']);self.assertEqual('192.0.2.0/24',clean(draft['raw'])[1][0]['allowed_ips'])
    def test_path_scoped_http_redirect_requires_manual_agreement(self):
        old=self.portal();old['path']='/portal';old['routes']=[];checked,draft=self.preview(old);self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw'])
        with self.assertRaises(ValueError):preview(self.manager,self.gateway(),self.engine.snapshot()[1],old['id'],True)
