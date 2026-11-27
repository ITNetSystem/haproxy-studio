from unittest.mock import patch
from test_services import ServicesFixture
from haproxy_studio.naming import backend_name
from haproxy_studio.services import clean

class OverviewGroupingTests(ServicesFixture):
    def overview(self,changes=None,missing=False):
        checked,draft=self.preview(self.data('exchange',fallback_status=503));self.config.write_bytes(draft['raw']);m=clean(draft['raw'])[1][0];routes=[r for r in m['routes'] if r['action']=='backend'];rows=[]
        for i,r in enumerate(routes):
            if missing and i==0:continue
            rows.append(backend_name(m,r)+',node1,'+('DOWN' if changes and i==0 else 'UP')+','+str(i)+',L7OK\n')
        csv='# pxname,svname,status,scur,check_status\n'+''.join(rows)
        with patch.object(self.engine,'runtime',side_effect=lambda cmd:'Version: test\n' if cmd=='show info' else csv):result=self.engine.overview()
        return result,routes
    def test_paths_are_one_service_destination_without_losing_rows(self):
        result,routes=self.overview();self.assertEqual(len(routes),len(result['rows']));self.assertEqual(1,len(result['server_groups']));group=result['server_groups'][0];self.assertEqual(len(routes),len(group['checks']));self.assertEqual(sum(range(len(routes))),group['scur']);self.assertEqual('UP',group['status']);self.assertEqual({r['path'] for r in routes},{r['path'] for r in group['checks']})
    def test_one_down_path_remains_visible_as_partial(self):
        result,_=self.overview(changes=True);group=result['server_groups'][0];self.assertEqual('Частично доступен',group['status']);self.assertTrue(any(c['status']=='DOWN' for c in group['checks']))
    def test_missing_path_is_not_treated_as_healthy(self):
        result,routes=self.overview(missing=True);group=result['server_groups'][0];self.assertEqual('Неполные данные',group['status']);self.assertTrue(group['partial_connections']);self.assertEqual(len(routes),len(group['checks']))
    def test_independent_services_on_same_server_are_not_merged(self):
        from haproxy_studio.monitoring import overview_servers
        a=self.manager.normalize(self.data('https'),'a'*16);b=self.manager.normalize(self.data('https',domain='other.example.test'),'b'*16)
        rows=[dict(pxname=backend_name(m),svname='node1',status='UP',server_address='192.0.2.5:443',scur='1') for m in (a,b)]
        self.assertEqual(2,len(overview_servers(rows,[],[a,b],'',self.settings)))

    def test_imported_exchange_group_is_also_one_destination(self):
        import test_exchange_groups
        from haproxy_studio.importer import Importer
        self.config.write_bytes(test_exchange_groups.ExchangeGroupTests.source(None));value=dict(revision=self.engine.snapshot()[1]);report=Importer(self.manager).scan(value);checked,draft=Importer(self.manager).preview(dict(value,fingerprint=report['fingerprint'],selected=[c['id'] for c in report['candidates']]));self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw']);models=clean(draft['raw'])[1];csv='# pxname,svname,status,scur,check_status\n'+''.join(m['import_pool']+',mail,UP,1,L7OK\n' for m in models)
        with patch.object(self.engine,'runtime',side_effect=lambda cmd:'Version: test\n' if cmd=='show info' else csv):result=self.engine.overview()
        self.assertEqual(1,len(result['server_groups']));group=result['server_groups'][0];self.assertEqual('Exchange — ACME',group['name']);self.assertEqual(8,group['scur']);self.assertEqual(8,len(group['checks']))
