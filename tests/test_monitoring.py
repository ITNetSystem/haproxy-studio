import unittest
from unittest.mock import patch
from test_services import ServicesFixture
from haproxy_studio.monitoring import annotate,service_status

class MonitoringTests(unittest.TestCase):
    def model(self,**values):
        return dict(dict(id='0123456789abcdef',name='Почта',enabled=True,health='http',routes=[],fallback_status=0),**values)
    def test_runtime_names_include_service_address_and_route(self):
        model=self.model();rows=[dict(pxname='studio_be_'+model['id'],svname='node1',status='UP'),dict(pxname='manual',svname='legacy',status='UP')]
        sections=[dict(name=rows[0]['pxname'],servers=[dict(name='node1',address='192.0.2.10:443')])]
        annotate(rows,sections,[model]);self.assertEqual('Почта',rows[0]['display_name']);self.assertEqual('192.0.2.10:443',rows[0]['server_address']);self.assertEqual('legacy',rows[1]['display_name'])
    def test_all_exchange_route_pools_determine_service_health_without_default_pool(self):
        model=self.model();model.update(routes=[{'path':'/owa'},{'path':'/ews'}],fallback_status=503)
        routes=[dict(action='backend',rows=[dict(status='UP')]),dict(action='backend',rows=[dict(status='UP')])]
        self.assertEqual('Сервер доступен',service_status(model,[],routes))
        routes[1]['rows']=[dict(status='DOWN')];self.assertEqual('Частично доступен',service_status(model,[],routes))
        routes[0]['rows']=[dict(status='MAINT')];self.assertEqual('Сервер недоступен',service_status(model,[],routes))
    def test_redirect_and_disabled_services_do_not_wait_for_backend(self):
        model=self.model();model.update(http_action='redirect');self.assertEqual('Перенаправление настроено',service_status(model,[],[]))
        model['enabled']=False;self.assertEqual('Выключен',service_status(model,[],[]))
    def test_missing_route_data_is_not_healthy(self):
        model=self.model();model.update(routes=[{}],fallback_status=503)
        self.assertEqual('Ожидание данных',service_status(model,[],[dict(action='backend',rows=[])]))
    def test_primary_pool_still_matters_when_routes_have_a_fallback(self):
        self.assertEqual('Частично доступен',service_status(self.model(),[dict(status='DOWN')],[dict(action='backend',rows=[dict(status='UP')])]))
    def test_disabled_checks_and_denied_paths_do_not_look_down(self):
        model=self.model();model['health']='none';self.assertEqual('Проверки выключены',service_status(model,[],[dict(action='deny',rows=[])]))

class MonitoringIntegrationTests(ServicesFixture):
    def test_catalog_aggregates_route_pools_and_overview_enriches_runtime(self):
        checked,draft=self.preview(self.data('exchange',fallback_status=503));self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw'])
        from haproxy_studio.services import clean
        from haproxy_studio.enterprise import route_key
        model=clean(draft['raw'])[1][0]
        csv='# pxname,svname,status,scur\n'+''.join('studio_be_'+model['id']+'_r'+route_key(model,r)+',node1,UP,0\n' for r in model['routes'] if r['action']=='backend')
        with patch.object(self.engine,'runtime',side_effect=lambda cmd:'Version: test\n' if cmd=='show info' else csv):
            overview=self.engine.overview();catalog=self.manager.catalog()
        self.assertEqual('Сервер доступен',catalog['service_status'][model['id']]);self.assertTrue(all(row['display_name']==model['name'] and row['server_address']=='192.0.2.15:443' and row['route_path'] for row in overview['rows']))
