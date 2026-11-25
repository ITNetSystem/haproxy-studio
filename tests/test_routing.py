from unittest.mock import patch
from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean
from haproxy_studio.core import sections
from haproxy_studio.routing import describe

class RoutingTests(ServicesFixture):
    def describe(self,raw):return describe(raw,sections(raw),clean(raw)[1])
    def test_managed_routes_show_name_domain_path_and_real_destination_without_runtime(self):
        checked,draft=self.preview(self.data(name='Портал компании',path='/portal'));self.assertTrue(checked['ok']);self.config.write_bytes(draft['raw'])
        with patch.object(self.engine,'runtime',side_effect=OSError):overview=self.engine.overview()
        cards=[c for s in overview['sections'] for c in s['route_cards'] if c['name']=='Портал компании' and c['kind']=='proxy']
        self.assertEqual(1,len(cards));self.assertEqual(['app.example.test'],cards[0]['domains']);self.assertEqual('/portal',cards[0]['path']);self.assertEqual('192.0.2.15:80',cards[0]['destination']);self.assertTrue(cards[0]['technical_backend'].startswith('studio_be_'))
        self.assertEqual(draft['raw'],self.config.read_bytes())
    def test_redirects_and_denied_exchange_paths_are_visible(self):
        checked,draft=self.preview(self.data('exchange',name='Почта',root_redirect='/owa',redirect=True,fallback_status=503));self.assertTrue(checked['ok'],checked['output'])
        cards=[c for s in self.describe(draft['raw']) for c in s['route_cards'] if c['name']=='Почта']
        self.assertTrue(any(c['kind']=='redirect' and c['destination']=='HTTPS того же домена' for c in cards));self.assertTrue(any(c['kind']=='redirect' and c['destination']=='/owa' for c in cards));self.assertTrue(any(c['kind']=='deny' and c['destination']=='Ответ 403' and c['path']=='/ecp' for c in cards));self.assertTrue(any(c['kind']=='deny' and c['destination']=='Ответ 503' for c in cards));self.assertTrue(any(c['kind']=='proxy' and c['path']=='/owa' for c in cards))
    def test_redirect_only_is_visible_without_a_backend(self):
        checked,draft=self.preview(self.data('http',backends=[],http_action='redirect',name='Перенаправление',redirect_code=302));self.assertTrue(checked['ok']);cards=[c for s in self.describe(draft['raw']) for c in s['route_cards']];self.assertTrue(any(c['name']=='Перенаправление' and '302' in c['condition'] and c['kind']=='redirect' for c in cards))
    def test_bridge_is_identified_by_loopback_tls_destination_and_named_without_hashes(self):
        raw=BASE+b'frontend external\n    bind 127.0.0.1:18443\n    mode tcp\n    default_backend transport\nbackend transport\n    mode tcp\n    server local 127.0.0.1:19443 send-proxy-v2\nfrontend inner\n    bind 127.0.0.1:19443 accept-proxy ssl crt '+str(self.certs/'leaf.pem').encode()+b'\n    mode http\n'
        parsed=self.describe(raw);bridge=next(s for s in parsed if s['name']=='transport');inner=next(s for s in parsed if s['name']=='inner');outer=next(s for s in parsed if s['name']=='external')
        self.assertEqual('Локальная обработка HTTPS',bridge['display_name']);self.assertEqual('Локальный вход HTTPS',inner['display_name']);self.assertEqual('Остальные HTTPS-сайты',outer['route_cards'][0]['name']);self.assertIn('127.0.0.1:19443',outer['route_cards'][0]['destination'])
    def test_unknown_manual_condition_is_not_translated_as_a_known_service(self):
        raw=BASE.replace(b'default_backend old',b'use_backend old if old_host');parsed=self.describe(raw);card=next(s for s in parsed if s['name']=='legacy')['route_cards'][0];self.assertEqual('old',card['name']);self.assertIn('Ручное условие',card['condition']);self.assertEqual('if old_host',card['technical_condition'])
    def test_backend_names_available_even_with_no_health_rows(self):
        checked,draft=self.preview(self.data(name='Сайт'));self.assertTrue(checked['ok']);parsed=self.describe(draft['raw']);backend=next(s for s in parsed if s['type']=='backend' and s['name'].startswith('studio_be_'));self.assertEqual('Сайт',backend['display_name'])
    def test_dedicated_tcp_uses_connections_not_domain_paths(self):
        checked,draft=self.preview(self.data('rdp',name='Рабочий стол'));self.assertTrue(checked['ok']);cards=[c for s in self.describe(draft['raw']) for c in s['route_cards'] if c['name']=='Рабочий стол'];self.assertEqual(1,len(cards));self.assertEqual('Все подключения',cards[0]['condition']);self.assertEqual([],cards[0]['domains'])
    def test_sni_default_is_described_as_fallback_not_as_a_domain_match(self):
        checked,draft=self.preview(self.data('tls',port=18443,sni_routing=True,sni_domains='app.example.test',sni_default=True));self.assertTrue(checked['ok']);cards=[c for s in self.describe(draft['raw']) for c in s['route_cards'] if c['technical_backend'].startswith('studio_be_')];self.assertTrue(any(c['condition']=='По имени TLS (SNI)' for c in cards));self.assertTrue(any(c['condition']=='Остальные подключения (по умолчанию)' for c in cards))
    def test_http_exception_shows_its_actual_paths(self):
        checked,draft=self.preview(self.data(http_exceptions=['/health'],redirect=True));self.assertTrue(checked['ok']);cards=[c for s in self.describe(draft['raw']) for c in s['route_cards']];self.assertTrue(any(c['kind']=='proxy' and c['path']=='/health' and 'без перенаправления' in c['condition'] for c in cards))
