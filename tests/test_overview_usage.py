from unittest.mock import patch
from test_services import ServicesFixture,BASE
from haproxy_studio.services import clean
from haproxy_studio.naming import backend_name
from haproxy_studio.monitoring import backend_usage
from haproxy_studio.core import sections

class OverviewUsageTests(ServicesFixture):
    def sample(self,dynamic=False,extra=False):
        checked,draft=self.preview(self.data('exchange',fallback_status=503,backends=[dict(host='192.0.2.10',port=443),dict(host='192.0.2.11',port=443)]));self.assertTrue(checked['ok']);m=clean(draft['raw'])[1][0]
        unused=b'backend unused_ort_owa\n mode http\n server stale1 192.0.2.10:443 check\n server stale2 192.0.2.11:443 check\nbackend unused_ort_mapi\n mode http\n server stale1 192.0.2.10:443 check\n server stale2 192.0.2.11:443 check\n'
        raw=draft['raw']+unused
        if dynamic:raw+=b'frontend dynamic\n bind 127.0.0.1:19990\n mode http\n use_backend %[req.hdr(x-backend)]\n'
        if extra:(self.extra/'routes.cfg').write_bytes(b'frontend additional\n bind 127.0.0.1:19991\n mode http\n default_backend unused_ort_owa\n')
        self.config.write_bytes(raw);rows=[]
        for r in m['routes']:
            if r['action']=='backend':rows += [backend_name(m,r)+',node'+str(i+1)+',UP,1,L7OK\n' for i,s in enumerate(r['backends'])]
        rows += [name+','+server+',UP,0,L7OK\n' for name in ('unused_ort_owa','unused_ort_mapi') for server in ('stale1','stale2')]
        csv='# pxname,svname,status,scur,check_status\n'+''.join(rows)
        with patch.object(self.engine,'runtime',side_effect=lambda cmd:'Version: test\n' if cmd=='show info' else csv):overview=self.engine.overview()
        return overview,m
    def test_two_servers_are_one_service_and_unused_pools_are_separate(self):
        d,m=self.sample();self.assertEqual(1,len(d['service_groups']));g=d['service_groups'][0];self.assertEqual(2,g['server_count']);self.assertEqual(2,len(g['servers']));self.assertEqual(14,len(g['checks']));self.assertEqual(14,g['scur']);self.assertEqual(2,len(d['unused_groups']));self.assertEqual(4,sum(len(g['checks']) for g in d['unused_groups']));self.assertEqual(18,len(d['rows']));self.assertEqual(0,len(d['unmapped_groups']))
    def test_extra_file_reference_prevents_false_unused_classification(self):
        d,_=self.sample(extra=True);self.assertEqual(2,len(d['service_groups']));self.assertEqual(1,len(d['unused_groups']));self.assertEqual('unused_ort_mapi',d['unused_groups'][0]['name'])
    def test_dynamic_routes_do_not_hide_potentially_used_pools(self):
        d,_=self.sample(dynamic=True);self.assertEqual(0,len(d['unused_groups']));self.assertEqual(3,len(d['service_groups']));self.assertEqual(2,sum(g['usage']=='unknown' for g in d['service_groups']))
    def test_frontend_and_listen_usage_is_static_and_comment_aware(self):
        raw=b'frontend public\n bind :18080\n # default_backend unused\n default_backend active\nbackend active\n server a 192.0.2.1:80\nbackend unused\n server b 192.0.2.2:80\nlisten direct\n bind :19000\n server c 192.0.2.3:80\n'
        self.assertEqual({'active':'active','unused':'unused','direct':'active'},backend_usage(sections(raw)))
    def test_unknown_runtime_pool_is_preserved_in_diagnostics(self):
        self.config.write_bytes(BASE)
        csv='# pxname,svname,status,scur,check_status\nretired,server1,UP,3,L7OK\n'
        with patch.object(self.engine,'runtime',side_effect=lambda cmd:'Version: test\n' if cmd=='show info' else csv):d=self.engine.overview()
        self.assertEqual([],d['service_groups']);self.assertEqual('retired',d['unmapped_groups'][0]['name']);self.assertEqual(3,d['unmapped_groups'][0]['scur'])

    def test_opaque_continued_backend_expression_is_not_called_unused(self):
        raw=b'frontend public\n bind :18080\n use_backend '+bytes([92])+b'\n %[req.hdr(x-backend)]\nbackend selected_by_map\n server app 192.0.2.1:80\n'
        self.assertEqual('unknown',backend_usage(sections(raw))['selected_by_map'])
