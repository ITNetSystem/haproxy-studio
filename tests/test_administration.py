import http.client
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import threading
import unittest
from unittest.mock import patch
from haproxy_studio.accounts import Accounts
from haproxy_studio.core import Conflict
from haproxy_studio.resources import Resources
from haproxy_studio.web import Application
from test_services import ServicesFixture, BASE

class AdministrationTests(ServicesFixture):
    def setUp(self):
        super().setUp();self.resources=Resources(self.engine)
    def test_account_migration_lifecycle_and_recovery(self):
        app=Application(self.settings);accounts=app.accounts;password=(self.engine.state/'initial-password').read_text().strip()
        admin=accounts.authenticate('admin',password);self.assertEqual('admin',admin['role'])
        self.assertNotIn('digest',accounts.list()[0]);self.assertEqual(0o600,(self.engine.state/'users.json').stat().st_mode&0o777)
        viewer=accounts.manage(admin['id'],dict(username='reader',password='a secure password',role='viewer'))
        self.assertEqual('viewer',accounts.authenticate('reader','a secure password')['role'])
        with self.assertRaises(ValueError):accounts.manage(admin['id'],dict(username='reader',password='a secure password'))
        with self.assertRaises(PermissionError):accounts.manage(viewer['id'],dict(username='intruder',password='a secure password'))
        with self.assertRaises(ValueError):accounts.manage(admin['id'],dict(action='delete',id=admin['id'],confirm=True))
        with self.assertRaises(ValueError):accounts.change_password(viewer['id'],'wrong','new secure password','new secure password')
        changed=accounts.change_password(viewer['id'],'a secure password','new secure password','new secure password');self.assertGreater(changed['generation'],viewer['generation'])
        self.assertIsNone(accounts.authenticate('reader','a secure password'))
        accounts.manage(admin['id'],dict(action='update',id=viewer['id'],enabled=False));self.assertIsNone(accounts.authenticate('reader','new secure password'))
        accounts.manage(admin['id'],dict(action='delete',id=viewer['id'],confirm=True));self.assertIsNone(accounts.get(viewer['id']))
        app.reset_password();new=(self.engine.state/'initial-password').read_text().strip();self.assertIsNotNone(accounts.authenticate('admin',new));self.assertIsNone(accounts.authenticate('admin',password))
        self.assertIsNotNone(Accounts(self.engine.state).authenticate('admin',new))
    def test_http_viewer_permissions_and_session_revocation(self):
        app=Application(self.settings);admin=app.accounts.list()[0];app.accounts.manage(admin['id'],dict(username='reader',password='a secure password'))
        server=ThreadingHTTPServer(('127.0.0.1',0),app.handler());thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(path,data=None,session=None):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=8)
            cookie,csrf=session or ('','');headers={'Host':'127.0.0.1:9130','Origin':'http://127.0.0.1:9130','Cookie':cookie,'X-CSRF-Token':csrf,'Content-Type':'application/json'}
            conn.request('GET' if data is None else 'POST','/haproxy-admin/api/'+path,None if data is None else json.dumps(data),headers)
            response=conn.getresponse();value=json.loads(response.read());status=response.status;cookie=response.getheader('Set-Cookie');conn.close();return status,value,cookie
        try:
            _,value,cookie=request('login',dict(username='reader',password='a secure password'));first=(cookie.split(';')[0],value['csrf'])
            _,value,cookie=request('login',dict(username='reader',password='a secure password'));second=(cookie.split(';')[0],value['csrf'])
            for endpoint in ('config','services','overview','certificates','backends'):
                status,value,_=request(endpoint,session=first);self.assertEqual(200,status);self.assertTrue(value['read_only'])
            self.assertEqual(403,request('users',session=first)[0])
            for endpoint in ('preview','apply','services/preview','services/check','services/import/scan','services/import/preview','services/names/preview','services/replace/preview','certificates/upload','certificates/manage','users/manage','backends/preview-delete'):
                self.assertEqual(403,request(endpoint,{},first)[0])
            self.assertEqual(200,request('account/password',dict(current='a secure password',password='updated secure password',confirmation='updated secure password'),first)[0])
            self.assertEqual(401,request('config',session=second)[0]);self.assertEqual(200,request('account',session=first)[0])
        finally:server.shutdown();server.server_close();thread.join()
    def test_certificate_label_delete_and_backup(self):
        self.resources.manage_certificate(dict(action='rename',name='leaf.pem',label='Почта компании'))
        self.assertEqual('Почта компании',self.resources.certificates()['certificates'][0]['label'])
        self.resources.manage_certificate(dict(action='delete',name='leaf.pem',confirm=True));self.assertFalse((self.certs/'leaf.pem').exists());self.assertEqual(1,len(list((self.engine.state/'deleted-certificates').glob('*/leaf.pem'))))
        with self.assertRaises(ValueError):self.resources.manage_certificate(dict(action='delete',name='../private.pem',confirm=True))
    def test_used_certificate_file_directory_and_crt_list_cannot_delete(self):
        for directive in ('crt '+str(self.certs/'leaf.pem'),'crt '+str(self.certs),'crt-list '+str(self.root/'cert-list')):
            (self.root/'cert-list').write_text(str(self.certs/'leaf.pem')+' [alpn h2,http/1.1] app.example.test\n')
            self.config.write_bytes(BASE.replace(b'bind 127.0.0.1:18080',('bind 127.0.0.1:18080 ssl '+directive).encode()))
            self.assertTrue(self.resources.certificate_references('leaf.pem'))
            with self.assertRaisesRegex(ValueError,'используется'):self.resources.manage_certificate(dict(action='delete',name='leaf.pem',confirm=True))
        self.assertTrue((self.certs/'leaf.pem').exists())
    def test_disabled_managed_certificate_dependency(self):
        _,draft=self.preview(self.data('https'));self.config.write_bytes(draft['raw']);model=self.manager.catalog()['services'][0];model['enabled']=False
        _,draft=self.preview(model);self.config.write_bytes(draft['raw']);self.assertTrue(self.resources.certificate_references('leaf.pem'))
    def deletion(self,name,**values):
        catalog=self.resources.backends();item=next(b for b in catalog['backends'] if b['name']==name)
        return self.resources.delete_backend(dict(id=item['id'],revision=catalog['revision'],**values))
    def test_manual_backend_requires_route_decision_and_preserves_managed_blocks(self):
        _,draft=self.preview(self.data('rdp',port=13389));self.config.write_bytes(draft['raw'])
        with self.assertRaisesRegex(ValueError,'замену'):self.deletion('old')
        checked,draft=self.deletion('old',remove_routes=True);self.assertTrue(checked['ok']);self.assertNotIn(b'default_backend old',draft['raw']);self.assertNotIn(b'backend old\n',draft['raw']);self.assertIn(b'# studio-begin',draft['raw'])
        from haproxy_studio.services import clean
        self.assertEqual(1,len(clean(draft['raw'])[1]))
        managed=next(b for b in self.resources.backends()['backends'] if b['managed'])
        with self.assertRaisesRegex(ValueError,'мастера'):self.deletion(managed['name'],remove_routes=True)
    def test_multifile_delete_replaces_references_and_rolls_back(self):
        extra=self.extra/'pools.cfg';extra.write_text('backend spare\n    mode http\n    server second 127.0.0.1:18082\n')
        catalog=self.resources.backends();replacement=next(b['id'] for b in catalog['backends'] if b['name']=='spare')
        checked,draft=self.deletion('old',replacement=replacement);self.assertTrue(checked['ok']);self.assertIn(b'default_backend spare',draft['raw'])
        # Delete a pool declared in conf.d while rewriting references in the main file.
        self.config.write_bytes(BASE.replace(b'default_backend old',b'default_backend spare'))
        before=self.config.read_bytes();before_extra=extra.read_bytes()
        checked,draft=self.deletion('spare',remove_routes=True);self.assertTrue(checked['ok']);self.assertIn(str(extra),draft['files'])
        with patch.object(self.engine,'command',side_effect=[subprocess.CompletedProcess([],1),subprocess.CompletedProcess([],0),subprocess.CompletedProcess([],0)]),patch.object(self.engine,'validate',return_value=dict(ok=True)):
            with self.assertRaisesRegex(ValueError,'восстановлен'):self.engine.apply(draft)
        self.assertEqual(before,self.config.read_bytes());self.assertEqual(before_extra,extra.read_bytes())
        with patch.object(self.engine,'command',return_value=subprocess.CompletedProcess([],0)),patch.object(self.engine,'validate',return_value=dict(ok=True)):
            result=self.engine.apply(draft)
        self.assertNotIn(b'backend spare',extra.read_bytes());self.assertNotIn(b'default_backend spare',self.config.read_bytes())
        checked,restore=self.engine.preview(None,self.engine.snapshot()[1],result['backup']);self.assertTrue(checked['ok']);self.assertEqual(before_extra,restore['files'][str(extra)])
    def test_dynamic_backend_and_panel_protection(self):
        self.config.write_bytes(BASE.replace(b'default_backend old',b'use_backend %[req.hdr(host)]'))
        with self.assertRaisesRegex(ValueError,'динамический'):self.deletion('old',remove_routes=True)
        self.config.write_bytes(BASE.replace(b'127.0.0.1:18081',b'127.0.0.1:9130'))
        with self.assertRaisesRegex(ValueError,'панель'):self.deletion('old',remove_routes=True)
    def test_stale_revision_cannot_delete_and_readonly_cannot_mutate(self):
        catalog=self.resources.backends();self.config.write_bytes(BASE+b'# external\n')
        with self.assertRaises(Conflict):self.resources.delete_backend(dict(id=catalog['backends'][0]['id'],revision=catalog['revision']))
        self.settings['read_only']=True
        with self.assertRaises(ValueError):self.resources.manage_certificate(dict(action='rename',name='leaf.pem',label='Other'))
