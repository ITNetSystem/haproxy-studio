"""Execute the same frontend selector the wizard uses, without a browser dependency."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

class ExchangeWizardTests(unittest.TestCase):
    def test_new_publication_cannot_inherit_imported_group_mail(self):
        node=os.environ.get('NODE_BINARY') or shutil.which('node')
        if not node:self.skipTest('Node is optional; browser checks exercise the frontend selector')
        source=Path(__file__).resolve().parents[1]/'haproxy_studio/static/exchange.js'
        script=r'''
const vm=require('vm'),fs=require('fs'),assert=require('assert');const context={window:{}};
vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);
const select=context.window.StudioExchange.mailServices;
const catalog={exchange_groups:[{id:'imported',members:['foreign']},{id:'own',native:'root',members:['root','own','own2']}],services:[{id:'foreign',protocol:'imaps',enabled:true,import_pool:'petromir'},{id:'root',protocol:'exchange'},{id:'own',protocol:'submission',enabled:false},{id:'own2',protocol:'tls',classification:{id:'imaps'},enabled:true}]};
assert.equal(select({protocol:'exchange'},catalog).length,0);
assert.equal(select({id:'unknown',protocol:'exchange'},catalog).length,0);
assert.equal(select({id:'imported',protocol:'exchange'},catalog).length,0);
const chosen=select({id:'root'},catalog);
assert.equal(chosen.length,2);assert.equal(chosen[0].id,'own');assert.equal(chosen[0].enabled,false);
chosen[1].enabled=false;assert.equal(catalog.services[3].enabled,true);
'''
        subprocess.run([node,'-e',script,str(source)],check=True,capture_output=True)
