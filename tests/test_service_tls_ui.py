import os
from pathlib import Path
import shutil
import subprocess
import unittest

class ServiceTLSUITests(unittest.TestCase):
    def test_group_deduplicates_paths_but_keeps_domains_and_transport_modes(self):
        node=os.environ.get('NODE_BINARY') or shutil.which('node')
        if not node:self.skipTest('Node optional; browser regression covers TLS cards')
        file=Path(__file__).resolve().parents[1]/'haproxy_studio/static/service-tls.js'
        script=r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert'),context={window:{}};
vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);
const cert={label:'Company SSL',name:'company.pem',path:'/certs/company.pem',not_after:'Jan 1 00:00:00 2030 GMT',domains:['app.example.test'],key_algorithm:'rsaEncryption'};
const row={domain:'app.example.test',port:443,frontend:'https',mode:'terminate',status:'ok',message:'Matches domain',certificates:[cert],warnings:[]};
const report={enabled:true,rows:[row]};
const remote={enabled:true,rows:[{domain:'app.example.test',port:993,mode:'passthrough',status:'external',message:'Certificate is on the server',certificates:[],warnings:[]}]};
const html=context.window.StudioTLS.card([report,report,report,remote]);
assert.equal((html.match(/<tr>/g)||[]).length,3); // Header + one HTTPS domain + one passthrough endpoint.
assert.equal((html.match(/Company SSL/g)||[]).length,1);assert(html.includes('Сквозной TLS'));assert(html.includes('RSA'));
assert(html.includes('data-go="certificates"'));
assert(!context.window.StudioTLS.card([remote]).includes('data-go="certificates"'));
const bad=context.window.StudioTLS.card([{enabled:true,rows:[{...row,status:'expired',message:'Expired',certificates:[{...cert,expired:true}]}]}]);
assert(bad.includes('предупреждения'));assert(bad.includes('Истёк'));assert(!bad.includes('PRIVATE KEY'));
'''
        subprocess.run([node,'-e',script,str(file)],check=True,capture_output=True)
