"""Regression coverage for certificate entry points and viewer-only rendering."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

class CertificateUITests(unittest.TestCase):
    def test_upload_is_available_for_empty_and_populated_lists_only_when_writable(self):
        node=os.environ.get('NODE_BINARY') or shutil.which('node')
        if not node:self.skipTest('Node is optional; browser checks cover certificate UI')
        source=Path(__file__).resolve().parents[1]/'haproxy_studio/static/admin.js'
        script=r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert'),context={window:{}};
vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);
const render=context.window.StudioAdmin.certificates;
const empty=render({read_only:false,certificates:[]});
assert(empty.includes('data-cert-upload'));assert(empty.includes('Сертификатов пока нет'));
const certificate={name:'company.pem',label:'Company',used_by:[],details:'Certificate details'};
const populated=render({read_only:false,certificates:[certificate]});
assert(populated.includes('data-cert-upload'));assert(populated.includes('data-cert-replace="company.pem"'));
for(const certificates of [[],[certificate]]){
 const readonly=render({read_only:true,certificates});
 assert(!readonly.includes('data-cert-upload'));assert(!readonly.includes('data-cert-replace'));
}
'''
        subprocess.run([node,'-e',script,str(source)],check=True,capture_output=True)
