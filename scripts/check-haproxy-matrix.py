#!/usr/bin/env python3
"""Validate synthetic wizard configs with official HAProxy containers; no host config."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from haproxy_studio.core import Engine,decode
from haproxy_studio.services import ServiceManager,PRESETS
from haproxy_studio.settings import DEFAULTS

BASE='global\n    maxconn 100\ndefaults\n    mode http\n    timeout connect 5s\n    timeout client 30s\n    timeout server 30s\n'

def generate(root):
    root=Path(root);cert=root/'cert.pem';key=root/'key.pem';cases=root/'cases';cases.mkdir()
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','2','-subj','/CN=app.example.test','-addext','subjectAltName=DNS:app.example.test,DNS:other.example.test'],check=True,capture_output=True)
    cert.write_bytes(cert.read_bytes()+key.read_bytes())
    config=root/'haproxy.cfg';config.write_text(BASE)
    settings=copy.deepcopy(DEFAULTS);settings.update(config_file=str(config),extra_config_dir='',certificate_dir=str(root),state_dir=str(root/'state'),ca_bundle=str(cert),read_only=False)
    manager=ServiceManager(Engine(settings))
    count=0
    def save(name,values,baseline=BASE):
        nonlocal count
        models=[manager.normalize(v,format(i+1,'016x')) for i,v in enumerate(values)]
        raw,_=manager.render(baseline,models,probe=False)
        (cases/(name+'.cfg')).write_text(decode(raw).replace(str(root),'/studio-check'));count+=1
    def data(protocol,**changes):
        value=dict(name='Compatibility '+protocol,protocol=protocol,domain='app.example.test',certificate='cert.pem',backends=[dict(host='192.0.2.10',port=PRESETS[protocol][2])]);value.update(changes);return value
    for protocol in PRESETS:save(protocol,[data(protocol)])
    save('rds-token',[data('rds',rds_mode='token')])
    for tls in ('terminate','passthrough'):
        save('shared-sni-'+tls,[data('imaps',tls_mode=tls,sni_routing=True,sni_domains='app.example.test',sni_default=True),data('imaps',tls_mode=tls,sni_routing=True,sni_domains='other.example.test')])
    save('shared-https',[data('https'),data('https',domain='other.example.test')])
    save('preserve-redirect-only',[data('http',domain='_discovery.example.test',backends=[],http_action='redirect',redirect_code=302,http_host_match='raw')])
    save('preserve-cookies-and-health',[data('https',cookie_name='SESSION',backends=[dict(host='192.0.2.10',port=443,cookie_value='first')],upstream_tls=True,upstream_verify=False,upstream_sni=False,upstream_tls_version='TLSv1.2',health='http',health_http_version='1.0',health_host='',timeout=900,tunnel_timeout=3600)])
    save('preserve-tls-check-and-redirect',[data('tls',port=443,sni_routing=True,sni_domains='app.example.test',redirect=True,http_redirect_mode='scheme',proxy_protocol=True,health='tls',health_tls_verify=True,health_tls_name='app.example.test',health_send_proxy=True)])
    layered=BASE+'frontend public_tls\n    bind 0.0.0.0:443\n    mode tcp\n    default_backend bridge\nbackend bridge\n    mode tcp\n    server local 127.0.0.1:8443 send-proxy-v2\nfrontend local_tls\n    bind 127.0.0.1:8443 accept-proxy ssl crt '+str(cert)+'\n    mode http\n    http-request set-header X-Forwarded-Proto https\n    http-request deny deny_status 421\n'
    save('preserve-layered-https',[data('https',https_frontend='local_tls',forward_headers=False)],layered)
    save('rdweb-auto-layered-https',[data('rdwebproxy',redirect=False)],layered)
    save('imported-tcp-fallback',[data('tcp',port=2222,tcp_frontend='legacy_tcp',forward_headers=False,health='tcp')],BASE+'frontend legacy_tcp\n    bind 0.0.0.0:2222\n    mode tcp\n    option tcplog\n')
    save('readable-http',[data('https',naming='readable',name='Company website',backend_name='be_website',backends=[dict(name='web01',host='192.0.2.10',port=443)],upstream_tls=True,upstream_verify=False)])
    save('readable-exchange',[data('exchange',naming='readable',backend_name='be_exchange',fallback_status=503)])
    save('readable-sni',[data('imaps',naming='readable',sni_routing=True,sni_domains='app.example.test',sni_default=True)])
    # Lossless ACL adoption keeps shared pools and inserts each route in place.
    from haproxy_studio.importer import Importer,retained_comment
    def save_acl(name,source):
        nonlocal count
        base,_,candidates,_=Importer(manager).discover(source)
        chosen=[c for c in candidates if c.get('anchors')]
        if not chosen:raise ValueError('ACL matrix fixture was not adopted')
        anchors={i:a for c in chosen for i,a in c['anchors'].items()}
        baseline=''.join(retained_comment(line)+anchors[i] if i in anchors else line for i,line in enumerate(base.splitlines(True)))
        raw,_=manager.render(baseline,[c['model'] for c in chosen],probe=False)
        (cases/(name+'.cfg')).write_text(decode(raw).replace(str(root),'/studio-check'));count+=1
    shared=BASE+'frontend mail_web\n bind 127.0.0.1:18080\n mode http\n acl first hdr(host),lower,field(1,:) -i app.example.test\n acl second hdr(host),lower,field(1,:) -i other.example.test\n acl owa path_beg -i /owa\n use_backend exchange if first owa\n use_backend exchange if second owa\nbackend exchange\n mode http\n balance source\n timeout server 500ms\n server mailbox 192.0.2.10:443 ssl verify none check inter 500ms slowstart 30s\n'
    save_acl('import-shared-domain-path',shared)
    save_acl('import-inline-domain-case',shared.replace('use_backend exchange if first owa','use_backend exchange if { hdr(host) -m str app.example.test } owa').replace('use_backend exchange if second owa','use_backend exchange if { hdr(host) -i other.example.test } owa'))
    save_acl('import-https-sni-http-pool',shared.replace('bind 127.0.0.1:18080','bind 127.0.0.1:18443 ssl crt '+str(cert)).replace('use_backend exchange if first owa','use_backend exchange if { ssl_fc_sni -i app.example.test } owa').replace('use_backend exchange if second owa','use_backend exchange if { ssl_fc_sni -i other.example.test } owa'))
    mixed=BASE+'frontend outer\n bind 0.0.0.0:443\n mode tcp\n tcp-request inspect-delay 5s\n tcp-request content accept if { req.ssl_hello_type 1 }\n acl first req_ssl_sni -i app.example.test\n acl second req.ssl_sni -i other.example.test\n use_backend bridge if first or second\nbackend bridge\n mode tcp\n server local 127.0.0.1:8443 send-proxy-v2\n'+shared[len(BASE):].replace('frontend mail_web\n bind 127.0.0.1:18080','frontend mail_web\n bind 127.0.0.1:8443 accept-proxy ssl crt '+str(cert))
    save_acl('import-conditional-sni-proxy-shared-pool',mixed)
    return count

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--versions',nargs='+',default=['2.4','2.6','2.8','3.0','3.2','3.3','3.4']);args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='studio-compat-') as folder:
        count=generate(folder)
        def run(version):
            if not __import__('re').fullmatch(r'\d+\.\d+',version):raise ValueError('Expected major.minor')
            command=['docker','run','--rm','--user','0','--network','none','--read-only','--tmpfs','/tmp','-v',folder+':/studio-check:ro','--entrypoint','sh','haproxy:'+version,'-ec','haproxy -v | head -1; for f in /studio-check/cases/*.cfg; do if ! haproxy -c -f "$f" >/tmp/check.out 2>&1; then echo "FAILED: $f"; cat /tmp/check.out; exit 1; fi; done']
            result=subprocess.run(command,capture_output=True,text=True,timeout=240)
            return version,result
        failed=False
        with ThreadPoolExecutor(max_workers=3) as pool:
            for version,result in pool.map(run,args.versions):
                print(version+': '+('PASS '+str(count)+' configs' if result.returncode==0 else 'FAIL'),flush=True)
                print(result.stdout.strip(),flush=True)
                if result.returncode:failed=True;print(result.stderr[-4000:],flush=True)
        return 1 if failed else 0
if __name__=='__main__':raise SystemExit(main())
