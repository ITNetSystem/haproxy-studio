"""Public certificate metadata and conservative SNI overlap detection."""
import re
import ssl
import time

def metadata(engine,path):
    done=engine.command(['openssl','x509','-in',str(path),'-noout','-subject','-issuer','-dates','-ext','subjectAltName','-fingerprint','-sha256'])
    text=done.stdout.decode('utf-8','replace')
    names=re.findall(r'DNS:([^,\s]+)',text)
    if not names:
        cn=re.search(r'\bCN\s*=\s*([^,\n/]+)',text)
        if cn:names=[cn[1].strip()]
    expire=re.search(r'^notAfter=(.+)$',text,re.M);start=re.search(r'^notBefore=(.+)$',text,re.M)
    try:expired=not expire or ssl.cert_time_to_seconds(expire[1])<=time.time();not_yet_valid=bool(start and ssl.cert_time_to_seconds(start[1])>time.time())
    except ValueError:expired=True;not_yet_valid=False
    fingerprint=re.search(r'Fingerprint=(.+)',text,re.I)
    public=engine.command(['openssl','x509','-in',str(path),'-noout','-text']).stdout.decode('utf-8','replace')
    algorithm=re.search(r'Public Key Algorithm:\s*(\S+)',public)
    return dict(domains=names,expired=expired,not_yet_valid=not_yet_valid,fingerprint=fingerprint[1].strip() if fingerprint else '',key_algorithm=algorithm[1] if algorithm else '',readable=done.returncode==0)

def overlap(a,b):
    if a==b:return True
    def matches(pattern,name):return pattern.startswith('*.') and name.endswith(pattern[1:]) and name.count('.')==pattern.count('.')
    return matches(a,b) or matches(b,a)
