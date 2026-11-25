"""Verify the actual local HAProxy leaf by fingerprint, including accept-proxy binds."""
import hashlib
from pathlib import Path
import shlex
import socket
import ssl
import time
from .services import bindings
from .certificate_info import metadata

def verify(engine,change):
    target=Path(change['target']).resolve();info=metadata(engine,target)
    domain=next(iter(info['domains']),None)
    if not domain:return 0
    if domain.startswith('*.'):domain='studio-certificate-check.'+domain[2:]
    expected=info['fingerprint'].replace(':','').lower();count=0
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    texts=[file.read_text(errors='surrogateescape') for file in engine.config_files()]
    crt_base=next((line.strip().split(None,1)[1] for text in texts for line in text.splitlines() if line.strip().startswith('crt-base ')),'/etc/ssl/private')
    for text in texts:
        for section in bindings(text):
            for bind in section['binds']:
                if not bind['tls']:continue
                tokens=shlex.split(bind['line'],comments=True);refs=[tokens[i+1] for i,t in enumerate(tokens[:-1]) if t=='crt']
                files=[(Path(name) if Path(name).is_absolute() else Path(crt_base)/name).resolve() for name in refs]
                if not any(file==target or (file.is_dir() and file in target.parents) for file in files):continue
                if bind['lo']!=bind['hi']:raise ValueError('Автоматическая проверка сертификата для диапазона TLS-портов недоступна.')
                host='::1' if bind['host']=='::' else '127.0.0.1' if bind['host'] in ('*','0.0.0.0') else bind['host'];last=None
                for attempt in range(8):
                    try:
                        with socket.create_connection((host,bind['lo']),timeout=2) as raw:
                            if 'accept-proxy' in tokens:raw.sendall(b'PROXY TCP4 127.0.0.1 127.0.0.1 53000 443\r\n')
                            with context.wrap_socket(raw,server_hostname=domain) as client:
                                actual=hashlib.sha256(client.getpeercert(binary_form=True)).hexdigest()
                        if actual!=expected:raise ValueError('HAProxy отдаёт другой сертификат по SNI '+domain+'. Старый сертификат будет восстановлен.')
                        last=None;count+=1;break
                    except (OSError,ValueError) as error:last=error;time.sleep(.1)
                if last:raise ValueError('Не подтверждён новый сертификат на локальном TLS-входе '+section['name']+'. Старый сертификат будет восстановлен.')
    return count
