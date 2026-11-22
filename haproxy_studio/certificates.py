"""Certificate import: validate the leaf/key pair, store private PEM, never return keys."""
import json
import base64
import binascii
import ssl
import time
import os
from pathlib import Path
import re
import secrets
import tempfile

def upload(engine,data):
    if engine.settings['read_only']:raise ValueError('Загрузка сертификатов отключена в режиме наблюдения.')
    certificate=data.get('certificate','');key=data.get('key','');password=data.get('password','');label=data.get('label','Сертификат')
    if not all(isinstance(v,str) for v in (certificate,key,password,label)):raise ValueError('Ожидается PEM-сертификат и приватный ключ.')
    if len(certificate)>524288 or len(key)>524288 or len(password)>1024 or '\n' in password:raise ValueError('Сертификат и ключ — не более 512 КБ каждый; пароль — одна строка до 1024 символов.')
    if not 1<=len(label.strip())<=80 or any(ord(c)<32 for c in label):raise ValueError('Название сертификата: от 1 до 80 обычных символов.')
    pfx=data.get('pfx_base64','')
    if pfx:
        if not isinstance(pfx,str) or len(pfx)>720000:raise ValueError('PFX/P12 должен быть не больше 512 КБ.')
        try:binary=base64.b64decode(pfx,validate=True)
        except (ValueError,binascii.Error):raise ValueError('Некорректный файл PFX/P12.')
        if len(binary)>524288:raise ValueError('PFX/P12 должен быть не больше 512 КБ.')
        with tempfile.TemporaryDirectory(prefix='pkcs12-',dir=engine.state) as temp:
            source=Path(temp)/'input.pfx';source.write_bytes(binary)
            import subprocess
            args=['openssl','pkcs12','-in',str(source),'-nodes','-passin','stdin']
            converted=subprocess.run(args,input=(password+'\n').encode(),capture_output=True,timeout=15,check=False)
            if converted.returncode:
                converted=subprocess.run(args+['-legacy'],input=(password+'\n').encode(),capture_output=True,timeout=15,check=False)
            if converted.returncode:raise ValueError('Не удалось открыть PFX/P12. Проверьте пароль и наличие сертификата с ключом.')
            certificate=converted.stdout.decode('utf8','replace');key='';password=''
    blocks=re.findall(r'-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----',certificate)
    if not blocks:raise ValueError('Не найден PEM-сертификат. Поддерживаются текстовые PEM/CRT и KEY, бинарный PFX/P12 загружается отдельным файлом; DER преобразуйте в PEM.')
    with tempfile.TemporaryDirectory(prefix='certificate-',dir=engine.state) as temporary:
        folder=Path(temporary);leaf=folder/'certificate.pem';private=folder/'key.pem'
        leaf.write_text('\n'.join(blocks)+'\n');private.write_text(key or certificate)
        check=engine.command(['openssl','x509','-in',str(leaf),'-noout','-checkend','0'])
        if check.returncode:raise ValueError('Сертификат повреждён или истёк.')
        start=engine.command(['openssl','x509','-in',str(leaf),'-noout','-startdate']).stdout.decode().strip().partition('=')[2]
        if not start or ssl.cert_time_to_seconds(start)>time.time():raise ValueError('Срок действия сертификата ещё не начался.')
        public=engine.command(['openssl','x509','-in',str(leaf),'-pubkey','-noout'])
        # stdin carries only the password; private key material is in a mode-0700 temporary directory.
        import subprocess
        decrypted=subprocess.run(['openssl','pkey','-in',str(private),'-passin','stdin'],input=(password+'\n').encode(),capture_output=True,timeout=15,check=False)
        if decrypted.returncode:raise ValueError('Приватный ключ не читается. Проверьте файл KEY и его пароль.')
        private.write_bytes(decrypted.stdout)
        key_public=engine.command(['openssl','pkey','-in',str(private),'-pubout'])
        if public.returncode or key_public.returncode or public.stdout.strip()!=key_public.stdout.strip():raise ValueError('Сертификат и приватный ключ не подходят друг к другу.')
        # Validate every supplied chain block, not just the leaf.
        for block in blocks:
            leaf.write_text(block+'\n')
            if engine.command(['openssl','x509','-in',str(leaf),'-noout']).returncode:raise ValueError('Один из сертификатов цепочки повреждён.')
        combined=('\n'.join(blocks)+'\n').encode()+decrypted.stdout
        directory=Path(engine.settings['certificate_dir']);directory.mkdir(parents=True,exist_ok=True)
        name='studio-'+secrets.token_hex(12)+'.pem';destination=directory/name
        with engine.lock:
            fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(combined);stream.flush();os.fsync(stream.fileno())
            labels=engine.state/'certificate-labels.json'
            try:values=json.loads(labels.read_text()) if labels.exists() else {};values[name]=label.strip();tmp=labels.with_suffix('.tmp');tmp.write_text(json.dumps(values));tmp.replace(labels)
            except OSError:
                destination.unlink(missing_ok=True);raise
        engine.audit('certificate-upload',name=name)
        return dict(ok=True,name=name,label=label.strip(),message='Сертификат и ключ проверены и сохранены. Сертификат выбран для сервиса.',certificates=engine.certificates()['certificates'])
