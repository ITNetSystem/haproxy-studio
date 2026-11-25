"""Preserve and verify supplied certificate order without silently trusting a new CA."""
import re

def check(engine,folder,blocks):
    files=[];warnings=[]
    for i,block in enumerate(blocks):
        path=folder/('chain-'+str(i)+'.pem');path.write_text(block+'\n');files.append(path)
    def names(file):
        completed=engine.command(['openssl','x509','-in',str(file),'-noout','-subject','-issuer','-nameopt','RFC2253'])
        if completed.returncode:raise ValueError('Один из сертификатов цепочки повреждён.')
        lines=completed.stdout.decode().splitlines();return tuple(line.partition('=')[2] for line in lines[:2])
    identities=[names(file) for file in files]
    for i in range(len(files)-1):
        if identities[i][1]!=identities[i+1][0]:raise ValueError('Нарушен порядок цепочки сертификатов: после листового должны идти его промежуточные CA. Файлы не изменены.')
        verified=engine.command(['openssl','verify','-no_check_time','-partial_chain','-trusted',str(files[i+1]),str(files[i])])
        if verified.returncode:raise ValueError('Подпись или назначение одного из сертификатов цепочки не прошли проверку.')
    if identities[-1][0]!=identities[-1][1]:warnings.append('Цепочка не заканчивается самоподписанным CA: корневой CA обычно не отправляют. Если последний сертификат не выпущен доверенным корневым CA, добавьте недостающие промежуточные сертификаты.')
    args=['openssl','verify']
    bundle=engine.settings.get('ca_bundle')
    if bundle and bundle!='auto':args+=['-CAfile',bundle]
    if len(files)>1:
        intermediates=folder/'intermediates.pem';intermediates.write_text('\n'.join(blocks[1:])+'\n');args+=['-untrusted',str(intermediates)]
    verified=engine.command(args+[str(files[0])])
    if verified.returncode:warnings.append('Доверие к цепочке не подтверждено настроенным CA bundle. Возможны отсутствующий intermediate или частный корневой CA; для корпоративного CA настройте ca_bundle. SSL/TLS не отключён.')
    return warnings
