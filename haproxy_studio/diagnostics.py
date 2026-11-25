"""Nonmutating diagnostics. Never return unfiltered HAProxy output or key material."""
import re
from .core import mask,encode

def result(completed, raw, paths=None):
    text=(completed.stdout+completed.stderr).decode('utf-8','replace')
    original=text
    secret_source=raw+b'\n'+b'\n'.join((paths or {}).values())
    secrets=re.findall(r'(?i)(?:stats\s+auth|password|passwd|secret|token)\s+(\S+)',secret_source.decode('utf-8','replace'))
    for block in re.findall(r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)',secret_source.decode('utf-8','replace')):secrets += [line for line in block.splitlines() if line and not line.startswith('-----')]
    def redact(value):
        value=mask(encode(value))[0]
        for secret in secrets:value=value.replace(secret,'[скрыто]')
        return value
    # HAProxy sometimes embeds offending source lines, including credentials.
    text=redact(text)
    text=re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)','[приватный ключ скрыт]',text)
    diagnostics=[]
    sources={name:value.decode('utf-8','replace').splitlines() for name,value in (paths or {}).items()}
    for line in original.splitlines():
        found=re.search(r'\[([^\]]+):(\d+)\]',line)
        item=dict(severity=next((level for level in ('ALERT','WARNING','NOTICE') if '['+level+']' in line),'INFO'),message=redact(line))
        if found:
            name,number=found[1],int(found[2]);lines=sources.get(name,raw.decode('utf-8','replace').splitlines());section='global'
            for source in lines[:number]:
                header=re.match(r'^(global|defaults|frontend|backend|listen)\b(?:\s+(\S+))?',source)
                if header:section=(header[1]+' '+(header[2] or '')).strip()
            item.update(line=number,section=section,source=name)
            if 0<number<=len(lines):item['directive']=redact(lines[number-1]).strip()
        diagnostics.append(item)
    return dict(ok=completed.returncode==0,output=text.strip() or ('Конфигурация проверена HAProxy.' if completed.returncode==0 else 'HAProxy отклонил конфигурацию.'),diagnostics=diagnostics)

def compatibility(binary,command):
    completed=command([binary,'-vv']);text=(completed.stdout+completed.stderr).decode('utf-8','replace')
    library=next((line.strip() for line in text.splitlines() if re.search(r'(?:Built|Running) (?:with|on).*(?:OpenSSL|AWS-LC|LibreSSL|BoringSSL)',line,re.I)),'SSL-библиотека не определена')
    return dict(ssl_library=library,aws_lc='AWS-LC' in text,build_output=text)

def ssl_issues(raw,build):
    result=[]
    if build.get('aws_lc'):
        for number,line in enumerate(raw.decode('utf-8','replace').splitlines(),1):
            if re.match(r'\s*(?:ssl-dh-param-file|tune\.ssl\.default-dh-param)\s',line):
                result.append(dict(line=number,directive=line.strip(),message='AWS-LC не поддерживает эту настройку параметров DH. TLS остаётся включённым. Проверьте сборку и удалите только эту директиву через предварительный просмотр конфигурации.'))
    return result
