"""Read-only inventory independent of the conservative import compiler."""
import hashlib
import re
from .core import sections,encode,mask
from .services import clean,bindings
from .importer import _routing_commands,active,Unsupported

def discover(raw,rows=(),source_spans=(),settings=None):
    original_named={s['name']:s for s in sections(raw)}
    base,models=clean(raw);parsed=bindings(base);named={s['name']:s for s in sections(encode(base))};result=[]
    for front in parsed:
        if front['type'] not in ('frontend','listen') or not front['binds']:continue
        try:routes=_routing_commands(front)
        except Unsupported:routes=[]
        if not routes:continue
        # Preserve conditions verbatim as evidence; do not infer arbitrary ACL semantics.
        for _,parts in routes:
            name=parts[1] if len(parts)>1 else ''
            if '%' in name:continue
            target=named.get(name,{})
            if not target:continue
            servers=target.get('servers',[])
            infrastructure=len(servers)==1 and any(server['address']==(('['+b['host']+']') if ':' in b['host'] else b['host'])+':'+str(b['lo']) for server in servers for s in parsed if s['mode']=='http' for b in s['binds'] if b['tls'] and b['host'] in ('127.0.0.1','::1'))
            used=[r for r in rows if r.get('pxname')==name and r.get('svname') not in ('FRONTEND','BACKEND')]
            domains=[]
            try:
                for _,tokens in active(front):
                    if tokens[0]=='acl' and len(tokens)>3 and ('hdr(host)' in tokens[2] or 'ssl_sni' in tokens[2] or 'ssl_fc_sni' in tokens[2]):
                        if len(parts)<3 or tokens[1] in parts[2:]:domains += [d for d in tokens[3:] if re.fullmatch(r'[a-zA-Z0-9*-]+(?:\.[a-zA-Z0-9*-]+)+',d)]
            except Unsupported:pass
            if any(t in parts for t in ('ssl_fc_sni','req.ssl_sni','req_ssl_sni')):
                domains += [t for t in parts if re.fullmatch(r'[a-zA-Z0-9*-]+(?:\.[a-zA-Z0-9*-]+)+',t) and t not in ('req.ssl_sni',)]
            issue=''
            if not any(b['tls'] for b in front['binds']) and ('ssl_fc_sni' in parts or any('ssl_fc_sni' in line and any(t in line.split() for t in parts[3:]) for _,line in front['lines'] if line.lstrip().startswith('acl '))):
                issue='Условие ssl_fc_sni не получает SNI на входе без bind ssl. Для STARTTLS 143/587 нужен общий пул или отдельные IP/порты; исправление требует явного выбора маршрутизации.'
            pool=next((s for s in parsed if s['name']==name and s['type']=='backend'),None)
            health_path=''
            if pool:
                check=re.search(r'^\s*option httpchk (?:GET|HEAD|OPTIONS) (\S+)', ''.join(l for _,l in pool['lines']),re.M)
                if check:health_path=check[1]
            from .service_types import classify
            from .acl_import import pool_servers
            tls=any(b['tls'] for b in front['binds'])
            try:servers_for_type=pool_servers(pool) if pool else []
            except ValueError:servers_for_type=[]
            mode=front['mode'];port=front['binds'][0]['lo']
            encrypted=tls or port in (443,8443,465,993,995) or any('req.ssl_sni' in line or 'req_ssl_sni' in line for _,line in front['lines'])
            classification=classify(dict(id='0'*16,name=name,backend_name=name,protocol=('https' if tls else 'http') if mode=='http' else ('tls' if encrypted else 'tcp'),port=port,tls_mode='terminate' if tls else 'passthrough' if encrypted and mode=='tcp' else 'plain',import_acl=dict(frontend=front['name'],slots=[dict(terms=[dict(tests=[t for t in parts[3:] if t not in ('or','||')])])]),backends=servers_for_type),parsed,settings)
            exchange=classification['id']=='exchange' or bool(re.fullmatch(r'/(?:owa|autodiscover|mapi|microsoft-server-activesync|ews|rpc|ecp|oab)/healthcheck\.htm',health_path,re.I))
            identifier=hashlib.sha256((front['name']+'\0'+name).encode()).hexdigest()[:16]
            if any(x['id']==identifier for x in result):continue
            line=original_named.get(name,target).get('line');source_name=None
            for start,end,source in source_spans:
                if line and start<=line<=end:source_name=source;line=line-start+1;break
            result.append(dict(classification=classification,infrastructure=infrastructure,source=source_name,exchange=exchange,health_path=health_path,id=identifier,name=name,management='manual',routing_issue=issue,frontend=front['name'],backend=name,domains=list(dict.fromkeys(domains)),ports=[b['lo'] for b in front['binds']],servers=servers,runtime=used,line=line,condition=('Условие содержит защищённые данные; используйте редактор конфигурации.' if '@studio-protected-' in mask(encode(' '.join(parts)))[0] else ' '.join(parts[2:])),status='Сервер доступен' if any(r.get('status')=='UP' for r in used) else 'Сервер недоступен' if used else 'Статистика пока недоступна'))
    return result
