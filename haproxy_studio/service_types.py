"""Application identity is separate from transport/compiler presets. No config writes."""
import ipaddress
import re
import shlex
from .services import PRESETS,bindings
from .naming import backend_name

GENERIC={'http','https','tcp','tls'}
MAIL={25:'smtp',587:'submission',465:'smtps',143:'imap',993:'imaps',110:'pop3',995:'pop3s',4190:'sieve'}
PORTS={**MAIL,22:'ssh',3389:'rdp',3306:'mysql',5432:'postgresql',6379:'redis',6380:'redis'}
EXCHANGE={'owa','ecp','ews','mapi','autodiscover','microsoft-server-activesync','rpc','oab'}

def commands(section):
    for _,line in (section or {}).get('lines',[]):
        try:parts=shlex.split(line,comments=True)
        except ValueError:continue
        if parts:yield parts

def path(value):
    # Only product-specific path components are returned as evidence; never query secrets.
    from urllib.parse import urlsplit
    value=str(value)
    if value.startswith(('http://','https://')):value=urlsplit(value).path
    return value.partition('?')[0].lower().rstrip('/') or '/'

def classify(model,parsed=(),settings=None):
    settings=settings or {};protocol=model.get('protocol','tcp')
    def result(kind,confidence,reason,candidates=(),source='detected'):
        return dict(id=kind,label=PRESETS[kind][0],confidence=confidence,reason=reason,candidates=list(candidates),source=source)
    manual=model.get('service_type_override')
    if manual in PRESETS:
        chosen=result(manual,'explicit','Тип выбран администратором.',source='manual')
        chosen['auto']=classify(dict(model,service_type_override=''),parsed,settings)
        return chosen
    if protocol not in PRESETS:return result('tcp','unknown','Сохранён неизвестный тип; уточните назначение.')
    if protocol not in GENERIC:return result(protocol,'explicit','Тип указан в сохранённой публикации.',source='wizard')
    pools={s['name']:s for s in parsed if s['type'] in ('backend','listen')}
    names=[backend_name(model)]+[backend_name(model,r) for r in model.get('routes',[]) if r.get('action')=='backend']
    selected=[pools[n] for n in names if n in pools]
    tokens=[p for section in selected for p in commands(section)]
    healths={path(model.get('health_path','/'))};paths={path(model.get('path','/')),path(model.get('root_redirect','/'))}
    for route in model.get('routes',[]):
        if route.get('action')!='deny':paths.add(path(route.get('path','/')));healths.add(path(route.get('health_path','/')))
    for p in tokens:
        if p[:2]==['option','httpchk'] and len(p)>3:healths.add(path(p[3]))
        if p[:2]==['http-check','send'] and 'uri' in p:
            i=p.index('uri')
            if i+1<len(p):healths.add(path(p[i+1]))
    imported=model.get('import_acl',{})
    front=next((s for s in parsed if s['name']==imported.get('frontend')),None)
    used={t for slot in imported.get('slots',[]) for term in slot.get('terms',[]) for t in term.get('tests',[]) if not t.startswith('!')}
    scoped=[p for p in commands(front) if p[0]=='acl' and len(p)>3 and p[1] in used]
    for p in scoped:
        if p[2] in ('path','path_beg','path_end','url','url_beg'):
            paths.update(path(v) for v in p[3:] if v.startswith('/'))
    hints=' '.join([model.get('name',''),model.get('import_pool','')]+names).lower()
    def named(pattern):return bool(re.search(r'(?:^|[^a-z0-9])(?:'+pattern+r')(?:$|[^a-z0-9])',hints))
    mode='http' if PRESETS.get(protocol,PRESETS['tcp'])[3]=='http' else 'tcp'
    tls=model.get('tls_mode','plain')
    public=int(model.get('port',0));backends=model.get('backends',[])
    if selected:
        actual=[]
        for p in tokens:
            if p[0]!='server' or len(p)<3:continue
            match=re.fullmatch(r'(\[[^]]+\]|[^:]+):(\d+)',p[2])
            if match:actual.append(dict(host=match[1].strip('[]'),port=int(match[2])))
        backends=actual
    backend_ports={int(s['port']) for s in backends if s.get('port')}
    ports=backend_ports|{public}
    def signature(option):return any(p[:2]==['option',option] for p in tokens)
    def prefix(value):return any(p==value or p.startswith(value+'/') for p in paths|healths)
    if mode=='http':
        for p in healths:
            match=re.fullmatch(r'/(owa|ecp|ews|mapi|autodiscover|microsoft-server-activesync|rpc|oab)/healthcheck\.htm',p)
            if match:return result('exchange','high','Характерная проверка Exchange: '+p+'.')
        if prefix('/owa') or prefix('/mapi') or len({p.split('/')[1] for p in paths if p.startswith('/') and len(p.split('/'))>1}&EXCHANGE)>1:
            return result('exchange','high','Маршруты служб Exchange: OWA/MAPI или несколько связанных служб.')
        if prefix('/remotedesktopgateway'):
            return result('rdgateway','high','Маршрут RD Gateway / RPC over HTTPS.')
        if prefix('/rpc/rpcproxy.dll'):
            return result('https' if tls=='terminate' else 'http','unknown','Маршрут RPC сам по себе не определяет роль приложения.',('exchange','rdgateway'))
        if prefix('/rdweb'):
            return result('rdwebproxy','high','HTTP-маршрут портала RD Web; исходные TLS и редиректы сохраняются.')
        base=settings.get('base_path','/haproxy-admin').rstrip('/')
        local=False
        for server in backends:
            try:loop=ipaddress.ip_address(server['host']).is_loopback
            except ValueError:loop=server.get('host')=='localhost'
            if loop and int(server.get('port',0))==int(settings.get('port',9130)):local=True
        if local or base and any(p==base.lower()+'/api/health' for p in healths):
            return result('studio','high','Локальный адрес настроенной панели или её API healthcheck.')
        scoped_text=' '.join(' '.join(p) for p in tokens+scoped if p[0] in ('http-request','http-response','http-check','acl')).lower()
        if 'websocket' in scoped_text and ('upgrade' in scoped_text or signature('httpchk')):
            return result('websocket','high','Явная проверка или маршрутизация WebSocket Upgrade.')
        if named('websocket|web_socket|wss'):return result('websocket','medium','Указание WebSocket в имени; проверьте назначение.')
        return result('https' if tls=='terminate' else 'http','transport','Определён HTTP-транспорт; признаков конкретного приложения недостаточно.')
    text=' '.join(' '.join(p) for p in tokens if p[0] in ('tcp-check','option')).lower()
    if signature('mysql-check'):return result('mysql','high','Проверка mysql-check.')
    if signature('pgsql-check'):return result('postgresql','high','Проверка pgsql-check.')
    if signature('redis-check') or 'ping' in text and 'pong' in text:return result('redis','high','Проверка Redis PING/PONG.')
    if any('rdp_cookie(msts)' in v for p in tokens for v in p):return result('rds','high','Токенная маршрутизация RDS по cookie msts.')
    if any('rdp-cookie' in v or 'rdp_cookie' in v for p in tokens for v in p):return result('rds','medium','RDP cookie/persistence; уточните роль брокера RDS.',('rdp',))
    if 'ssh-2.0' in text:return result('ssh','high','Проверка приветствия SSH.')
    if tls in ('terminate','passthrough') or 443 in ports or 8443 in ports:
        if named('rdgateway|rd[ _-]gateway|rdg'):return result('rdgateway','medium','Имя RD Gateway и HTTPS-порт; содержимое сквозного TLS не видно.',('rdweb','tls'))
        if named('rdweb|rd[ _-]web|webclient|html5'):return result('rdweb','medium','Имя RD Web и HTTPS-порт; содержимое сквозного TLS не видно.',('rdgateway','tls'))
    if 3389 in ports and named('broker|rdcb|rds_broker'):return result('rds','medium','Порт RDP и указание брокера в имени.',('rdp',))
    smtp=signature('smtpchk') or bool(re.search(r'\behlo\b',text))
    kind=PORTS.get(public)
    if kind is None and len(backend_ports)==1:kind=PORTS.get(next(iter(backend_ports)))
    if smtp:
        if public==465 or tls in ('terminate','passthrough'):return result('smtps','high','SMTP-проверка и TLS с первого байта на входе.')
        return result('submission' if public==587 or public!=25 and 587 in backend_ports else 'smtp','high','Проверка SMTP EHLO и порт сервиса.')
    family=lambda k:{'smtps':'smtp','submission':'smtp','imaps':'imap','pop3s':'pop3'}.get(k,k)
    known_backend=PORTS.get(next(iter(backend_ports))) if len(backend_ports)==1 else None
    if kind and public in PORTS and known_backend and family(kind)!=family(known_backend):return result('tls' if tls!='plain' else 'tcp','unknown','Внешний порт и порт backend указывают на разные протоколы; уточните тип.',(kind,known_backend))
    if kind is None:
        for candidate,pattern in [('mysql','mysql|mariadb'),('postgresql','postgres|postgresql|pgsql'),('redis','redis'),('imaps','imaps'),('imap','imap'),('pop3s','pop3s'),('pop3','pop3'),('smtps','smtps'),('submission','submission'),('smtp','smtp'),('sieve','sieve|managesieve'),('ssh','ssh'),('rdp','rdp')]:
            if named(pattern):return result(candidate,'medium','Указание протокола в имени; нестандартные порты, проверьте назначение.')
    if tls in ('terminate','passthrough'):kind={'smtp':'smtps','submission':'smtps','imap':'imaps','pop3':'pop3s'}.get(kind,kind)
    if kind:return result(kind,'medium','Стандартный внешний порт '+str(public)+'.' if public in PORTS else 'Стандартный порт backend '+str(next(iter(backend_ports)))+'.')
    if tls in ('terminate','passthrough') or public in (443,8443) or backend_ports=={443}:
        return result('tls','unknown','Сквозной/общий TLS: приложение по порту определить нельзя.',('rdgateway','rdweb'))
    return result('tcp','unknown','Общий TCP: признаков конкретного приложения недостаточно.')

def annotate(models,base,settings):
    parsed=bindings(base)
    for model in models:model['classification']=classify(model,parsed,settings)
    return models

def normalize(data,model):
    value=data.get('service_type_override','')
    if not isinstance(value,str) or value and value not in PRESETS:raise ValueError('Выберите тип сервиса из списка мастера.')
    if value:model['service_type_override']=value
    return model


def type_only_change(previous, candidate):
    """Prove that only the optional application label changed."""
    from .services import BLOCK, clean
    from .core import decode
    _, before = clean(previous)
    _, after = clean(candidate)
    if not before or len(before) != len(after):
        return False
    def without_type(model):
        return {k: v for k, v in model.items() if k != 'service_type_override'}
    if any(without_type(a) != without_type(b) for a, b in zip(before, after)):
        return False
    if all(a.get('service_type_override', '') == b.get('service_type_override', '') for a, b in zip(before, after)):
        return False
    def canonical(raw):
        def replace(match):
            body = match[4]
            if match[2] == 'model':
                body = re.sub(r'^# studio-model [^\n]+\n', '', body, count=1, flags=re.M)
            return '# studio-begin ' + match[1] + ' ' + match[2] + '\n' + body + '# studio-end ' + match[1] + ' ' + match[2] + '\n'
        return BLOCK.sub(replace, decode(raw))
    return canonical(previous) == canonical(candidate)
