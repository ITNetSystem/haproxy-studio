"""Typed service compiler. Managed blocks round-trip through the main config."""
import base64
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import ssl
import time
from pathlib import Path
from .core import Conflict, decode, encode, mask
from .naming import backend_name

PRESETS = {
    'exchange': ('Microsoft Exchange / Outlook',443,443,'http','terminate','OWA, Autodiscover, MAPI, ActiveSync, EWS, RPC, OAB и управляемый доступ к ECP.'),
    'https': ('Сайт HTTPS',443,80,'http','terminate','Домен и сертификат на HAProxy. Сервер может работать по HTTP.'),
    'http': ('Сайт HTTP',80,80,'http','plain','Обычный сайт без TLS. Для публичного сайта лучше HTTPS.'),
    'websocket': ('WebSocket / веб-приложение',443,80,'http','terminate','HTTPS с поддержкой долгих WebSocket-соединений.'),
    'rdgateway': ('RDS: RD Gateway — шлюз HTTPS',443,443,'tcp','passthrough','Внешний RDP через HTTPS до Windows RD Gateway. Сквозной TLS, сертификат на Windows; TCP/443, без публикации UDP/3391.'),
    'rdweb': ('RDS: RD Web Access — портал HTTPS',443,443,'tcp','passthrough','Веб-портал RDS по HTTPS: /RDWeb/. Сквозной TLS до IIS, сертификат на Windows. Не создаёт роль RD Gateway.'),
    'rds': ('RDS: прямой RDP через брокер (3389)',3389,3389,'tcp','plain','Ферма рабочих столов RDS: вход через брокер или маршрутизация на Session Host по токену брокера. Шифрование и NLA остаются на Windows.'),
    'rdp': ('Удалённый рабочий стол RDP',3389,3389,'tcp','plain','Прозрачная передача RDP. Шифрование и учётные записи на Windows-сервере.'),
    'ssh': ('SSH',22,22,'tcp','plain','Прозрачная передача SSH. Выберите свободный внешний порт, например 2222.'),
    'smtp': ('Почта SMTP / STARTTLS',25,25,'tcp','plain','SMTP и STARTTLS проходят без изменения. Сертификат хранится на почтовом сервере.'),
    'submission': ('Отправка почты STARTTLS',587,587,'tcp','plain','Передача SMTP submission и STARTTLS без расшифровки на HAProxy.'),
    'smtps': ('Почта SMTPS',465,465,'tcp','passthrough','TLS до почтового сервера или расшифровка сертификатом на HAProxy.'),
    'imap': ('Почта IMAP / STARTTLS',143,143,'tcp','plain','IMAP и STARTTLS проходят без изменения. TLS и сертификат обслуживает почтовый сервер.'),
    'pop3': ('Почта POP3 / STARTTLS',110,110,'tcp','plain','POP3 и переход на TLS передаются прозрачно почтовому серверу.'),
    'sieve': ('Почтовые фильтры ManageSieve / STARTTLS',4190,4190,'tcp','plain','Управление почтовыми фильтрами Sieve; STARTTLS остаётся на почтовом сервере.'),
    'imaps': ('Почта IMAPS',993,993,'tcp','passthrough','Защищённый доступ к почтовому ящику.'),
    'pop3s': ('Почта POP3S',995,995,'tcp','passthrough','Защищённое получение почты по POP3.'),
    'mysql': ('База данных MySQL',3306,3306,'tcp','plain','TCP-передача MySQL. Рекомендуется ограничить доступ по IP.'),
    'postgresql': ('База данных PostgreSQL',5432,5432,'tcp','plain','Нативное согласование PostgreSQL TLS сохраняется на сервере.'),
    'redis': ('Redis',6379,6379,'tcp','plain','TCP-передача Redis. Настройте пароль сервера и список разрешённых IP.'),
    'tcp': ('Другой TCP-сервис',8080,8080,'tcp','plain','Прозрачная передача произвольного TCP-протокола.'),
    'tls': ('Другой TLS-сервис',8443,443,'tcp','passthrough','Сквозной TLS или TLS-терминация на HAProxy.'),
}

BLOCK = re.compile(r'(?m)^[ \t]*# studio-begin ([a-f0-9]{16}) (\w+) ([a-f0-9]{64})\n(.*?)^[ \t]*# studio-end \1 \2\n?', re.S)
TLSBASE = re.compile(r'(?m)^[ \t]*# studio-tls-base ([A-Za-z0-9_=-]+)\n([^\n]*\n?)')
HEADER = re.compile(r'^(global|defaults|frontend|backend|listen|userlist|resolvers|peers|cache|program|ring|mailers)\b(?:\s+(\S+))?')

def packed(value):
    return base64.urlsafe_b64encode(json.dumps(value,ensure_ascii=True,separators=(',',':')).encode()).decode()

def unpacked(value):
    return json.loads(base64.urlsafe_b64decode(value).decode())

def block(identifier, kind, body):
    body = body if body.endswith('\n') else body+'\n'
    return '# studio-begin '+identifier+' '+kind+' '+hashlib.sha256(encode(body)).hexdigest()+'\n'+body+'# studio-end '+identifier+' '+kind+'\n'

def clean(raw):
    source = decode(raw)
    models = []
    for match in BLOCK.finditer(source):
        if hashlib.sha256(encode(match[4])).hexdigest()!=match[3]:
            raise ValueError('Служебный блок изменён вручную. Восстановите его из истории перед работой с мастером.')
        if match[2]=='model':
            found=re.search(r'^# studio-model (\S+)$',match[4],re.M)
            if not found:raise ValueError('Повреждены данные сервиса мастера.')
            model=unpacked(found[1])
            if model.get('id')!=match[1]:raise ValueError('Повреждён идентификатор сервиса.')
            models.append(model)
    source=BLOCK.sub('',source)
    def restore(match):
        entry=unpacked(match[1])
        if hashlib.sha256(encode(match[2])).hexdigest()!=entry['hash']:
            raise ValueError('TLS-вход изменён вручную. Восстановите его перед работой с мастером.')
        return entry['line']
    source=TLSBASE.sub(restore,source)
    if '# studio-begin ' in source or '# studio-tls-base ' in source:
        raise ValueError('Незавершённый служебный блок. Восстановите конфигурацию из истории.')
    return source,models

def number(value,label,minimum=1,maximum=65535):
    if isinstance(value,bool) or not re.fullmatch(r'\d+',str(value)):
        raise ValueError(label+': укажите целое число.')
    result=int(value)
    if not minimum<=result<=maximum:raise ValueError(label+': допустимо от '+str(minimum)+' до '+str(maximum)+'.')
    return result

def hostname(value,label='Адрес сервера',allow_underscore=False):
    if not isinstance(value,str):raise ValueError(label+': укажите IP или домен.')
    value=value.strip().rstrip('.')
    if value.startswith('[') and value.endswith(']'):value=value[1:-1]
    try:return str(ipaddress.ip_address(value))
    except ValueError:pass
    try:value=value.encode('idna').decode('ascii').lower()
    except UnicodeError:raise ValueError(label+': некорректный домен.')
    if len(value)>253 or not value or not all(re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?' if allow_underscore else r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in value.split('.')):
        raise ValueError(label+': укажите только домен или IP, без протокола, порта и пути.')
    return value

def address(host,port):
    return ('['+host+']' if ':' in host else host)+':'+str(port)

def bindings(source):
    lines=source.splitlines(keepends=True);result=[];current=None;default_mode='tcp';in_defaults=False
    for index,line in enumerate(lines):
        found=HEADER.match(line)
        if found:
            in_defaults=found[1]=='defaults'
            current=dict(name=found[2] or found[1],type=found[1],start=index,mode=default_mode,binds=[],lines=[])
            result.append(current)
        elif current:
            current['lines'].append((index,line))
            parts=line.strip().split()
            if len(parts)>1 and parts[0]=='mode':
                current['mode']=parts[1]
                if in_defaults:default_mode=parts[1]
            if len(parts)>1 and parts[0]=='bind':
                for target in parts[1].split(','):
                    found=re.fullmatch(r'(\[[^]]+\]|[^:]*):(\d+)(?:-(\d+))?',target)
                    if found:
                        current['binds'].append(dict(host=found[1].strip('[]') or '*',lo=int(found[2]),hi=int(found[3] or found[2]),index=index,line=line,tls='ssl' in parts))
    return result

def overlaps(a,b):
    return a==b or a in ('*','0.0.0.0','::') or b in ('*','0.0.0.0','::')

class ServiceManager:
    def __init__(self,engine):self.engine=engine

    def normalize(self,data,identifier):
        if not isinstance(data,dict):raise ValueError('Ожидаются поля сервиса.')
        protocol=data.get('protocol','https')
        if protocol not in PRESETS:raise ValueError('Выберите поддерживаемый протокол.')
        if protocol=='exchange':
            data=dict(data)
            for key,value in dict(upstream_tls=True,health='http',health_path='/owa/healthcheck.htm',timeout=3600).items():data.setdefault(key,value)
        if protocol=='rds':
            data=dict(data)
            data.setdefault('balance','leastconn')
            data.setdefault('timeout',28800)
        if protocol in ('rdgateway','rdweb'):
            data=dict(data)
            data.setdefault('balance','source')
            data.setdefault('timeout',28800 if protocol=='rdgateway' else 3600)
            data.setdefault('sni_routing',True)
            data.setdefault('sni_domains',data.get('domains') or data.get('domain',''))
        redirect_only=protocol=='http' and data.get('http_action')=='redirect'
        if redirect_only:
            data=dict(data);data.setdefault('health','none')
        preset=PRESETS[protocol];name=data.get('name','')
        if not isinstance(name,str) or not 1<=len(name.strip())<=80 or any(ord(c)<32 for c in name):raise ValueError('Название сервиса: от 1 до 80 обычных символов.')
        mode=data.get('tls_mode',preset[4]);http=preset[3]=='http'
        allowed=('plain','terminate') if http else (('passthrough','terminate') if protocol in ('smtps','imaps','pop3s','tls','rdgateway','rdweb') else ('plain',))
        if mode not in allowed:raise ValueError('Выбранный TLS-режим несовместим с протоколом. RDP, SSH и STARTTLS передаются прозрачно.')
        if protocol in ('https','websocket','exchange') and mode!='terminate':raise ValueError('Для HTTPS выберите TLS-терминацию. Для сквозного TLS используйте шаблон TLS-сервис.')
        if protocol in ('rdgateway','rdweb') and mode!='passthrough':raise ValueError('RD Gateway / RD Web в этом шаблоне используют сквозной TLS до Windows. Сертификат устанавливается на Windows-сервере.')
        if protocol=='http' and mode!='plain':raise ValueError('Для защищённого сайта используйте шаблон HTTPS.')
        public=data.get('bind_address','*')
        if public!='*':
            try:public=str(ipaddress.ip_address(public))
            except (ValueError,TypeError):raise ValueError('Адрес прослушивания: * или IP этого сервера.')
        domain=hostname(data.get('domain',''),'Домен сайта',allow_underscore=protocol=='http') if http else ''
        if http:
            try:ipaddress.ip_address(domain);raise ValueError('Для сайта укажите доменное имя, а не IP.')
            except ValueError as error:
                if 'Для сайта' in str(error):raise
        path=data.get('path','/') if http else '/'
        if not isinstance(path,str) or not re.fullmatch(r'/[A-Za-z0-9/_~.\-]*',path) or '..' in path or len(path)>256:raise ValueError('Путь должен начинаться с / и не содержать пробелы, параметры или ..')
        path=path.rstrip('/') or '/'
        backends=data.get('backends',[])
        if not isinstance(backends,list) or not (0 if redirect_only else 1)<=len(backends)<=16:raise ValueError('Добавьте от 1 до 16 серверов.')
        servers=[]
        for row in backends:
            if not isinstance(row,dict):raise ValueError('Некорректная строка сервера.')
            servers.append(dict(host=hostname(row.get('host','')),port=number(row.get('port',preset[2]),'Порт сервера'),weight=number(row.get('weight',1),'Вес',1,256),backup=row.get('backup',False) is True))
        if servers and all(s['backup'] for s in servers):raise ValueError('Нужен хотя бы один основной сервер, не только резервные.')
        balance=data.get('balance','roundrobin')
        if balance not in ('roundrobin','leastconn','source'):raise ValueError('Некорректная балансировка.')
        cidrs=data.get('allowed_ips','')
        if not isinstance(cidrs,str) or len(cidrs)>4096:raise ValueError('Некорректный список разрешённых IP.')
        networks=[]
        for item in re.split(r'[\s,;]+',cidrs.strip()):
            if not item:continue
            try:networks.append(str(ipaddress.ip_network(item,strict=False)))
            except ValueError:raise ValueError('В списке доступа используйте IP или CIDR, например 192.0.2.10 или 10.0.0.0/8.')
        if len(networks)>64:raise ValueError('Не более 64 разрешённых сетей.')
        health=data.get('health','tcp')
        if health not in ('none','tcp','http','smtp','tls') or health=='http' and not http or health=='smtp' and protocol not in ('smtp','submission','smtps'):raise ValueError('HTTP-проверка доступна только для веб-сервисов.')
        health_path=data.get('health_path','/')
        if not isinstance(health_path,str) or not re.fullmatch(r'/[A-Za-z0-9/_~.\-?=&%]*',health_path) or len(health_path)>256:raise ValueError('Некорректный путь проверки доступности.')
        upstream_tls=data.get('upstream_tls',False) is True
        if mode=='passthrough' and upstream_tls:raise ValueError('При сквозном TLS повторное шифрование к серверу не требуется.')
        upstream_name=hostname(data.get('upstream_name') or domain or servers[0]['host'],'TLS-имя сервера') if upstream_tls else ''
        host_override=data.get('host_override','').strip() if http else ''
        if host_override:host_override=hostname(host_override,'Заголовок Host')
        certificate=data.get('certificate','') if mode=='terminate' else ''
        if mode=='terminate':self.certificate_path(certificate)
        model=dict(id=identifier,name=name.strip(),protocol=protocol,enabled=data.get('enabled',True) is True,port=number(data.get('port',preset[1]),'Внешний порт'),bind_address=public,domain=domain,path=path,tls_mode=mode,certificate=certificate,backends=servers,balance=balance,allowed_ips=' '.join(networks),health=health,health_path=health_path,upstream_tls=upstream_tls,upstream_verify=data.get('upstream_verify',True) is True,upstream_name=upstream_name,host_override=host_override,redirect=http and mode=='terminate' and data.get('redirect',True) is True,http_port=number(data.get('http_port',80),'Порт HTTP'),strip_prefix=http and path!='/' and data.get('strip_prefix',False) is True,hsts=http and mode=='terminate' and data.get('hsts',False) is True,timeout=number(data.get('timeout',3600),'Таймаут',5,86400),check_interval=number(data.get('check_interval',5),'Интервал проверок',1,300),maxconn=number(data.get('maxconn',0),'Лимит на сервер',0,100000),proxy_protocol=data.get('proxy_protocol',False) is True)
        if protocol in ('rdgateway','rdweb'):
            if upstream_tls or model['proxy_protocol'] or health not in ('none','tcp'):raise ValueError('RD Gateway / RD Web: используйте TCP-проверку без дополнительного TLS и PROXY protocol до Windows.')
        if protocol=='rds':
            model['rds_mode']=data.get('rds_mode','broker')
            if model['rds_mode'] not in ('broker','token'):raise ValueError('Выберите схему подключения RDS.')
            if upstream_tls or model['proxy_protocol'] or health not in ('none','tcp'):raise ValueError('RDS передаётся без изменения: отключите дополнительный TLS, PROXY protocol и используйте TCP-проверку.')
            if model['rds_mode']=='token':
                for server in servers:
                    try:ipaddress.IPv4Address(server['host'])
                    except ipaddress.AddressValueError:raise ValueError('Для токенного режима укажите реальные IPv4-адреса всех Session Host, на которые перенаправляет брокер.')
        if model['redirect'] and model['http_port']==model['port']:raise ValueError('HTTP и HTTPS должны использовать разные порты.')
        for server in servers:
            try:loop=ipaddress.ip_address(server['host']).is_loopback
            except ValueError:loop=server['host']=='localhost'
            if loop and server['port']==model['port'] and model['bind_address'] in ('*','0.0.0.0','::','127.0.0.1','::1'):raise ValueError('Внешний порт и локальный порт сервера совпадают: получится петля. Выберите другой внешний порт.')
        from .enterprise import normalize
        from .preserve import normalize as preserve
        from .naming import normalize as normalize_names
        return normalize_names(data,preserve(self,data,normalize(self,data,model)))

    def certificate_path(self,name):
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]+\.pem',name):raise ValueError('Выберите сертификат из списка или загрузите PEM/CRT и ключ.')
        root=Path(self.engine.settings['certificate_dir']).resolve();path=root/name
        if not path.is_file() or path.resolve().parent!=root:raise ValueError('Сертификат не найден в настроенном каталоге.')
        if re.search(r'[\s#\\]',str(path)):raise ValueError('Путь сертификата должен быть без пробелов и служебных символов.')
        return path

    def certificate_check(self,model):
        from .enterprise import certificates
        certificates(self,model)

    def catalog(self):
        raw,revision=self.engine.snapshot();base,models=clean(raw)
        rows=self.engine.overview()['rows'] if models else []
        runtime={m['id']:[row for row in rows if row['pxname']==backend_name(m) and row['svname'] not in ('FRONTEND','BACKEND')] for m in models}
        from .enterprise import route_key
        route_runtime={m['id']:[dict(path=row['path'],action=row['action'],rows=[entry for entry in rows if entry['pxname']==backend_name(m,row) and entry['svname'] not in ('FRONTEND','BACKEND')]) for index,row in enumerate(m.get('routes',[]))] for m in models}
        from .monitoring import service_status
        statuses={m['id']:service_status(m,runtime[m['id']],route_runtime[m['id']]) for m in models}
        return dict(service_status=statuses,route_runtime=route_runtime,runtime=runtime,services=models,revision=revision,read_only=self.engine.settings['read_only'],presets=[dict(id=k,label=v[0],port=v[1],backend_port=v[2],kind=v[3],tls=v[4],description=v[5]) for k,v in PRESETS.items()],certificates=self.engine.certificates()['certificates'],https_frontends=[dict(name=s['name'],port=b['lo'],address=b['host']) for s in bindings(base) if s['type']=='frontend' and s['mode']=='http' for b in s['binds'] if b['tls']],listeners=[dict(name=s['name'],mode=s['mode'],bindings=[dict(address=b['host'],port=b['lo'],tls=b['tls']) for b in s['binds']]) for s in bindings(base) if s['binds']],notes=['DNS домена должен указывать на этот сервер. Внешний firewall и правила облачного провайдера настраиваются у провайдера.','Веб-сайты могут разделять HTTP/HTTPS-вход. RDP, почта и сквозной TLS используют отдельный TCP-порт.'])

    def render(self,base,models,probe=True,owned_bindings=None):
        lines=base.splitlines(keepends=True);parsed=bindings(base)
        extra=''
        if self.engine.extra and self.engine.extra.is_dir():extra='\n'.join(decode(p.read_bytes()) for p in sorted(self.engine.extra.glob('*.cfg')))
        other=bindings(extra)
        from .naming import names as pool_names
        used={s['name'].lower() for s in parsed+other if s['type'] in ('backend','listen')}
        for model in models:
            for name in pool_names(model):
                if name.lower() in used:raise ValueError('Имя backend уже используется: '+name+'. Выберите другое имя в настройках сервиса.')
                used.add(name.lower())
        insertions={};tls_add={};tail=[];claimed=[];warnings=[]
        def add(index,model,kind,body):insertions.setdefault(index,[]).append(block(model['id'],kind,body))
        def listener(model,port,tls,http_redirect=False):
            from .preserve import resolve_https
            if model.get('tcp_frontend') and not http_redirect:
                target=next((s for s in parsed if s['name']==model['tcp_frontend'] and s['mode']=='tcp'),None)
                if not target or not any(b['lo']<=port<=b['hi'] and b['tls']==tls and overlaps(model['bind_address'],b['host']) for b in target['binds']):raise ValueError('Существующий TCP-вход не соответствует выбранным порту, адресу или TLS. Сначала согласуйте изменение входа в конфигурации.')
            resolved=resolve_https(model,parsed+other) if tls and PRESETS[model['protocol']][3]=='http' else None
            layered=bool(resolved and resolved[2])
            if resolved:
                model['listener_port']=resolved[1]['lo'];model['route_port']=model['port'] if 'accept-proxy' in resolved[1]['line'].split() else resolved[1]['lo'];port=resolved[1]['lo']
            hits=[(s,b) for s in parsed+other for b in s['binds'] if b['lo']<=port<=b['hi'] and overlaps(model['bind_address'],b['host'])]
            if resolved:hits=[(resolved[0],resolved[1])]
            if not hits:
                for s in claimed:
                    if s['port']==port and overlaps(s['address'],model['bind_address']):
                        if (http_redirect or PRESETS[model['protocol']][3]=='http') and s['http'] and tls==s['tls']:return s['name']
                        if model.get('sni_routing') and not s['http'] and tls==s['tls'] and all(m.get('sni_routing') for m in s['models']):return s['name']
                        raise ValueError('Порт '+str(port)+' уже используется другим сервисом мастера.')
                if probe and not any(b['lo']<=port<=b['hi'] and overlaps(model['bind_address'],b['host']) for b in (owned_bindings or [])):
                    family=socket.AF_INET6 if ':' in model['bind_address'] else socket.AF_INET
                    try:
                        with socket.socket(family) as sock:
                            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                            sock.bind(('0.0.0.0' if model['bind_address']=='*' else model['bind_address'],port))
                    except OSError:raise ValueError('Порт '+str(port)+' занят другим процессом или IP недоступен на этом сервере.')
                name='studio_fe_'+model['id']+'_'+str(port)
                claimed.append(dict(name=name,port=port,address=model['bind_address'],tls=tls,http=http_redirect or PRESETS[model['protocol']][3]=='http',models=[],redirects=[]))
                return name
            if any(s in other for s,b in hits):raise ValueError('Порт '+str(port)+' описан в дополнительном .cfg. Мастер не меняет этот файл: выберите свободный порт.')
            names=set(s['name'] for s,b in hits)
            if len(names)!=1:raise ValueError('Несколько входов используют порт '+str(port)+'. Выберите отдельный порт.')
            section=hits[0][0]
            compatible_http=(http_redirect or PRESETS[model['protocol']][3]=='http') and section['mode']=='http'
            compatible_sni=model.get('sni_routing') and section['mode']=='tcp'
            compatible_tcp=model.get('tcp_frontend')==section['name'] and section['mode']=='tcp' and not any(re.match(r'\s*default_backend\b',line) for _,line in section['lines'])
            if not (compatible_http or compatible_sni or compatible_tcp) or any(b['tls']!=tls for s,b in hits):raise ValueError('Порт '+str(port)+' уже занят несовместимым входом '+section['name']+'. Выберите другой внешний порт.')
            if not layered and model['bind_address'] in ('*','0.0.0.0','::') and all(b['host'] not in ('*','0.0.0.0','::') for s,b in hits):raise ValueError('Вход на этом порту доступен только на отдельном IP. Укажите тот же IP или свободный порт.')
            if compatible_sni:
                if model['protocol'] in ('rdgateway','rdweb'):
                    if not any(re.match(r'\s*tcp-request inspect-delay\b',line) for _,line in section['lines']):raise ValueError('Для общего TLS-входа нужен tcp-request inspect-delay. Настройте его перед публикацией SNI или выберите отдельный IP/порт.')
                    for existing in parsed+other:
                        if existing['mode']=='http' and any(('hdr(host)' in line or 'txn.host' in line) and any(d in re.findall(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',line.lower()) for d in model['domains']) for _,line in existing['lines']):raise ValueError('Домен уже указан в ручном HTTP-входе '+existing['name']+'. SNI-публикация перехватит его. Выберите другой домен или сначала согласуйте перенос существующего маршрута.')
                for _,line in section['lines']:
                    if ('ssl_fc_sni' in line or 'req.ssl_sni' in line) and any(d in re.findall(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',line.lower()) for d in model['domains']):raise ValueError('SNI-домен уже используется ручными правилами этого входа.')
                if model.get('sni_default') and any(re.match(r'\s*default_backend\b',line) for _,line in section['lines']):raise ValueError('У общего TCP-входа уже настроен сервер по умолчанию. Оставьте SNI fallback выключенным.')
            return section['name']
        def route(model,redirect=False):
            from .enterprise import http_route,tcp_route
            if model.get('tcp_frontend') and not redirect:return '    default_backend '+backend_name(model)+'\n'
            return tcp_route(model) if model.get('sni_routing') and not redirect else http_route(model,redirect)
        def attach(model,name,redirect=False):
            owned=next((s for s in claimed if s['name']==name),None)
            if owned:
                owned['redirects' if redirect else 'models'].append(model);return
            section=next(s for s in parsed if s['name']==name)
            # Inject before any request or routing rules, after bind/mode declarations.
            index=next((i for i,line in section['lines'] if re.match(r'\s*(?:http-request\s+(?:deny|allow|redirect|auth|tarpit|return|use-service)|use_backend|default_backend|redirect)\b',line) or model.get('sni_routing') and re.match(r'\s*tcp-request content accept\b',line)),section['lines'][-1][0]+1 if section['lines'] else section['start']+1)
            add(index,model,'redirect' if redirect else 'route',route(model,redirect))
            if model['tls_mode']=='terminate' and not redirect:
                for b in section['binds']:
                    if b['lo']<=model.get('listener_port',model['port'])<=b['hi']:
                        tokens=b['line'].split();existing=[tokens[i+1] for i,t in enumerate(tokens[:-1]) if t=='crt']
                        for certificate in model.get('certificates',[model['certificate']]):
                            path=str(self.certificate_path(certificate))
                            if path not in existing and str(Path(path).parent) not in existing:tls_add.setdefault(b['index'],set()).add(path)
        active=[m for m in models if m['enabled']]
        for i,model in enumerate(active):
            http=PRESETS[model['protocol']][3]=='http'
            if model['tls_mode']=='terminate':self.certificate_check(model)
            for prior in active[:i]:
                if model.get('tcp_frontend') and model.get('tcp_frontend')==prior.get('tcp_frontend'):raise ValueError('Для TCP-входа уже задан основной сервис.')
                if prior['port']==model['port'] and overlaps(prior['bind_address'],model['bind_address']) and bool(model.get('sni_routing'))!=bool(prior.get('sni_routing')) and set(prior.get('domains') or [prior['domain']]) & set(model.get('domains') or [model['domain']]):raise ValueError('Домен пересекается с HTTP/SNI-публикацией на этом внешнем порту. Сначала согласуйте перенос существующего сервиса.')
                if http and PRESETS[prior['protocol']][3]=='http' and prior['port']==model['port'] and overlaps(prior['bind_address'],model['bind_address']) and set(prior.get('domains') or [prior['domain']]) & set(model.get('domains') or [model['domain']]) and (prior['path']=='/' or model['path']=='/' or prior['path']==model['path'] or prior['path'].startswith(model['path']+'/') or model['path'].startswith(prior['path']+'/')):raise ValueError('Домен, порт и путь пересекаются с сервисом «'+prior['name']+'».')
                if model.get('sni_routing'):
                    sameport=prior['port']==model['port'] and overlaps(prior['bind_address'],model['bind_address'])
                    if sameport and prior.get('sni_routing') and set(prior['domains']) & set(model['domains']):raise ValueError('SNI-домен уже используется другой публикацией.')
                    if sameport and prior.get('sni_default') and model.get('sni_default'):raise ValueError('На одном порту может быть только один SNI fallback.')
            if http and model['path']=='/' and any(any(d in re.findall(r'(?i)\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b',line) for d in (model.get('domains') or [model['domain']])) for section in parsed+other if any(b['lo']<=model['port']<=b['hi'] and overlaps(model['bind_address'],b['host']) for b in section['binds']) for _,line in section['lines'] if re.match(r'\s*acl\s+\S+\s+hdr(?:_dom)?\(host\)',line)):
                raise ValueError('Домен '+model['domain']+' уже используется ручными правилами. Выберите новый домен или отдельный путь, например /app.')
            name=listener(model,model['port'],model['tls_mode']=='terminate')
            if http:
                attach(model,name)
                if model['redirect']:attach(model,listener(model,model['http_port'],False,True),True)
            elif model.get('sni_routing') or model.get('tcp_frontend'):
                attach(model,name)
                if model.get('redirect'):attach(model,listener(model,model['http_port'],False,True),True)
            else:next(s for s in claimed if s['name']==name)['models'].append(model)
            if model['upstream_tls'] and not model['upstream_verify']:warnings.append('«'+model['name']+'»: проверка сертификата внутреннего сервера отключена.')
            if model['path']!='/':warnings.append('Путь '+model['path']+' имеет приоритет перед ручными маршрутами этого домена. Остальные пути сохраняются.')
        for spec in claimed:
            first=(spec['models'] or spec['redirects'])[0];http=spec['http'];bind_host='0.0.0.0' if spec['address']=='*' else spec['address']
            body='frontend '+spec['name']+'\n    bind '+address(bind_host,spec['port'])
            if spec['tls']:
                ordered=sorted(spec['models'],key=lambda m:not m.get('sni_default'))
                certs=list(dict.fromkeys(str(self.certificate_path(c)) for m in ordered for c in m.get('certificates',[m['certificate']])))
                body+=' ssl '+ ' '.join('crt '+c for c in certs)
                if http:body+=' alpn h2,http/1.1'
            body+='\n    mode '+('http' if http else 'tcp')+'\n    timeout client '+str(first['timeout'])+'s\n'
            if http:
                for m in spec['redirects']:body+=route(m,True)
                for m in spec['models']:body+=route(m)
            else:
                body+='    option tcplog\n'
                if first['protocol']=='rds' and first.get('rds_mode')=='token':
                    body+='    tcp-request inspect-delay 5s\n    tcp-request content accept if { req.rdp_cookie_cnt gt 0 }\n'
                if first.get('sni_routing'):
                    if not spec['tls']:body+='    tcp-request inspect-delay 5s\n'
                    for item in spec['models']:body+=route(item)
                    fallback=next((item for item in spec['models'] if item.get('sni_default')),None)
                    if fallback and fallback['allowed_ips']:
                        fetch='ssl_fc_sni' if spec['tls'] else 'req.ssl_sni'
                        body+='    acl st_known_sni '+fetch+' -i '+' '.join(d for item in spec['models'] for d in item['domains'])+'\n'
                        body+='    tcp-request content reject if !st_known_sni !{ src '+fallback['allowed_ips']+' }\n'
                    if not spec['tls']:body+='    tcp-request content accept if { req.ssl_hello_type 1 }\n'
                    if fallback:body+='    default_backend '+backend_name(fallback)+'\n'
                else:
                    if first['allowed_ips']:body+='    tcp-request connection reject unless { src '+first['allowed_ips']+' }\n'
                    body+='    default_backend '+backend_name(first)+'\n'
            tail.append(block(first['id'],'listener_'+str(spec['port']),body))
        for model in models:
            body='# studio-model '+packed(model)+'\n'
            if model['enabled']:body+=self.backend(model)
            tail.append(block(model['id'],'model',body))
        out=[]
        for index,line in enumerate(lines):
            out.extend(insertions.get(index,[]))
            if index in tls_add:
                rendered=line.rstrip('\r\n')+' '+ ' '.join('crt '+p for p in sorted(tls_add[index]))+'\n'
                out.append('    # studio-tls-base '+packed(dict(line=line,hash=hashlib.sha256(encode(rendered)).hexdigest()))+'\n');out.append(rendered)
            else:out.append(line)
        out.extend(insertions.get(len(lines),[]))
        # No separator is introduced: removing generated blocks restores baseline bytes exactly.
        if tail and out and not out[-1].endswith('\n'):raise ValueError('Последняя строка конфигурации должна завершаться переводом строки.')
        out.extend(tail)
        return encode(''.join(out)),warnings

    def backend(self,m):
        from .enterprise import backends
        return '' if m.get('http_action')=='redirect' else backends(self,m)

    def _backend_base(self,m):
        http=PRESETS[m['protocol']][3]=='http';mode='http' if http else 'tcp'
        s='backend '+backend_name(m)+'\n    mode '+mode+'\n    balance '+m['balance']+'\n    timeout connect 5s\n    timeout server '+str(m['timeout'])+'s\n    timeout tunnel '+str(m.get('tunnel_timeout',m['timeout']))+'s\n'
        if m['protocol']=='rds' and m.get('rds_mode')=='token':
            s+='    persist rdp-cookie\n'
        forwarded_port='%[ssl_fc,iif('+str(m['port'])+','+str(m['http_port'])+')]' if m.get('listener_port',m['port'])!=m['port'] else '%[dst_port]'
        if http:
            if m.get('cookie_name'):s+='    cookie '+m['cookie_name']+' insert nocache\n'
            if m.get('backend_forwardfor') and not m.get('forward_headers',True):s+='    option forwardfor\n'
            if m.get('forward_headers',True):s+='    option forwardfor\n    http-request set-header X-Forwarded-Proto '+'%[ssl_fc,iif(https,http)]'+'\n    http-request set-header X-Forwarded-Port '+forwarded_port+'\n    http-request set-header X-Forwarded-Host %[req.hdr(Host)]\n'
            if m['host_override']:s+='    http-request set-header Host '+m['host_override']+'\n'
            if m['strip_prefix']:s+='    http-request replace-path ^'+re.escape(m['path'])+'/?(.*)$ /\\1\n'
            if m['hsts']:s+='    http-response set-header Strict-Transport-Security max-age=31536000\n'
            if m['health']=='http':
                s+='    option httpchk\n    http-check send meth '+m.get('health_method','GET')+' uri '+m['health_path']+' ver HTTP/'+m.get('health_http_version','1.1')+(' hdr Host '+m.get('health_host',m['domain']) if m.get('health_host',m['domain']) else '')+'\n'
                status=m.get('health_status','2xx3xx')
                s+=('    http-check expect rstatus ^[23][0-9][0-9]$\n' if status=='2xx3xx' else '    http-check expect status '+status+'\n')
            if m.get('security_headers'):s+='    http-response set-header X-Frame-Options SAMEORIGIN\n    http-response set-header X-Content-Type-Options nosniff\n'
        if m['health']=='smtp':s+='    option smtpchk EHLO '+m.get('smtp_ehlo','haproxy-check')+'\n'
        if m.get('health_log'):s+='    option log-health-checks\n'
        ca=None
        if m['upstream_tls'] and m['upstream_verify'] or m.get('health_tls_verify'):
            ca=self.engine.settings.get('ca_bundle')
            if not ca or ca=='auto':ca=next((p for p in ('/etc/ssl/certs/ca-certificates.crt','/etc/pki/tls/certs/ca-bundle.crt') if Path(p).is_file()),None)
            if not ca or not Path(ca).is_file() or re.search(r'[\s#\\]',ca):raise ValueError('Для проверки TLS внутреннего сервера настройте ca_bundle или установите системные CA-сертификаты.')
        for i,server in enumerate(m['backends']):
            s+='    server '+server.get('name','node'+str(i+1))+' '+address(server['host'],server['port'])+' weight '+str(server['weight'])
            if server['backup']:s+=' backup'
            if m['health']!='none':s+=' check inter '+str(m['check_interval'])+'s fall '+str(m.get('check_fall',3))+' rise '+str(m.get('check_rise',2))
            if m['health']=='tls' and not m['upstream_tls']:
                s+=' check-ssl verify '+('required ca-file '+ca+' verifyhost '+m['health_tls_name']+' check-sni '+m['health_tls_name'] if m.get('health_tls_verify') else 'none')
            if m.get('health_send_proxy'):s+=' check-send-proxy'
            if m.get('cookie_name'):s+=' cookie '+server['cookie_value']
            if m['maxconn']:s+=' maxconn '+str(m['maxconn'])
            if m['proxy_protocol']:s+=' send-proxy-v2'
            if m['upstream_tls']:
                s+=' ssl verify '+('required ca-file '+ca if m['upstream_verify'] else 'none')
                if m.get('upstream_tls_version'):s+=' ssl-min-ver '+m['upstream_tls_version']+' ssl-max-ver '+m['upstream_tls_version']
                if m.get('upstream_sni',True) and m['upstream_name']:s+=' sni str('+m['upstream_name']+') check-sni '+m['upstream_name']+(' verifyhost '+m['upstream_name'] if m['upstream_verify'] else '')
            s+='\n'
        return s

    def preview(self,data,revision,action='upsert',probe=True):
        if self.engine.settings['read_only']:raise ValueError('Мастер недоступен в режиме наблюдения.')
        raw,actual=self.engine.snapshot()
        if revision!=actual:raise Conflict('Конфигурация изменилась. Обновите список сервисов.')
        base,models=clean(raw);identifier=data.get('id') if isinstance(data,dict) else None
        existing=next((m for m in models if m['id']==identifier),None)
        if identifier and not existing:raise ValueError('Сервис не найден. Обновите список.')
        if action=='delete':
            if not existing:raise ValueError('Сервис не найден.')
            models=[m for m in models if m['id']!=identifier];summary=['Удалить публикацию «'+existing['name']+'». Внутренний сервер и сертификат не удаляются.']
        else:
            if action!='upsert':raise ValueError('Неизвестное действие.')
            data=dict(data)
            if not existing:data.setdefault('naming','readable')
            model=self.normalize(data,identifier or secrets.token_hex(8))
            models=[model if m['id']==model['id'] else m for m in models] if existing else models+[model]
            label=PRESETS[model['protocol']][0]
            summary=[('Изменить' if existing else 'Опубликовать')+' «'+model['name']+'»: '+label+'.',('Домен '+model['domain']+model['path']+', ' if model['domain'] else '')+'внешний TCP-порт '+str(model['port'])+'.','Серверы: '+', '.join(address(s['host'],s['port']) for s in model['backends'])+'.']
            if not model['enabled']:summary.append('Публикация будет выключена. Её порт и маршруты не активируются.')
            if model['redirect']:summary.append('HTTP на порту '+str(model['http_port'])+' → HTTPS на порту '+str(model['port'])+'.')
        owned=[b for section in bindings(decode(raw)) if section['name'].startswith('studio_fe_') for b in section['binds']]
        if action!='delete' and existing:
            from .naming import changes,references
            base=references(base,changes(existing,model))
        candidate,warnings=self.render(base,models,probe,owned)
        checked=self.engine.validate(candidate)
        import difflib
        checked.update(changed=candidate!=raw,diff=''.join(difflib.unified_diff(mask(raw)[0].splitlines(True),mask(candidate)[0].splitlines(True),fromfile='Текущая версия',tofile='Мастер публикации')),summary=summary,warnings=list(dict.fromkeys(warnings))+['Проверьте DNS и доступность внешнего порта в сети или у провайдера.'])
        if action!='delete':
            if existing:
                from .naming import changes
                renamed=changes(existing,model)
                checked['summary'] += [old+' → '+new for old,new in renamed.items()]
                if renamed or [s.get('name') for s in existing['backends']]!=[s.get('name') for s in model['backends']]:checked['warnings'].append('Меняются технические имена. Проверьте внешние скрипты, метрики, Runtime API и server-state, использующие старые имена.')
            if model['protocol'] in ('rdgateway','rdweb'):
                gateway=model['protocol']=='rdgateway'
                checked['summary'].append('Windows '+('RD Gateway: RDP через HTTPS, TCP/443.' if gateway else 'RD Web Access: откройте /RDWeb/ на опубликованном домене.'))
                checked['warnings'].append('TLS передаётся до Windows без расшифровки. Сертификат Windows должен покрывать публичное имя; роли, коллекции, NLA и политики доступа настраиваются на Windows.')
                if model.get('sni_routing'):checked['warnings'].append('На общем 443 клиенты должны отправлять SNI. Для клиента без SNI нужен отдельный IP/порт или согласованный fallback; существующий fallback не заменяется.')
                if gateway:
                    checked['warnings'].append('UDP/3391 не публикуется этим шаблоном. Для UDP-транспорта RD Gateway нужен отдельный NAT/балансировщик. Прямой RDP/3389 наружу этот шаблон не открывает.')
                    if len(model['backends'])>1 and model['balance']!='source':checked['warnings'].append('Для нескольких RD Gateway рекомендуется балансировка по IP клиента: связанные TCP/RPC-подключения должны попадать на один сервер.')
                else:checked['warnings'].append('Портал RD Web не заменяет RD Gateway. Если обе роли находятся на одном сервере под одним доменом, используйте одну публикацию RD Gateway вместо дублирующей публикации RD Web.')
            if model['protocol']=='rds':
                token=model['rds_mode']=='token'
                checked['summary'].append('RDS: '+('токенная маршрутизация брокера (msts) на Session Host.' if token else 'прозрачный вход на RDP-порт брокера / redirector.'))
                checked['warnings'].append('На Windows включите token redirection и отключите IP address redirection; в пуле должны быть все реальные IPv4 и RDP-порты серверов назначения.' if token else 'При IP-перенаправлении клиент должен иметь доступ к адресам Session Host. Для внешнего доступа используйте RD Gateway или токенный режим.')
                checked['warnings'].append('Используйте RDP-файл нужной коллекции из RD Web; HAProxy сохраняет loadbalanceinfo и не настраивает роли Windows.')
            if model.get('naming')=='readable':
                from .naming import names as pool_names
                if pool_names(model):checked['summary'].append('Имена backend: '+', '.join(pool_names(model))+'.')
                if model['backends']:checked['summary'].append('Имена серверов: '+', '.join(s['name'] for s in model['backends'])+'.')
            if model.get('aliases'):checked['summary'].append('Дополнительные домены: '+', '.join(model['aliases'])+'.')
            if model.get('sni_routing'):checked['summary'].append('Общий TLS-порт, маршрутизация по SNI: '+', '.join(model['domains'])+'.')
            if model.get('routes'):checked['summary'].append('Маршруты по путям: '+str(len(model['routes']))+'; запрещённые пути отвечают 403.')
        return checked,dict(raw=candidate,revision=revision,reason='service:'+action)

    def preview_names(self,revision):
        if self.engine.settings['read_only']:raise ValueError('Переименование недоступно в режиме наблюдения.')
        raw,actual=self.engine.snapshot()
        if revision!=actual:raise Conflict('Конфигурация изменилась. Обновите список сервисов.')
        from .naming import migrate
        base,models=clean(raw);base,models,mapping=migrate(self,base,models)
        candidate,warnings=self.render(base,models,probe=False);checked=self.engine.validate(candidate)
        import difflib
        checked.update(changed=candidate!=raw,diff=''.join(difflib.unified_diff(mask(raw)[0].splitlines(True),mask(candidate)[0].splitlines(True),fromfile='Текущие имена',tofile='Понятные имена')),summary=[old+' → '+new for old,new in mapping.items()],warnings=warnings+['Имена серверов также станут понятными. Адреса, порты, проверки и cookie остаются прежними. Внешние скрипты, метрики, Runtime API и server-state могут ссылаться на старые имена: учтите переименование перед применением.'])
        return checked,dict(raw=candidate,revision=revision,reason='service:rename')

    def connectivity(self,data):
        identifier=data.get('id') or secrets.token_hex(8);model=self.normalize(data,identifier);results=[]
        from concurrent.futures import ThreadPoolExecutor
        def check(server):
            try:
                with socket.create_connection((server['host'],server['port']),timeout=3):pass
                return dict(host=server['host'],port=server['port'],ok=True,message='TCP-подключение установлено.')
            except OSError:return dict(host=server['host'],port=server['port'],ok=False,message='Нет TCP-подключения. Проверьте адрес, порт и firewall внутреннего сервера.')
        with ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(check,model['backends']))
        return dict(results=results,note='TCP-проверка не подтверждает учётные записи, готовность приложения или корректность TLS. Проверки HAProxy продолжат следить за сервером после публикации.')
