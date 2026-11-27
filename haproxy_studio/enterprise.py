"""Form-based multi-domain, Exchange and SNI routing. No organization data."""
from .naming import backend_name
import copy
import hashlib
import ipaddress
import re
import ssl
import time
from urllib.parse import urlsplit

EXCHANGE_PATHS = [('/owa','/owa/healthcheck.htm'),('/Autodiscover','/autodiscover/healthcheck.htm'),('/mapi','/mapi/healthcheck.htm'),('/Microsoft-Server-ActiveSync','/microsoft-server-activesync/healthcheck.htm'),('/ews','/ews/healthcheck.htm'),('/rpc','/rpc/healthcheck.htm'),('/ecp','/ecp/healthcheck.htm'),('/oab','/oab/healthcheck.htm')]

def names(value,allow_underscore=False):
    from .services import hostname
    if isinstance(value,str):value=re.split(r'[\s,;]+',value.strip())
    if not isinstance(value,list) or len(value)>32:raise ValueError('Не более 32 доменных имён.')
    result=[]
    for item in value:
        if not item:continue
        domain=hostname(item,'Домен',allow_underscore=allow_underscore)
        try:ipaddress.ip_address(domain)
        except ValueError:pass
        else:raise ValueError('Для маршрутизации по имени нужен домен, а не IP.')
        if domain not in result:result.append(domain)
    return result

def path(value,label='Путь'):
    if not isinstance(value,str) or not re.fullmatch(r'/[A-Za-z0-9/_~.\-]*',value) or '..' in value or len(value)>256:raise ValueError(label+': используйте путь с / без пробелов, параметров и ..')
    return value.rstrip('/') or '/'

def normalize(manager,data,m):
    from .services import PRESETS,number,hostname
    http=PRESETS[m['protocol']][3]=='http'
    m['aliases']=names(data.get('aliases',[]),allow_underscore=m['protocol']=='http') if http else []
    m['domains']=list(dict.fromkeys(([m['domain']]+m['aliases']) if http else names(data.get('sni_domains',[]))))
    m['sni_routing']=not http and data.get('sni_routing',False) is True
    m['sni_default']=m['sni_routing'] and data.get('sni_default',False) is True
    if m['sni_routing'] and (m['tls_mode'] not in ('terminate','passthrough') or not m['domains']):raise ValueError('SNI требует доменных имён и TLS с первого байта. На SMTP 25/587 и STARTTLS используйте общий пул или отдельный IP/порт.')
    if not http and not m['sni_routing']:m['domains']=[]
    if m['sni_routing'] and m['upstream_tls'] and not data.get('upstream_name'):m['upstream_name']=m['domains'][0]
    extra=data.get('certificates',[])
    if isinstance(extra,str):extra=re.split(r'[\s,;]+',extra.strip())
    if not isinstance(extra,list) or len(extra)>32:raise ValueError('Не более 32 сертификатов на публикацию.')
    m['certificates']=list(dict.fromkeys((([m['certificate']] if m['certificate'] or not data.get('import_pool') else [])+[x for x in extra if x]) if m['tls_mode']=='terminate' else []))
    for name in m['certificates']:
        if data.get('import_pool'):
            if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]+',name):raise ValueError('Некорректное имя сертификата исходного frontend.')
        else:manager.certificate_path(name)
    m['path_ignore_case']=data.get('path_ignore_case',m['protocol']=='exchange') is True
    target=data.get('root_redirect','/owa' if m['protocol']=='exchange' else '')
    if not isinstance(target,str) or len(target)>1024:raise ValueError('Некорректный адрес перенаправления.')
    if target:
        if target.startswith('/'):
            path(target,'Перенаправление')
        else:
            url=urlsplit(target)
            if url.scheme not in ('https','http') or not url.hostname or url.username or url.password or url.fragment or re.search(r'[\s#%\\]',target):raise ValueError('Перенаправление: путь /owa или полный адрес https://mail.example.org/owa.')
            hostname(url.hostname,'Домен перенаправления')
            if url.port is not None:number(url.port,'Порт перенаправления')
    if http and target=='/':raise ValueError('Корень / нельзя перенаправлять на самого себя.')
    m['root_redirect']=target if http else ''
    exceptions=data.get('http_exceptions',[])
    if isinstance(exceptions,str):exceptions=[x for x in re.split(r'[\s,;]+',exceptions.strip()) if x]
    if not isinstance(exceptions,list) or len(exceptions)>32:raise ValueError('Не более 32 HTTP-исключений.')
    m['http_exceptions']=[path(v,'HTTP-исключение') for v in exceptions] if m['redirect'] else []
    m['security_headers']=http and data.get('security_headers',False) is True
    m['health_status']=str(data.get('health_status','200' if m['protocol']=='exchange' else '2xx3xx'))
    if m['health_status']!='2xx3xx':number(m['health_status'],'Ожидаемый HTTP-код',100,599)
    m['health_method']=data.get('health_method','GET')
    if m['health_method'] not in ('GET','HEAD','OPTIONS'):raise ValueError('Некорректный HTTP-метод проверки.')
    m['health_log']=data.get('health_log',m['protocol']=='exchange') is True
    m['check_rise']=number(data.get('check_rise',2),'Успешных проверок',1,20)
    m['check_fall']=number(data.get('check_fall',3),'Неудачных проверок',1,20)
    m['smtp_ehlo']=hostname(data.get('smtp_ehlo','haproxy-check'),'Имя EHLO')
    routes=data.get('routes')
    if routes is None:routes=[dict(path=p,health_path=h,action='deny' if p=='/ecp' else 'backend',timeout=3600 if 'ActiveSync' in p else m['timeout']) for p,h in EXCHANGE_PATHS] if m['protocol']=='exchange' else []
    if not isinstance(routes,list) or len(routes)>32 or routes and not http:raise ValueError('Маршруты по путям доступны для веб-сервисов, не более 32.')
    m['routes']=[];seen=set()
    for row in routes:
        if not isinstance(row,dict):raise ValueError('Некорректный маршрут.')
        prefix=path(row.get('path',''))
        match=row.get('match','segment')
        if match not in ('segment','prefix'):raise ValueError('Сопоставление пути: сегмент или префикс.')
        if match=='prefix':prefix=row['path']
        if m['path']!='/' and prefix!=m['path'] and not prefix.startswith(m['path']+'/'):raise ValueError('Маршрут должен находиться внутри основного пути сервиса.')
        key=prefix.lower() if m['path_ignore_case'] else prefix
        if key in seen:raise ValueError('Пути маршрутов не должны повторяться.')
        seen.add(key);action=row.get('action','backend')
        if action not in ('backend','deny'):raise ValueError('Действие пути: опубликовать или запретить.')
        inherit=row.get('inherit_pool',not row.get('backends')) is True
        pool=m['backends'] if inherit else row.get('backends') or m['backends']
        if not isinstance(pool,list) or not 1<=len(pool)<=16:raise ValueError('Укажите от 1 до 16 серверов для пути.')
        servers=[dict(host=hostname(b.get('host','')),port=number(b.get('port',443),'Порт сервера'),weight=number(b.get('weight',1),'Вес',1,256),backup=b.get('backup',False) is True) for b in pool if isinstance(b,dict)]
        if len(servers)!=len(pool) or all(b['backup'] for b in servers):raise ValueError('Для пути нужен основной сервер.')
        status=str(row.get('health_status',m['health_status']))
        if status!='2xx3xx':number(status,'HTTP-код пути',100,599)
        health_path=row.get('health_path',m['health_path'])
        if not isinstance(health_path,str) or not re.fullmatch(r'/[A-Za-z0-9/_~.\-?=&%]*',health_path):raise ValueError('Некорректная страница проверки пути.')
        balance=row.get('balance',m['balance'])
        if balance not in ('roundrobin','leastconn','source'):raise ValueError('Некорректная балансировка пути.')
        m['routes'].append(dict(inherit_pool=inherit,match=match,path=prefix,action=action,health_path=health_path,health_status=status,timeout=number(row.get('timeout',m['timeout']),'Таймаут пути',5,86400),balance=balance,backends=servers))
    return m

def model_domains(m):return m.get('domains') or [m['domain']]

def certificates(manager,m):
    files=[manager.certificate_path(name) for name in m.get('certificates',[m['certificate']])]
    domains=m.get('domains') or ([m['domain']] if m.get('domain') else [])
    def valid(file):
        if manager.engine.command(['openssl','x509','-in',str(file),'-noout','-checkend','0']).returncode:return False
        start=manager.engine.command(['openssl','x509','-in',str(file),'-noout','-startdate']).stdout.decode().strip().partition('=')[2]
        return bool(start and ssl.cert_time_to_seconds(start)<=time.time())
    if not domains:
        for file in files:
            if not valid(file):raise ValueError('Сертификат '+file.name+' истёк, ещё не действует или не читается.')
    for domain in domains:
        matching=[file for file in files if manager.engine.command(['openssl','x509','-in',str(file),'-noout','-checkhost',domain]).returncode==0]
        if not matching:raise ValueError('Набор выбранных сертификатов не покрывает домен '+domain+'. Добавьте сертификат для этого имени.')
        invalid=[file for file in matching if not valid(file)]
        if invalid:raise ValueError('Для домена '+domain+' выбран истёкший, ещё не действующий или нечитаемый сертификат: '+', '.join(file.name for file in invalid)+'. Замените его, чтобы HAProxy не выдавал этот сертификат по SNI.')

def route_key(model,row):
    identity=row['path'].lower() if model.get('path_ignore_case') else row['path']
    return hashlib.sha256(identity.encode()).hexdigest()[:8]

def path_acl(name,prefix,ignore=False):
    flag='-i ' if ignore else ''
    result='    acl '+name+' path '+flag+prefix+'\n'
    if prefix!='/':result+='    acl '+name+' path_beg '+flag+prefix+'/\n'
    return result

def location_redirect(target,condition):
    # Fixed locations do not preserve query strings in HAProxy. Keep them explicitly,
    # without evaluating request input as configuration or changing the target host.
    suffix='&' if '?' in target else '?'
    return ('    http-request redirect location '+target+suffix+'%[query] code 302 if '+condition+' { query -m len gt 0 }\n'
            +'    http-request redirect location '+target+' code 302 if '+condition+'\n')

def http_route(m,redirect=False):
    ident='st_'+m['id'];conditions=[ident+'_host','{ dst_port '+str(m['http_port'] if redirect else m.get('route_port',m['port']))+' }']
    fetch='hdr(host)' if (redirect or m['tls_mode']=='plain') and m.get('http_host_match')=='raw' else 'hdr(host),lower,field(1,:)'
    body='    acl '+ident+'_host '+fetch+' -i '+' '.join(model_domains(m))+'\n'
    host_condition=' '.join(conditions)
    from .rdweb import access_rules
    body+=access_rules(m,host_condition,redirect)
    if not redirect and m.get('canonical_slash'):body+=location_redirect(m['path']+'/',host_condition+' { path '+m['path']+' }')
    if not redirect and m.get('redirect_root') and m.get('root_redirect'):body+=location_redirect(m['root_redirect'],host_condition+' { path / }'+(' { method GET HEAD }' if m['protocol'] in ('rdwebproxy','studio') else ''))
    if m['path']!='/' and not (redirect and m.get('http_redirect_all_paths')):body+=path_acl(ident+'_path',m['path'],m.get('path_ignore_case'));conditions.append(ident+'_path')
    condition=' '.join(conditions)
    if m['allowed_ips']:body+='    http-request deny deny_status 403 if '+condition+' !{ src '+m['allowed_ips']+' }\n'
    if not redirect and m.get('reject_other_paths'):body+='    http-request deny deny_status 404 if '+host_condition+' !'+ident+'_path\n'
    if m.get('http_action')=='redirect':
        target='location '+m['http_redirect_location'] if m.get('http_redirect_location') else 'scheme https'
        return body+'    http-request redirect '+target+' code '+str(m.get('redirect_code',301))+' if '+condition+'\n'
    if redirect:
        if m.get('http_redirect_location'):return body+'    http-request redirect location '+m['http_redirect_location']+' code '+str(m.get('redirect_code',301))+' if '+condition+'\n'
        if m.get('http_redirect_mode')=='scheme':return body+'    http-request redirect scheme https code '+str(m.get('redirect_code',301))+' if '+condition+'\n'
        exceptions=m.get('http_exceptions',[])
        for prefix in exceptions:body+=path_acl(ident+'_exception',prefix,m.get('path_ignore_case'))
        if exceptions:body+='    http-request allow if '+condition+' '+ident+'_exception\n    use_backend '+backend_name(m)+' if '+condition+' '+ident+'_exception\n'
        origin='https://'+(model_domains(m)[0] if len(model_domains(m))==1 else '%[req.hdr(host),field(1,:)]')+(':'+str(m['port']) if m['port']!=443 else '')
        body+='    http-request redirect prefix '+origin+' code '+str(m.get('redirect_code',301))+' if '+condition+(' !'+ident+'_exception' if exceptions else '')+'\n'
        return body
    if m.get('root_redirect') and not m.get('redirect_root'):body+=location_redirect(m['root_redirect'],host_condition+' { path / }'+(' { method GET HEAD }' if m['protocol'] in ('rdwebproxy','studio') else ''))
    routes=sorted(enumerate(m.get('routes',[])),key=lambda pair:-len(pair[1]['path']))
    for index,row in routes:
        acl=ident+'_r'+route_key(m,row);body+=('    acl '+acl+' path_beg '+('-i ' if m.get('path_ignore_case') else '')+row['path']+'\n' if row.get('match')=='prefix' else path_acl(acl,row['path'],m.get('path_ignore_case')))
        if row['action']=='deny':body+='    http-request deny deny_status 403 if '+condition+' '+acl+'\n'
    if m.get('fallback_status') and routes:body+='    http-request deny deny_status '+str(m['fallback_status'])+' if '+condition+' '+' '.join('!'+ident+'_r'+route_key(m,row) for _,row in routes)+'\n'
    body+='    http-request allow if '+condition+'\n'
    for index,row in routes:
        if row['action']=='backend':body+='    use_backend '+backend_name(m,row)+' if '+condition+' '+ident+'_r'+route_key(m,row)+'\n'
    return body if m.get('fallback_status') and routes else body+'    use_backend '+backend_name(m)+' if '+condition+'\n'

def tcp_route(m):
    fetch='ssl_fc_sni' if m['tls_mode']=='terminate' else 'req.ssl_sni'
    acl='st_'+m['id']+'_sni'
    result='    acl '+acl+' '+fetch+' -i '+' '.join(m['domains'])+'\n'
    if m['allowed_ips']:result+='    tcp-request content reject if '+acl+' !{ src '+m['allowed_ips']+' }\n'
    return result+'    use_backend '+backend_name(m)+' if '+acl+'\n'

def backends(manager,m):
    result='' if m.get('fallback_status') and m.get('routes') else manager._backend_base(m)
    for index,row in enumerate(m.get('routes',[])):
        if row['action']!='backend':continue
        child=copy.deepcopy(m);child.update(row);child.update(backend_name=backend_name(m,row),id=m['id']+'_r'+route_key(m,row),health='http',strip_prefix=False,routes=[])
        result+=manager._backend_base(child)
    return result
