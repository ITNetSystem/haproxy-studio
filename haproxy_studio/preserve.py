"""Typed compatibility controls for importing existing publications without losing policy."""
from pathlib import Path
import ipaddress
import re
from urllib.parse import urlsplit

def token(value,label,empty=True):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{'+('0' if empty else '1')+r',64}',value):raise ValueError(label+': используйте буквы, цифры, _, точку или дефис.')
    return value

def location(value):
    if not isinstance(value,str) or len(value)>1024 or re.search(r'[\s#%\\]',value):raise ValueError('Некорректный адрес перенаправления.')
    if not value:return ''
    parsed=urlsplit(value)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:raise ValueError('Укажите полный HTTP(S)-адрес перенаправления.')
    from .services import hostname,number
    hostname(parsed.hostname)
    if parsed.port is not None:number(parsed.port,'Порт перенаправления')
    return value

def normalize(manager,data,m):
    from .services import PRESETS,number,hostname
    http=PRESETS[m['protocol']][3]=='http'
    m['tcp_frontend']=token(data.get('tcp_frontend',''),'TCP-вход')
    if m['tcp_frontend'] and http:raise ValueError('TCP-вход доступен только для TCP/TLS-сервиса.')
    m['https_frontend']=token(data.get('https_frontend',''),'HTTPS-вход')
    if m['https_frontend'] and not (http and m['tls_mode']=='terminate'):raise ValueError('Выбор внутреннего HTTPS-входа доступен только для HTTPS-сервиса.')
    m['forward_headers']=data.get('forward_headers',True) is True
    m['backend_forwardfor']=data.get('backend_forwardfor',False) is True
    m['tunnel_timeout']=number(data.get('tunnel_timeout',m['timeout']),'Таймаут туннеля',5,86400)
    m['upstream_sni']=data.get('upstream_sni',True) is True
    if not m['upstream_sni']:m['upstream_name']=''
    m['redirect_code']=number(data.get('redirect_code',301),'HTTP-код перенаправления',301,308)
    if m['redirect_code'] not in (301,302,303,307,308):raise ValueError('Выберите допустимый код перенаправления.')
    m['http_host_match']=data.get('http_host_match','normalized')
    if m['http_host_match'] not in ('raw','normalized'):raise ValueError('Некорректное сопоставление HTTP Host.')
    m['http_redirect_mode']=data.get('http_redirect_mode','prefix')
    if m['http_redirect_mode'] not in ('prefix','scheme'):raise ValueError('Режим HTTP-редиректа: публичный адрес или исходный Host.')
    m['http_redirect_all_paths']=data.get('http_redirect_all_paths',False) is True
    m['http_redirect_location']=location(data.get('http_redirect_location',''))
    m['http_action']=data.get('http_action','proxy')
    if m['http_action'] not in ('proxy','redirect') or m['http_action']=='redirect' and m['protocol']!='http':raise ValueError('Режим только перенаправления доступен для HTTP.')
    if m['http_action']=='redirect' and (m['upstream_tls'] or m['proxy_protocol'] or m['routes']):raise ValueError('Для HTTP-перенаправления не нужны TLS до сервера, PROXY protocol или маршруты.')
    if m['http_action']=='redirect':m['health']='none';m['backends']=[]
    if not http and data.get('redirect',False):
        if not m['sni_routing'] or m['tls_mode']!='passthrough':raise ValueError('HTTP-перенаправление для TCP требует сквозного TLS с доменами SNI.')
        m['redirect']=True
    m['health_http_version']=data.get('health_http_version','1.1')
    if m['health_http_version'] not in ('1.0','1.1'):raise ValueError('Версия HTTP-проверки: 1.0 или 1.1.')
    host=data.get('health_host',m['domain'] if m['http_action']!='redirect' else '')
    m['health_host']=hostname(host,'Host проверки') if host else ''
    m['health_tls_verify']=data.get('health_tls_verify',False) is True
    m['health_tls_name']=hostname(data.get('health_tls_name'),'TLS-имя проверки') if m['health_tls_verify'] else ''
    m['health_send_proxy']=data.get('health_send_proxy',False) is True
    if m['health_send_proxy'] and not m['proxy_protocol']:raise ValueError('PROXY в проверках требует PROXY protocol до сервера.')
    m['cookie_name']=token(data.get('cookie_name',''),'Cookie привязки')
    if m['cookie_name'] and not http:raise ValueError('Cookie-привязка доступна только HTTP-сервисам.')
    for index,server in enumerate(m['backends']):
        source=data.get('backends',[])[index]
        server['cookie_value']=token(source.get('cookie_value','node'+str(index+1)),'Cookie сервера',False) if m['cookie_name'] else ''
    m['upstream_tls_version']=data.get('upstream_tls_version','')
    if m['upstream_tls_version'] not in ('','TLSv1.2','TLSv1.3'):raise ValueError('Версия TLS до сервера: автоматически, TLSv1.2 или TLSv1.3.')
    if m['upstream_tls_version'] and not m['upstream_tls']:raise ValueError('Фиксация версии TLS требует TLS до сервера.')
    m['fallback_status']=int(data.get('fallback_status',0))
    if m['fallback_status'] not in (0,403,404,503):raise ValueError('Ответ вне маршрутов: обычный backend, 403, 404 или 503.')
    m['redirect_root']=data.get('redirect_root',False) is True
    m['canonical_slash']=data.get('canonical_slash',False) is True
    m['reject_other_paths']=data.get('reject_other_paths',False) is True
    if (m['redirect_root'] or m['canonical_slash'] or m['reject_other_paths']) and (not http or m['path']=='/'):raise ValueError('Настройки ограниченного пути требуют веб-сервис с путём, отличным от /.')
    m['imported']=data.get('imported',False) is True
    return m

def resolve_https(model,parsed):
    """Prove public TCP default -> local raw-TLS bridge -> named HTTP TLS listener."""
    from .services import overlaps
    name=model.get('https_frontend')
    if not name:return None
    matches=[s for s in parsed if s['type']=='frontend' and s['name']==name and s['mode']=='http']
    if len(matches)!=1:raise ValueError('Выбранный HTTP frontend не найден.')
    target=matches[0];binds=[b for b in target['binds'] if b['tls'] and b['lo']==b['hi']]
    if len(binds)!=1:raise ValueError('Для выбранного HTTPS-входа нужен один однозначный TLS bind.')
    bind=binds[0]
    if bind['lo']==model['port']:return target,bind,False
    if bind['host'] not in ('127.0.0.1','::1'):raise ValueError('Внутренний TLS-вход должен слушать loopback.')
    for outer in parsed:
        if outer['type']!='frontend' or outer['mode']!='tcp' or not any(b['lo']<=model['port']<=b['hi'] and not b['tls'] and overlaps(model['bind_address'],b['host']) and (model['bind_address'] not in ('*','0.0.0.0','::') or b['host'] in ('*','0.0.0.0','::')) for b in outer['binds']):continue
        defaults=[line.strip().split()[1] for _,line in outer['lines'] if re.match(r'\s*default_backend\s+\S+',line)]
        for backend in parsed:
            if backend['type']!='backend' or backend['name'] not in defaults or backend['mode']!='tcp':continue
            servers=[line.strip().split() for _,line in backend['lines'] if re.match(r'\s*server\s+',line)]
            if len(servers)!=1:continue
            parts=servers[0]
            if parts[2] not in (bind['host']+':'+str(bind['lo']),'['+bind['host']+']:'+str(bind['lo'])) or 'ssl' in parts:continue
            sending=any(x in parts for x in ('send-proxy','send-proxy-v2'))
            if sending!=('accept-proxy' in bind['line'].split()):raise ValueError('PROXY protocol на TLS-мосте и внутреннем bind должен совпадать.')
            domains=model.get('domains') or [model['domain']]
            if any('req.ssl_sni' in line and any(d in re.findall(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+',line.lower()) for d in domains) for _,line in outer['lines']):raise ValueError('Домен уже направляется внешним SNI-входом на другой backend.')
            return target,bind,True
    raise ValueError('Не подтверждён путь внешнего TCP-порта к выбранному внутреннему TLS-входу. Проверьте default_backend и локальный сервер-мост.')
