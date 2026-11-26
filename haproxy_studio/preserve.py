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
    if m['redirect_root'] and (not http or not m.get('root_redirect')):raise ValueError('Для корневого перенаправления задайте адрес назначения веб-сервиса.')
    if (m['canonical_slash'] or m['reject_other_paths']) and (not http or m['path']=='/'):raise ValueError('Настройки ограниченного пути требуют веб-сервис с путём, отличным от /.')
    m['imported']=data.get('imported',False) is True
    from .acl_import import normalize as normalize_acl_import
    return normalize_acl_import(data,m)

def resolve_https(model,parsed,models=()):
    """Select a direct HTTPS listener or prove the public SNI -> local TLS path."""
    from .services import overlaps
    from .acl_import import resolve_bridge
    name=model.get('https_frontend')
    if not name:
        tcp=[s for s in parsed if s['type']=='frontend' and s['mode']=='tcp' and any(not b['tls'] and b['lo']<=model['port']<=b['hi'] and overlaps(model['bind_address'],b['host']) for b in s['binds'])]
        if not tcp:return None
    targets=[s for s in parsed if s['type']=='frontend' and s['mode']=='http' and (not name or s['name']==name)]
    if name and len(targets)!=1:raise ValueError('Выбранный HTTP frontend не найден.')
    matches=[]
    for target in targets:
        binds=[b for b in target['binds'] if b['tls'] and b['lo']==b['hi']]
        if len(binds)!=1:
            if name:raise ValueError('Для выбранного HTTPS-входа нужен один однозначный TLS bind.')
            continue
        bind=binds[0]
        if name and bind['lo']==model['port']:return target,bind,False
        if bind['host'] not in ('127.0.0.1','::1'):continue
        trial=dict(model,import_acl=dict(frontend=target['name'],listener_port=bind['lo'],listener_address=bind['host']))
        resolved=resolve_bridge(trial,parsed,models)
        if resolved:matches.append(resolved)
    if len(matches)==1:
        model['https_frontend']=matches[0][0]['name']
        return matches[0]
    if len(matches)>1:raise ValueError('Для домена подтверждены несколько внутренних HTTPS-входов: '+', '.join(s['name'] for s,_,_ in matches)+'. Выберите нужный вход на шаге «Адреса и защита».')
    raise ValueError('На внешнем порту работает TCP/SNI, но путь этого домена к внутреннему HTTPS не подтверждён. Проверьте SNI-маршрут, локальный TLS-мост и соответствие PROXY protocol. Существующую SNI-публикацию этого домена нужно изменить или явно заменить.')
