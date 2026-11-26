"""Conservative import: only fully understood route/pool pairs become managed models."""
import difflib
import hashlib
import re
import shlex
from pathlib import Path
from .core import Conflict,encode,mask
from .services import bindings,clean,PRESETS

class Unsupported(ValueError):pass

def seconds(value):
    match=re.fullmatch(r'(\d+)(ms|s|m|h|d)?',value)
    if not match:raise Unsupported('Неподдерживаемый формат таймаута.')
    result=int(match[1])*{'ms':.001,'s':1,'m':60,'h':3600,'d':86400,None:.001}[match[2]]
    if result!=int(result):raise Unsupported('Дробные секунды таймаута требуют ручной настройки.')
    return int(result)

def active(section):
    result=[]
    for index,line in section['lines']:
        text=line.strip()
        if text and not text.startswith('#'):
            if text.endswith('\\'):raise Unsupported('Секция '+section['name']+', строка '+str(index+1)+': продолжение директивы требует ручной проверки.')
            if re.search(r'(?<!\\)\$\{?',text):raise Unsupported('Секция '+section['name']+', строка '+str(index+1)+': переменные окружения требуют ручной проверки.')
            try:parts=shlex.split(text,comments=True,posix=True)
            except ValueError:raise Unsupported('Секция '+section['name']+', строка '+str(index+1)+': незакрытая кавычка или экранирование.')
            if parts:result.append((index,parts))
    return result

def _routing_commands(section):
    # Only backend references matter for dynamic-reference protection. A stats realm
    # or unrelated unsupported policy cannot block an independent frontend.
    return active(dict(section,lines=[(i,line) for i,line in section['lines'] if re.match(r'\s*(?:use_backend|default_backend)\b',line)]))

def retained_comment(line):
    quote=None;escaped=False
    for index,char in enumerate(line):
        if escaped:escaped=False;continue
        if char=='\\':escaped=True;continue
        if char in ("'",'"'):
            if quote==char:quote=None
            elif quote is None:quote=char
        elif char=='#' and quote is None:
            return line if not line[:index].strip() else '    '+line[index:]
    return ''

def endpoint(value):
    match=re.fullmatch(r'(\[[^]]+\]|[^:]+):(\d+)',value)
    if not match:raise Unsupported('Нужен явный адрес сервера и один порт.')
    return match[1].strip('[]'),int(match[2])

def pool(manager,section,defaults):
    if any(p[0] in ('default-server','http-request','http-response','tcp-request','tcp-response','http-check','tcp-check','retry-on','retries','cookie','balance','option') and p not in (['option','httplog'],['option','tcplog'],['option','dontlognull'],['option','log-separate-errors']) for _,p in defaults):
        raise Unsupported('В defaults есть политика пула, которую нужно перенести вручную.')
    times={}
    for _,p in defaults:
        if p[0]=='timeout' and len(p)==3:times[p[1]]=seconds(p[2])
    data=dict(backends=[],balance='roundrobin',forward_headers=False,backend_forwardfor=False,upstream_tls=False,upstream_sni=False,upstream_verify=False,health='none',health_host='',health_http_version='1.0',check_interval=2,check_fall=3,check_rise=2)
    shared=None;method=None
    for _,p in active(section):
        if p[0]=='mode' and len(p)==2:continue
        if p[0]=='description':continue
        if p[0]=='log' and p==['log','global']:continue
        if p[0]=='balance' and len(p)==2 and p[1] in ('roundrobin','leastconn','source'):data['balance']=p[1];continue
        if p[0]=='timeout' and len(p)==3 and p[1] in ('connect','server','tunnel'):times[p[1]]=seconds(p[2]);continue
        if p==['option','forwardfor']:data['backend_forwardfor']=True;continue
        if p==['option','tcp-check']:continue
        if p==['option','log-health-checks']:data['health_log']=True;continue
        if p[:2]==['option','smtpchk'] and len(p)==4 and p[2]=='EHLO':data.update(health='smtp',smtp_ehlo=p[3]);continue
        if p[:2]==['option','httpchk'] and len(p) in (4,5) and p[2] in ('GET','HEAD','OPTIONS'):
            data.update(health='http',health_method=p[2],health_path=p[3]);method='http'
            if len(p)==5:
                if p[4] not in ('HTTP/1.0','HTTP/1.1'):raise Unsupported('Версия HTTP-проверки не поддерживается.')
                data['health_http_version']=p[4][5:]
            continue
        if p[:3]==['http-check','expect','status'] and len(p)==4:data['health_status']=p[3];continue
        if p[0]!='server' or len(p)<3:raise Unsupported('Backend: директива «'+p[0]+'» требует ручного переноса.')
        host,port=endpoint(p[2]);server=dict(host=host,port=port,weight=1,backup=False)
        if re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,62}',p[1]):server['name']=p[1]
        flags=dict(check=False,ssl=False,verify=None,interval=2,rise=2,fall=3,proxy=False,maxconn=0,sni='',check_sni='',verifyhost='',ca='')
        i=3
        while i<len(p):
            key=p[i]
            if key in ('check','ssl','backup','send-proxy-v2'):
                if key=='backup':server['backup']=True
                else:flags[{'send-proxy-v2':'proxy'}.get(key,key)]=True
                i+=1;continue
            if key in ('weight','inter','rise','fall','maxconn','verify','ca-file','sni','check-sni','verifyhost') and i+1<len(p):
                value=p[i+1]
                if key=='weight':server['weight']=int(value)
                elif key=='inter':flags['interval']=seconds(value)
                elif key in ('rise','fall','maxconn'):flags[key]=int(value)
                else:flags[{'ca-file':'ca','check-sni':'check_sni'}.get(key,key)]=value
                i+=2;continue
            raise Unsupported('Параметр сервера «'+key+'» требует ручного переноса.')
        if shared is not None and flags!=shared:raise Unsupported('Разные TLS/health-параметры серверов: требуется ручное сопоставление.')
        shared=flags;data['backends'].append(server)
    if not shared:raise Unsupported('В backend нет серверов.')
    if times.get('connect')!=5:raise Unsupported('Автоперенос поддерживает timeout connect 5s; остальные значения сохраняются вручную.')
    data['timeout']=times.get('server',0);data['tunnel_timeout']=times.get('tunnel',data['timeout'])
    if not 5<=data['timeout']<=86400:raise Unsupported('Нужен timeout server от 5 секунд до суток.')
    data.update(upstream_tls=shared['ssl'],check_interval=shared['interval'],check_rise=shared['rise'],check_fall=shared['fall'],proxy_protocol=shared['proxy'],maxconn=shared['maxconn'])
    if shared['check'] and data['health']=='none':data['health']='tcp'
    if not shared['check'] and data['health']!='none':raise Unsupported('Проверка настроена без check на сервере.')
    if shared['ssl']:
        verify=shared['verify']
        if verify not in ('none','required'):raise Unsupported('TLS сервера требует явного verify none или verify required.')
        data['upstream_verify']=verify=='required'
        if shared['sni']:
            found=re.fullmatch(r'str\(([A-Za-z0-9.-]+)\)',shared['sni'])
            if not found or shared['check_sni']!=found[1] or (verify=='required' and shared['verifyhost']!=found[1]):raise Unsupported('Параметры SNI/проверки имени требуют ручного переноса.')
            data.update(upstream_sni=True,upstream_name=found[1])
        elif shared['check_sni'] or shared['verifyhost']:raise Unsupported('Раздельные SNI/verifyhost требуют ручного переноса.')
        ca=manager.engine.settings.get('ca_bundle')
        if verify=='required' and (not shared['sni'] or ca=='auto' or not ca or shared['ca']!=ca):raise Unsupported('Для проверяемого TLS настройте совпадающий ca_bundle и SNI либо перенесите вручную.')
    elif shared['verify'] or shared['sni'] or shared['ca']:raise Unsupported('TLS-параметры без ssl требуют ручного переноса.')
    return data

class Importer:
    def __init__(self,manager):self.manager=manager;self.engine=manager.engine

    def source(self,value):
        if self.engine.settings['read_only']:raise ValueError('Импорт недоступен в режиме наблюдения.')
        current,revision=self.engine.snapshot()
        if value.get('revision')!=revision:raise Conflict('Конфигурация изменилась. Обновите список сервисов и повторите анализ.')
        source=value.get('source','current')
        if source not in ('current','file'):raise ValueError('Выберите текущий конфиг или файл.')
        text=value.get('content') if source=='file' else current.decode('utf-8','surrogateescape')
        if not isinstance(text,str) or not text.strip() or len(text.encode('utf-8','surrogateescape'))>512*1024 or '\x00' in text:raise ValueError('Нужен текстовый конфиг размером до 512 КиБ.')
        return text,current,revision

    def discover(self,text):
        base,managed=clean(encode(text));parsed=bindings(base);lines=base.splitlines(keepends=True)
        ends={s['start']:parsed[i+1]['start'] if i+1<len(parsed) else len(lines) for i,s in enumerate(parsed)}
        names={};candidates=[];warnings=[]
        for section in parsed:names.setdefault(section['name'],[]).append(section)
        defaults=[]
        if sum(s['type']=='defaults' for s in parsed)>1:return base,managed,[],[dict(name='defaults',reason='Несколько секций defaults требуют ручного сопоставления наследования.')]
        for section in parsed:
            if section['type']=='defaults':defaults=active(section)
        from .acl_import import discover as discover_acl
        adopted,handled,acl_warnings=discover_acl(self.manager,base,parsed,managed)
        candidates.extend(adopted)
        warnings.extend(acl_warnings)
        for front in parsed:
            if front['type']!='frontend' or front['name'].startswith('studio_fe_'):continue
            if any(index in handled for index,_ in front['lines']):continue
            try:
                commands=active(front)
                if len(names[front['name']])!=1:raise Unsupported('Неоднозначное имя frontend.')
                route_lines=[index for index,p in commands if p[0] in ('use_backend','default_backend')]
                if route_lines and any(index>min(route_lines) and p[0]=='http-request' for index,p in commands):raise Unsupported('HTTP-действия после маршрутов требуют ручного сохранения порядка.')
                if any(p[0] in ('use_backend','default_backend') and len(p)>1 and '%' in p[1] for s in parsed if s['type'] in ('frontend','listen') for _,p in _routing_commands(s)):raise Unsupported('Динамический выбор backend требует ручной проверки внешних map-файлов.')
                # Only simple name-based routes. Path ACLs, auth, rewrites and terminal policy stay manual.
                permitted={'bind','mode','log','option','timeout','capture','description','acl','use_backend','default_backend','tcp-request','http-request','http-response'}
                for _,p in commands:
                    if p[0] not in permitted:raise Unsupported('Frontend: «'+p[0]+'» требует ручного переноса.')
                    if p[0]=='http-request' and p[1:2] not in (['set-header'],['redirect']):raise Unsupported('Вход содержит редирект, ограничение или другую политику HTTP; нужен ручной перенос.')
                    if p[0]=='tcp-request' and p[1:3] not in (['inspect-delay'],['content','accept']):
                        if p[1]!='inspect-delay':raise Unsupported('TCP-политика требует ручного переноса.')
                if len(front['binds'])!=1:raise Unsupported('Нужен один bind с одним портом.')
                bind=front['binds'][0]
                if bind['lo']!=bind['hi']:raise Unsupported('Диапазон портов требует ручного переноса.')
                if 'accept-proxy' in bind['line'].split():raise Unsupported('Вход с accept-proxy: нужно вручную сопоставить исходные адрес и порт клиента.')
                acls={p[1]:(index,p) for index,p in commands if p[0]=='acl' and len(p)>3}
                redirects=[p for _,p in commands if p[:2]==['http-request','redirect']]
                if redirects:
                    if any(p[0] in ('use_backend','default_backend') for _,p in commands):raise Unsupported('HTTP-редиректы вместе с backend-маршрутами требуют ручной проверки порядка.')
                    for p in redirects:
                        acl=acls.get(p[-1],(-1,[]))[1]
                        if len(p)!=8 or p[2] not in ('scheme','location') or p[4]!='code' or p[6]!='if' or len(acl)<5 or acl[2] not in ('hdr(host)','hdr(host),lower,field(1,:)') or acl[3]!='-i':raise Unsupported('Сложный HTTP-редирект остаётся ручным.')
                routes=[(index,p) for index,p in commands if p[0]=='use_backend']
                routes += [(index,p) for index,p in commands if p[:2]==['http-request','redirect']]
                if front['mode']=='tcp':routes += [(index,p) for index,p in commands if p[0]=='default_backend']
                if not routes:raise Unsupported('Нет простых маршрутов use_backend по домену; вход сохранён вручную.')
                for route_index,r in routes:
                    try:
                        redirect=r[:2]==['http-request','redirect']
                        target_location='';redirect_code=301
                        if redirect:
                            if front['mode']!='http' or bind['tls'] or len(r)!=8 or r[2] not in ('scheme','location') or r[4]!='code' or r[6]!='if':raise Unsupported('Редирект требует одного HTTP ACL и явного кода.')
                            if r[2]=='scheme' and r[3]!='https':raise Unsupported('Поддерживается перенаправление схемы только на HTTPS.')
                            target_location=r[3] if r[2]=='location' else '';redirect_code=int(r[5]);r=['use_backend','HTTP redirect','if',r[7]]
                        fallback=r[0]=='default_backend' and len(r)==2
                        if not fallback and (len(r)!=4 or r[2]!='if' or r[3] not in acls):raise Unsupported('Условие маршрута должно содержать один ACL домена.')
                        acl_index,a=(-1,['acl','fallback','ssl_fc_sni' if bind['tls'] else 'req.ssl_sni','-i']) if fallback else acls[r[3]]
                        if (not fallback and len(a)<5) or a[3]!='-i' or a[2] not in ('hdr(host)','hdr(host),lower,field(1,:)','req.ssl_sni','ssl_fc_sni'):raise Unsupported('ACL должен сопоставлять только домены без дополнительных условий.')
                        http=front['mode']=='http'
                        if http!=(a[2].startswith('hdr(host)')):raise Unsupported('Тип ACL не соответствует режиму frontend.')
                        if http and bind['tls'] and a[2]=='hdr(host)':raise Unsupported('HTTPS с полным Host требует ручного сопоставления порта в имени.')
                        if not http and (a[2]=='ssl_fc_sni')!=bind['tls']:raise Unsupported('SNI не соответствует TLS-режиму bind.')
                        refs=2 if fallback else sum(len(re.findall(r'(?<![\w.-])'+re.escape(r[3])+r'(?![\w.-])',' '.join(p))) for _,p in commands)
                        if refs!=2:raise Unsupported('ACL используется несколькими правилами; он остаётся ручным.')
                        backend=None
                        if redirect:
                            data=dict(backends=[],health='none',http_action='redirect',redirect_code=redirect_code,http_redirect_location=target_location,http_redirect_mode='scheme',forward_headers=False)
                        else:
                            target=names.get(r[1],[])
                            if len(target)!=1 or target[0]['type']!='backend':raise Unsupported('Backend отсутствует или его имя неоднозначно.')
                            backend=target[0]
                            if front['mode']=='tcp':
                                from .acl_import import pool_servers
                                servers=pool_servers(backend)
                                if len(servers)==1 and any(servers[0]['host']==b['host'] and servers[0]['port']==b['lo'] for s in parsed if s['mode']=='http' for b in s['binds'] if b['tls'] and b['host'] in ('127.0.0.1','::1')):raise Unsupported('Служебный TCP → локальный HTTPS-мост сохраняется в конфигурации; его не нужно переносить как отдельное приложение.')
                            if backend['mode']!=front['mode']:raise Unsupported('Режимы frontend и backend различаются.')
                            references=[(s,index) for s in parsed for index,p in _routing_commands(s) if p[0] in ('use_backend','default_backend') and len(p)>1 and p[1]==r[1]]
                            if len(references)!=1:raise Unsupported('Backend используется несколькими маршрутами; нужен ручной перенос.')
                            # Dynamic expressions/maps may reference the same backend too.
                            if any(re.search(r'(?<![\w.-])'+re.escape(r[1])+r'(?![\w.-])',' '.join(p)) for s in parsed for index,p in active(dict(s,lines=[(i,line) for i,line in s['lines'] if r[1] in line and not line.lstrip().startswith('#')])) if p[0] not in ('use_backend','default_backend','description') and s is not backend):raise Unsupported('Backend упоминается в других директивах.')
                            data=pool(self.manager,backend,defaults)
                        protocol='https' if http and bind['tls'] else 'http' if http else 'tcp' if fallback and not bind['tls'] else 'tls'
                        certificate='';certificates=[]
                        if bind['tls']:
                            p=bind['line'].split();files=[p[i+1] for i,t in enumerate(p[:-1]) if t=='crt']
                            if not files or any(Path(f).parent!=Path(self.engine.settings['certificate_dir']) for f in files):raise Unsupported('Сертификаты bind должны быть файлами из каталога сертификатов панели.')
                            certificates=[Path(f).name for f in files];certificate=certificates[0]
                        domains=a[4:]
                        identifier=hashlib.sha256((front['name']+'\0'+str(route_index)+'\0'+r[1]).encode()).hexdigest()[:16]
                        data.update(naming='readable',id=identifier,name=(front['name']+' — '+domains[0] if redirect else r[1])[:80],protocol=protocol,enabled=True,port=bind['lo'],bind_address=bind['host'],domain=domains[0] if http else '',aliases=domains[1:] if http else [],sni_domains=domains if not http else [],sni_routing=not http and not fallback,tcp_frontend=front['name'] if fallback else '',tls_mode='terminate' if bind['tls'] else 'plain' if http or fallback else 'passthrough',certificate=certificate,certificates=certificates,redirect=False,http_host_match='raw' if a[2]=='hdr(host)' else 'normalized',imported=True)
                        model=self.manager.normalize(data,identifier)
                        if bind['tls']:self.manager.certificate_check(model)
                        removed=({route_index} if fallback else {acl_index,route_index})|(set(range(backend['start'],ends[backend['start']])) if backend else set())
                        candidates.append(dict(id=identifier,name=model['name'],frontend=front['name'],backend=backend['name'] if backend else 'HTTP redirect',protocol=PRESETS[protocol][0],domains=domains,port=bind['lo'],servers=[str(s['host'])+':'+str(s['port']) for s in model['backends']],model=model,removed=removed))
                    except (ValueError,TypeError,IndexError) as error:warnings.append(dict(name=front['name']+' → '+r[1],reason=str(error)))
            except (ValueError,TypeError,IndexError) as error:warnings.append(dict(name=front['name'],reason=str(error)))
        from .service_types import classify
        for candidate in candidates:candidate['classification']=classify(candidate['model'],parsed,self.engine.settings)
        return base,managed,candidates,warnings

    def certificate_warnings(self,base):
        from .certificate_info import metadata
        import shlex
        known={};warnings=[];seen=set()
        for section in bindings(base):
            for bind in section['binds']:
                if not bind['tls']:continue
                try:tokens=shlex.split(bind['line'],comments=True)
                except ValueError:continue
                for index,token in enumerate(tokens[:-1]):
                    if token!='crt':continue
                    path=Path(tokens[index+1])
                    if not path.is_absolute():continue
                    paths=sorted(path.glob('*.pem')) if path.is_dir() else [path]
                    for file in paths:
                        key=(section['name'],str(file))
                        if key in seen:continue
                        seen.add(key)
                        if str(file) not in known:known[str(file)]=metadata(self.engine,file)
                        item=known[str(file)]
                        if not item['readable']:problem='не читается или отсутствует'
                        elif item['expired']:problem='истёк'
                        elif item['not_yet_valid']:problem='ещё не действует'
                        else:continue
                        warnings.append('Общий TLS-вход '+section['name']+': сертификат '+file.name+' '+problem+'. Это зависимость входа, а не ошибка отдельного backend. Импорт сохраняет сертификат; проверьте его замену отдельно. Невалидная конфигурация HAProxy не будет применена.')
        return warnings

    def scan(self,value):
        text,current,revision=self.source(value);base,managed,candidates,warnings=self.discover(text)
        return dict(revision=revision,source=value.get('source','current'),fingerprint=hashlib.sha256(encode(text)).hexdigest(),candidates=[{k:v for k,v in c.items() if k not in ('model','removed','anchors')} for c in candidates],preserved=warnings,managed=len(managed),warnings=self.certificate_warnings(base)+(['Файл заменит основной конфиг целиком. Дополнительные .cfg останутся на сервере; сертификаты, ключи и другие файлы не переносятся.'] if value.get('source')=='file' else []),limit='Автоматически переносятся простые HTTP/HTTPS, SNI и TCP-маршруты с отдельными пулами, а также HTTP-редиректы. Доменные ACL с AND/OR и общими backend переносятся с сохранением исходных пулов и порядка правил. Сложные анонимные выражения и TLS-мосты остаются ручными. Дополнительные .cfg не импортируются.')

    def preview(self,value):
        text,current,revision=self.source(value)
        if value.get('fingerprint')!=hashlib.sha256(encode(text)).hexdigest():raise Conflict('Источник импорта изменился. Повторите анализ.')
        if value.get('source')=='file' and value.get('replace_confirm') is not True:raise ValueError('Подтвердите замену основного конфига файлом.')
        base,managed,candidates,warnings=self.discover(text)
        selected=value.get('selected');renames=value.get('names',{})
        if not isinstance(selected,list) or not selected or not all(isinstance(item,str) for item in selected) or len(selected)!=len(set(selected)) or not isinstance(renames,dict):raise ValueError('Выберите хотя бы одну публикацию без повторов.')
        chosen=[c for c in candidates if c['id'] in selected]
        if len(chosen)!=len(selected):raise ValueError('Список публикаций изменился. Повторите анализ.')
        ids={m['id'] for m in managed};removed=set()
        for c in chosen:
            if c['id'] in ids:raise ValueError('Публикация уже перенесена.')
            c['model']['name']=renames.get(c['id'],c['name']);
            types=value.get('types',{})
            if not isinstance(types,dict):raise ValueError('Выберите типы сервисов из списка.')
            if c['id'] in types:c['model']['service_type_override']=types[c['id']]
            c['model']=self.manager.normalize(dict(c['model'],sni_domains=c['model']['domains']),c['id'])
            ids.add(c['id']);removed.update(c['removed'])
        anchors={index:anchor for c in chosen for index,anchor in c.get('anchors',{}).items()}
        baseline=''.join(line if i not in removed else retained_comment(line)+anchors.get(i,'') for i,line in enumerate(base.splitlines(keepends=True)))
        candidate,notes=self.manager.render(baseline,managed+[c['model'] for c in chosen],probe=False)
        checked=self.engine.validate(candidate)
        checked['baseline']=self.engine.validate(current)
        checked.update(changed=candidate!=current,diff=''.join(difflib.unified_diff(mask(current)[0].splitlines(True),mask(candidate)[0].splitlines(True),fromfile='Текущая версия',tofile='Импорт публикаций')),summary=['Перенести в «Сервисы»: '+c['model']['name']+'.' for c in chosen],warnings=notes+self.certificate_warnings(base)+['Нераспознанные и невыбранные правила сохранены. Проверка синтаксиса не подтверждает полную эквивалентность поведения; проверьте разницу перед применением.']+(['Основной конфиг будет заменён загруженным файлом. Сохранится резервная копия текущего конфига.'] if value.get('source')=='file' else []))
        return checked,dict(raw=candidate,revision=revision,reason='service:import')
