"""Lossless ACL adoption: owned domain routes, retained shared backend and policies."""
import hashlib
import re
from pathlib import Path
from .services import hostname,number

FETCHES={'hdr(host)','hdr(host),lower,field(1,:)','req.ssl_sni','req_ssl_sni','ssl_fc_sni'}
ANCHOR='# studio-acl-slot '

def pool_servers(section):
    from .importer import active,endpoint,Unsupported
    rows=[]
    for _,parts in active(dict(section,lines=[(i,line) for i,line in section['lines'] if re.match(r'\s*server\s',line)])):
        if parts[0]!='server':continue
        if len(parts)<3:raise Unsupported('Неполная строка server.')
        host,port=endpoint(parts[2]);host=hostname(host)
        row=dict(name=parts[1],host=host,port=port,weight=1,backup='backup' in parts[3:])
        if 'weight' in parts[3:]:row['weight']=number(parts[parts.index('weight',3)+1],'Вес',1,256)
        rows.append(row)
    if not rows:raise Unsupported('Нет server с явными адресами; server-template и динамические адреса остаются ручными.')
    return rows

def domain_definition(definition):
    if len(definition)<4 or definition[2] not in FETCHES:return None
    args=definition[3:];ignore=False;values=[];i=0
    while i<len(args):
        value=args[i]
        if not values and value=='-i':ignore=True;i+=1;continue
        if not values and value=='-m' and i+1<len(args) and args[i+1]=='str':i+=2;continue
        if not values and value=='--':values=args[i+1:];break
        if value.startswith('-'):return None
        values.append(value);i+=1
    if not values:return None
    normalized=[]
    for value in values:
        name=hostname(value,'Домен ACL')
        if name!=(value.lower() if ignore else value):return None
        normalized.append(name)
    return ('req.ssl_sni' if definition[2]=='req_ssl_sni' else definition[2]),normalized,ignore

def terms(parts,acls):
    """HAProxy named ACL conditions are OR-separated conjunctions (implicit AND)."""
    from .importer import Unsupported
    if len(parts)<4 or parts[2]!='if':raise Unsupported('Нужен положительно ограниченный доменами маршрут if.')
    acls=dict(acls);expanded=[];tokens=parts[3:];i=0
    while i<len(tokens):
        if tokens[i]!='{':expanded.append(tokens[i]);i+=1;continue
        end=i+1
        while end<len(tokens) and tokens[end]!='}':end+=1
        if end==len(tokens) or '{' in tokens[i+1:end]:raise Unsupported('Незавершённый или вложенный анонимный ACL.')
        key='__studio_inline_'+str(i);definition=['acl',key]+tokens[i+1:end]
        if key in acls or domain_definition(definition) is None:raise Unsupported('Анонимный ACL должен сопоставлять точные домены Host или SNI.')
        acls[key]=[definition];expanded.append(key);i=end+1
    groups=[[]]
    for item in expanded:
        if item in ('or','||'):
            if not groups[-1]:raise Unsupported('Пустая ветвь OR.')
            groups.append([])
        else:groups[-1].append(item)
    output=[];fetches=set()
    for group in groups:
        if not group:raise Unsupported('Пустая ветвь OR.')
        positive=[];negative=[];tests=[];case_modes=set()
        for item in group:
            if item in ('and','&&','{','}') or not re.fullmatch(r'!?[A-Za-z0-9_.:-]+',item):raise Unsupported('Анонимные ACL и вложенные выражения пока остаются ручными.')
            name=item.lstrip('!');definitions=acls.get(name)
            if not definitions:raise Unsupported('ACL '+name+' не определён в этом frontend.')
            domain_values=[];domain_fetches=set();domain_acl=True;definition_modes=set()
            for definition in definitions:
                parsed=domain_definition(definition)
                if parsed is None:domain_acl=False;break
                domain_fetches.add(parsed[0]);domain_values.extend(parsed[1]);definition_modes.add(parsed[2])
            if len(definition_modes)>1:raise Unsupported('Один ACL содержит разные правила регистра домена; он остаётся ручным.')
            if domain_acl:
                fetches.update(domain_fetches);case_modes.update(definition_modes)
                (negative if item.startswith('!') else positive).append(set(domain_values))
            else:
                # Other named ACLs remain in the frontend verbatim, including path,
                # source IP and their negations. Never flatten them into host matching.
                tests.append(item)
        if not positive:raise Unsupported('Каждой ветви OR нужен положительный ACL точных доменов; дополнение доменов не ограничено.')
        if len(case_modes)>1:raise Unsupported('В одной ветви смешаны чувствительные и нечувствительные к регистру доменные ACL.')
        values=set.intersection(*positive)
        for excluded in negative:values-=excluded
        if values:output.append(dict(domains=sorted(values),tests=tests,ignore_case=next(iter(case_modes))))
    if len(fetches)!=1:raise Unsupported('Разные способы сопоставления доменов требуют отдельных публикаций.')
    if not output:raise Unsupported('Условие не содержит достижимых доменов.')
    return output,next(iter(fetches))

def routing_commands(section):
    # Other policies are retained as bytes. An opaque ACL can remain a named
    # additional predicate, but cannot establish a finite set of domains by itself.
    from .importer import active,Unsupported
    result=[]
    for index,line in section['lines']:
        prefix=re.match(r'\s*(acl|use_backend|default_backend)\s+(\S+)',line)
        if not prefix:continue
        try:result.extend(active(dict(section,lines=[(index,line)])))
        except Unsupported:result.append((index,[prefix[1],prefix[2],'__opaque__','__opaque__']))
    return result

def discover(manager,base,parsed,existing=()):
    from .importer import Unsupported
    names={};result=[];handled=set();warnings=[]
    for section in parsed:names.setdefault(section['name'],[]).append(section)
    for front in parsed:
        if front['type']!='frontend' or front['name'].startswith('studio_fe_') or len(front['binds'])!=1:continue
        bind=front['binds'][0]
        if bind['lo']!=bind['hi']:continue
        commands=routing_commands(front)
        acls={}
        for _,p in commands:
            if p[0]=='acl' and len(p)>3:acls.setdefault(p[1],[]).append(p)
        grouped={}
        for index,p in commands:
            if p[0]=='use_backend' and len(p)>1 and '%' not in p[1]:grouped.setdefault(p[1],[]).append((index,p))
        complex_front=any(len(rows)>1 or any(len(p)!=4 for _,p in rows) for rows in grouped.values())
        for target,routes in grouped.items():
            # Keep the established fully typed importer for simple isolated pairs.
            references=[line for s in parsed for _,line in s['lines'] if re.match(r'\s*(?:use_backend|default_backend)\s+'+re.escape(target)+r'(?:\s|$)',line)]
            special=(bind['tls'] and len(re.findall(r'\bcrt\s+',bind['line']))>1) or complex_front or any(m.get('import_pool')==target for m in existing) or len(references)>1 or any(len(p)!=4 for _,p in routes) or any(re.match(r'\s*http-request\s+redirect\b',line) for _,line in front['lines'])
            if not special:continue
            try:
                pool=names.get(target,[])
                if len(pool)!=1 or pool[0]['type']!='backend' or pool[0]['mode']!=front['mode']:raise Unsupported('Backend отсутствует, неоднозначен или имеет другой режим.')
                slots=[];fetches=set()
                for index,p in routes:
                    branches,fetch=terms(p,acls);fetches.add(fetch);slots.append(dict(line=index,terms=branches))
                if len(fetches)!=1:raise Unsupported('Маршруты используют разные способы сопоставления доменов.')
                fetch=fetches.pop();http=front['mode']=='http'
                if http and not(fetch.startswith('hdr(host)') or bind['tls'] and fetch=='ssl_fc_sni'):raise Unsupported('Доменный ACL не соответствует режиму входа.')
                if not http and fetch.startswith('hdr(host)'):raise Unsupported('HTTP Host ACL не соответствует TCP-входу.')
                if not http and (fetch=='ssl_fc_sni')!=bind['tls']:raise Unsupported('SNI не соответствует TLS-режиму bind.')
                protocol='https' if http and bind['tls'] else 'http' if http else 'tls'
                if not http and not bind['tls']:mode='passthrough'
                else:mode='terminate' if bind['tls'] else 'plain'
                certificate='';certificates=[]
                if bind['tls']:
                    import shlex
                    tokens=shlex.split(bind['line'],comments=True)
                    paths=[tokens[i+1] for i,t in enumerate(tokens[:-1]) if t=='crt']
                    if not paths or any(Path(p).parent!=Path(manager.engine.settings['certificate_dir']) for p in paths):raise Unsupported('Для этого bind нужны явные PEM-файлы из каталога панели; crt-list остаётся ручным.')
                    certificates=[Path(p).name for p in paths];certificate=certificates[0]
                domains=list(dict.fromkeys(d for slot in slots for term in slot['terms'] for d in term['domains']))
                identifier=hashlib.sha256(('acl-pool\0'+front['name']+'\0'+target).encode()).hexdigest()[:16]
                imported=dict(listener_port=bind['lo'],listener_address=bind['host'],frontend=front['name'],fetch=fetch,slots=[dict(terms=s['terms']) for s in slots])
                data=dict(id=identifier,imported=True,import_pool=target,import_acl=imported,naming='legacy',name=target,protocol=protocol,enabled=True,port=bind['lo'],bind_address=bind['host'],domain=domains[0] if http else '',aliases=domains[1:] if http else [],sni_domains=domains if not http else [],sni_routing=not http,tls_mode=mode,certificate=certificate,certificates=certificates,redirect=False,backends=pool_servers(pool[0]),health='none',forward_headers=False)
                if http and bind['tls'] and bind['host'] in ('127.0.0.1','::1'):
                    possibilities=[]
                    for outer in parsed:
                        if outer['type']!='frontend' or outer['mode']!='tcp':continue
                        for public in outer['binds']:
                            if public['tls'] or public['lo']!=public['hi']:continue
                            trial=dict(data,port=public['lo'],bind_address=public['host'],https_frontend=front['name'])
                            try:
                                candidate=manager.normalize(trial,identifier)
                                resolved=resolve_bridge(candidate,parsed,existing)
                                if resolved and resolved[0]['name']==front['name']:possibilities.append(trial)
                            except ValueError:pass
                    if len(possibilities)>1:raise Unsupported('Несколько внешних портов ведут во внутренний HTTPS-вход; сопоставьте их вручную.')
                    if possibilities:data=possibilities[0]
                    elif 'accept-proxy' in bind['line'].split():raise Unsupported('Не подтверждён внешний TCP/SNI-вход и PROXY protocol для внутреннего HTTPS.')
                elif 'accept-proxy' in bind['line'].split():raise Unsupported('accept-proxy без проверенного HTTPS-моста остаётся ручным.')
                model=manager.normalize(data,identifier)
                anchors={slot['line']:ANCHOR+identifier+' '+str(i)+'\n' for i,slot in enumerate(slots)}
                result.append(dict(id=identifier,name=target,frontend=front['name'],backend=target,protocol='ACL → общий пул (параметры backend сохраняются)',domains=domains,port=data['port'],servers=[s['host']+':'+str(s['port']) for s in data['backends']],model=model,removed=set(anchors),anchors=anchors))
                handled.update(anchors)
            except (ValueError,TypeError,IndexError) as error:warnings.append(dict(name=front['name']+' → '+target,reason=str(error)))
    return result,handled,warnings

def normalize(data,m):
    if not data.get('import_pool'):return m
    from .enterprise import names
    if not m.get('imported') or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',str(data['import_pool'])):raise ValueError('Некорректная ссылка на импортированный общий backend.')
    source=data.get('import_acl')
    if not isinstance(source,dict) or source.get('fetch') not in FETCHES or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',str(source.get('frontend',''))):raise ValueError('Повреждены данные импортированных ACL.')
    slots=source.get('slots')
    if not isinstance(slots,list) or not 1<=len(slots)<=128:raise ValueError('Некорректное число маршрутов ACL.')
    parsed=[]
    for slot in slots:
        if not isinstance(slot,dict) or not isinstance(slot.get('terms'),list) or not 1<=len(slot['terms'])<=128:raise ValueError('Некорректные ветви ACL.')
        branches=[]
        for term in slot['terms']:
            if not isinstance(term,dict):raise ValueError('Некорректная ветвь ACL.')
            tests=term.get('tests',[])
            if not isinstance(tests,list) or len(tests)>64 or any(not isinstance(t,str) or not re.fullmatch(r'!?[A-Za-z0-9_.:-]{1,128}',t) for t in tests):raise ValueError('Повреждены ссылки на ACL.')
            domains=names(term.get('domains',[]))
            if not domains:raise ValueError('Пустой ACL домена.')
            if not isinstance(term.get('ignore_case',True),bool):raise ValueError('Некорректное сопоставление регистра домена.')
            branches.append(dict(domains=domains,tests=tests,ignore_case=term.get('ignore_case',True)))
        parsed.append(dict(terms=branches))
    for row,source_row in zip(m['backends'],data.get('backends',[])):
        if source_row.get('name'):row['name']=source_row['name']
    template=data.get('import_domain_template','')
    original={d for slot in parsed for term in slot['terms'] for d in term['domains']}
    if not isinstance(template,str) or template and template not in original:raise ValueError('Выберите существующий домен как образец правил.')
    m['import_domain_template']=template
    m['import_pool']=data['import_pool'];m['import_acl']=dict(listener_port=number(source.get('listener_port',m['port']),'Внутренний порт'),listener_address=str(source.get('listener_address',m['bind_address'])),frontend=source['frontend'],fetch=source['fetch'],slots=parsed)
    return m

def attach(manager,base,parsed,model,add,models=()):
    """Emit only backend choices at their original positions. All policies stay raw."""
    front=next((s for s in parsed if s['type']=='frontend' and s['name']==model['import_acl']['frontend']),None)
    pool=next((s for s in parsed if s['type']=='backend' and s['name']==model['import_pool']),None)
    if not front or not pool or front['mode']!=pool['mode']:raise ValueError('Frontend или общий backend импортированной публикации изменён. Повторите импорт.')
    http=front['mode']=='http'
    if (model['protocol'] in ('http','https'))!=http or not any(b['lo']==b['hi']==model['import_acl']['listener_port'] and b['host']==model['import_acl']['listener_address'] and b['tls']==(model['tls_mode']=='terminate') for b in front['binds']):raise ValueError('Порт, адрес и TLS импортированного входа меняются в исходной конфигурации, а не отдельно от общего frontend.')
    if model['import_acl']['listener_port']!=model['port'] or model['import_acl']['listener_address']!=model['bind_address']:
        resolved=resolve_bridge(model,parsed,models)
        if not resolved or resolved[0]['name']!=front['name']:raise ValueError('Связь внешнего SNI-входа и внутреннего HTTPS изменилась.')
    current=set(model['domains']);original={d for slot in model['import_acl']['slots'] for term in slot['terms'] for d in term['domains']};extra=current-original
    if extra and model['tls_mode']=='terminate':
        manager.certificate_check(dict(model,domains=sorted(extra)))
    profiles={(t.get('ignore_case',True),tuple(t['tests'])) for slot in model['import_acl']['slots'] for t in slot['terms']}
    if extra and len(profiles)>1 and not model.get('import_domain_template'):raise ValueError('У доменов этого пула разные дополнительные ACL. Выберите существующий домен как образец правил для новых доменов.')
    template=model.get('import_domain_template') or model['import_acl']['slots'][0]['terms'][0]['domains'][0]
    available={p[1] for _,p in routing_commands(front) if p[0]=='acl' and len(p)>1}
    for i,slot in enumerate(model['import_acl']['slots']):
        marker=ANCHOR+model['id']+' '+str(i)
        matches=[index for index,line in front['lines'] if line.strip()==marker]
        if len(matches)!=1:raise ValueError('Место импортированного ACL изменено вручную. Восстановите конфигурацию из истории.')
        body=''
        for j,term in enumerate(slot['terms']):
            domains=set(term['domains'])&current
            if template in term['domains']:domains|=extra
            if not domains:continue
            if any(t.lstrip('!') not in available for t in term['tests']):raise ValueError('Исходный ACL, используемый импортированной публикацией, удалён.')
            acl='st_'+model['id']+'_slot'+str(i)+'_term'+str(j)
            if acl in available:raise ValueError('Имя управляемого ACL уже определено вручную: '+acl)
            body+='    acl '+acl+' '+model['import_acl']['fetch']+(' -i ' if term.get('ignore_case',True) else ' ')+' '.join(sorted(domains))+'\n'
            body+='    use_backend '+model['import_pool']+' if '+acl+(' '+' '.join(term['tests']) if term['tests'] else '')+'\n'
        if body:add(matches[0],model,'aclroute'+str(i),body)
    return front

def resolve_bridge(model,parsed,models=()):
    """Prove first-match SNI -> raw TLS bridge, including conditional use_backend."""
    from .importer import active
    target=next((s for s in parsed if s['name']==model['import_acl']['frontend'] and s['type']=='frontend'),None)
    if not target:return None
    bind=next((b for b in target['binds'] if b['lo']==model['import_acl']['listener_port'] and b['host'] in ('127.0.0.1','::1') and b['tls']),None)
    if not bind:return None
    candidates=[]
    for pool in parsed:
        if pool['type']!='backend' or pool['mode']!='tcp':continue
        try:commands=active(pool)
        except ValueError:continue
        servers=[p for _,p in commands if p[0]=='server']
        if len(servers)!=1:continue
        p=servers[0];expected=('['+bind['host']+']' if ':' in bind['host'] else bind['host'])+':'+str(bind['lo'])
        if len(p)<3 or p[2]!=expected or 'ssl' in p[3:]:continue
        if any(x in p[3:] for x in ('send-proxy','send-proxy-v2'))!=('accept-proxy' in bind['line'].split()):continue
        candidates.append(pool['name'])
    from .services import overlaps
    domains=set(model['domains']);matches=[]
    for outer in parsed:
        if outer['type']!='frontend' or outer['mode']!='tcp' or not any(b['lo']==b['hi']==model['port'] and overlaps(b['host'],model['bind_address']) and (model['bind_address'] not in ('*','0.0.0.0','::') or b['host'] in ('*','0.0.0.0','::')) and not b['tls'] for b in outer['binds']):continue
        commands=routing_commands(outer)
        acls={};routes=[];fallback=None
        for _,p in commands:
            if p[0]=='acl' and len(p)>3:acls.setdefault(p[1],[]).append(p)
        for index,p in commands:
            if p[0]=='default_backend' and len(p)==2:fallback=p[1]
            elif p[0]=='use_backend' and len(p)>1:
                try:
                    branches,fetch=terms(p,acls)
                    if fetch!='req.ssl_sni':raise ValueError('Not ClientHello SNI')
                    routes.extend((index,p[1],set(t['domains']),bool(t['tests'])) for t in branches)
                except ValueError:routes.append((index,p[1],None,True))
        for owned in models:
            if not owned.get('import_pool') or not owned['enabled'] or owned['import_acl']['frontend']!=outer['name']:continue
            original={d for slot in owned['import_acl']['slots'] for term in slot['terms'] for d in term['domains']}
            for i,slot in enumerate(owned['import_acl']['slots']):
                position=next((n for n,line in outer['lines'] if line.strip()==ANCHOR+owned['id']+' '+str(i)),None)
                if position is None:continue
                for j,term in enumerate(slot['terms']):
                    values=set(term['domains'])&set(owned['domains'])
                    template=owned.get('import_domain_template') or owned['import_acl']['slots'][0]['terms'][0]['domains'][0]
                    if template in term['domains']:values|=set(owned['domains'])-original
                    routes.append((position,owned['import_pool'],values,bool(term['tests'])))
        selected=set();proven=True
        for domain in domains:
            destination=fallback
            for _,backend,values,conditional in sorted(routes,key=lambda row:row[0]):
                if values is not None and domain not in values:continue
                if conditional:proven=False;break
                destination=backend;break
            if not proven:break
            selected.add(destination)
        if proven and len(selected)==1 and next(iter(selected)) in candidates:matches.append((target,bind,True))
    return matches[0] if len(matches)==1 else None
