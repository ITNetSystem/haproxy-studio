"""Reviewed conversion of legacy SNI-on-STARTTLS frontends into dedicated TCP services."""
import copy
import difflib
import hashlib
import json
import ipaddress
import re
from .core import Conflict,decode,mask
from .services import clean,bindings,number
from .importer import active,pool,seconds
from .naming import slug


def inspect(manager):
    raw,_=manager.engine.snapshot();base,models=clean(raw);parsed=bindings(base)
    named={s['name']:s for s in parsed};defaults=next((s for s in parsed if s['type']=='defaults'),None);result=[]
    for front in parsed:
        if front['type']!='frontend' or front['mode']!='tcp' or len(front['binds'])!=1:continue
        bind=front['binds'][0]
        if bind['tls'] or bind['lo']!=bind['hi'] or bind['lo'] not in (143,587):continue
        try:commands=active(front)
        except ValueError:continue
        if not any(p[0]=='use_backend' for _,p in commands) or not any('ssl_fc_sni' in line for _,line in front['lines']):continue
        entry=dict(frontend=front['name'],port=bind['lo'],address=bind['host'],rows=[],error='')
        try:
            if sum(s['type']=='defaults' for s in parsed)>1:raise ValueError('Несколько defaults требуют отдельной проверки наследования.')
            if any(m.get('sni_routing') and m['port']==bind['lo'] for m in models):raise ValueError('На этом порту уже есть управляемые TLS-службы. Сначала разделите входы.')
            if sum(s['name']==front['name'] for s in parsed)!=1:raise ValueError('Имя входа неоднозначно.')
            if any(m.get('tcp_frontend')==front['name'] or m.get('import_acl',{}).get('frontend')==front['name'] for m in models):raise ValueError('Вход уже содержит управляемые службы; измените его отдельно.')
            if any(p[2:] for _,p in commands if p[0]=='bind'):raise ValueError('Дополнительные параметры bind требуют отдельного переноса.')
            acls={p[1]:p for _,p in commands if p[0]=='acl' and len(p)>3};targets=[];fallback=None;timeout=None
            for _,p in commands:
                if p[0] in ('bind','mode','description') or p==['log','global']:continue
                if p[0]=='option' and p[1:]==['tcplog']:continue
                if p[:2]==['timeout','client'] and len(p)==3:timeout=seconds(p[2]);continue
                if p[0]=='acl' and p[2]=='ssl_fc_sni':continue
                if p[0]=='use_backend' and len(p)>=4 and p[2]=='if':
                    condition=p[3:]
                    direct=condition[:2]==['{','ssl_fc_sni'] and condition[-1:]==['}'] and condition.count('{')==condition.count('}')==1
                    named_acl=len(condition)==1 and acls.get(condition[0],['','',''])[2]=='ssl_fc_sni'
                    if not direct and not named_acl:raise ValueError('Есть другое условие маршрутизации; автоматическая замена входа остановлена.')
                    targets.append(p[1]);continue
                if p[0]=='default_backend' and len(p)==2:
                    if fallback:raise ValueError('Несколько default_backend.')
                    fallback=p[1];targets.append(p[1]);continue
                raise ValueError('Политика '+p[0]+' требует отдельного переноса; исходный вход сохранён.')
            rows={}
            for target in dict.fromkeys(targets):
                section=named.get(target)
                if sum(s['name']==target for s in parsed)!=1:raise ValueError('Имя backend неоднозначно: '+target)
                if not section or section['type']!='backend' or section['mode']!='tcp':raise ValueError('Не найден TCP-backend '+target)
                data=pool(manager,section,active(defaults) if defaults else [])
                if data.get('upstream_tls'):raise ValueError('Для STARTTLS не допускается немедленный TLS до backend '+target)
                signature=copy.deepcopy(data)
                for server in signature['backends']:server.pop('name',None)
                key=json.dumps(signature,sort_keys=True)
                if key not in rows:rows[key]=dict(key=hashlib.sha256((front['name']+'\0'+target).encode()).hexdigest()[:16],pools=[],servers=[dict(host=b['host'],port=b['port']) for b in data['backends']],address='',port=bind['lo'],data=data)
                row=rows[key];row['pools'].append(target)
                if target==fallback:row.update(address=bind['host'],port=bind['lo'])
                if timeout is not None:row['data']['client_timeout']=timeout
            if not rows:raise ValueError('Нет пулов для переноса.')
            from .exchange_groups import groups
            from .exchange_mail import choose_group
            from .acl_import import pool_servers
            farms=groups(copy.deepcopy(models),base,manager.engine.settings)
            source_pools={s['name']:s for s in parsed if s['type']=='backend'}
            addresses={m['id']:{b['host'] for b in (pool_servers(source_pools[m['import_pool']]) if m.get('import_pool') in source_pools else m['backends'])} for m in models}
            for row in rows.values():
                group=choose_group(farms,[],{b['host'] for b in row['servers']},addresses)
                row['exchange_name']=group['name'] if group else ''
            entry['rows']=[{k:v for k,v in row.items() if k!='data'} for row in rows.values()]
        except (ValueError,TypeError,IndexError) as error:entry['error']=str(error)
        result.append(entry)
    return result


def preview(manager,value):
    engine=manager.engine
    if engine.settings['read_only']:raise ValueError('Изменения отключены.')
    if not isinstance(value,dict):raise ValueError('Нужны настройки входов STARTTLS.')
    raw,revision=engine.snapshot()
    if revision!=value.get('revision'):raise Conflict('Конфигурация изменилась. Повторите проверку.')
    plan=next((p for p in inspect(manager) if p['frontend']==value.get('frontend')),None)
    if not plan:raise ValueError('Исходный вход STARTTLS изменён или не найден.')
    if plan['error']:raise ValueError(plan['error'])
    submitted=value.get('bindings')
    if not isinstance(submitted,list) or len(submitted)!=len(plan['rows']) or any(not isinstance(v,dict) for v in submitted):raise ValueError('Укажите адрес и порт для каждого пула / DAG.')
    patches={row.get('key'):row for row in submitted}
    if len(patches)!=len(submitted) or set(patches)!={r['key'] for r in plan['rows']}:raise ValueError('Состав пулов изменился. Повторите проверку.')
    from .services import overlaps,address as endpoint
    selected={}
    for row in plan['rows']:
        bind_host=patches[row['key']].get('address','')
        if not isinstance(bind_host,str) or not bind_host.strip():raise ValueError('Для каждого пула укажите IP на HAProxy либо * и отдельный порт.')
        bind_host=bind_host.strip()
        if bind_host!='*':
            try:bind_host=str(ipaddress.ip_address(bind_host.strip('[]')))
            except ValueError:raise ValueError('Укажите IP на HAProxy либо *, без домена, протокола и порта.')
        port=number(patches[row['key']].get('port'),'Порт входа на HAProxy')
        for other in plan['rows']:
            if other['key'] not in selected:continue
            host,used=selected[other['key']]
            if port==used and overlaps(host,bind_host):
                first=other.get('exchange_name') or ', '.join(other['pools']);second=row.get('exchange_name') or ', '.join(row['pools'])
                raise ValueError('Один вход на HAProxy '+endpoint(bind_host,port)+' задан для разных назначений: '+first+' и '+second+'. Знак * занимает все IPv4-адреса HAProxy. Укажите разные порты на одном IP либо разные IP на HAProxy; внутренние адреса Exchange здесь не разделяют вход.')
        selected[row['key']]=(bind_host,port)
    base,models=clean(raw);parsed=bindings(base);front=next(s for s in parsed if s['name']==plan['frontend']);lines=base.splitlines(True)
    end=next((s['start'] for s in parsed if s['start']>front['start']),len(lines));comments=''.join(line for line in lines[front['start']:end] if line.lstrip().startswith('#'))
    baseline=''.join(lines[:front['start']])+comments+''.join(lines[end:]);defaults=next((s for s in parsed if s['type']=='defaults'),None)
    from .exchange_groups import groups
    from .exchange_mail import choose_group
    farms=groups(copy.deepcopy(models),base,engine.settings)
    from .acl_import import pool_servers
    source_pools={s['name']:s for s in parsed if s['type']=='backend'}
    addresses={m['id']:{b['host'] for b in (pool_servers(source_pools[m['import_pool']]) if m.get('import_pool') in source_pools else m['backends'])} for m in models}
    for row in plan['rows']:
        address,port=selected[row['key']];target=row['pools'][0];section=next(s for s in parsed if s['type']=='backend' and s['name']==target)
        data=pool(manager,section,active(defaults) if defaults else [])
        timeout=next((seconds(p[2]) for _,p in active(front) if p[:2]==['timeout','client']),None)
        if timeout is None:
            timeout=next((seconds(p[2]) for _,p in active(defaults) if p[:2]==['timeout','client']),None) if defaults else None
        if timeout is not None:data['client_timeout']=timeout
        data['log_global']=any(p==['log','global'] for _,p in active(front))
        protocol='submission' if plan['port']==587 else 'imap'
        group=choose_group(farms,[],{s['host'] for s in row['servers']},addresses)
        data.update(name=(group['name']+' — ' if group else '')+('Почта SMTP Submission' if protocol=='submission' else 'Почта IMAP'),protocol=protocol,bind_address=address.strip(),port=port,domain='',sni_domains=[],sni_routing=False,tls_mode='plain',certificate='',redirect=False,naming='readable',backend_name='be_'+slug(target.removeprefix('be_'))[:42]+'_starttls')
        if group:data['exchange_parent']=group['web_members'][0]
        identifier=row['key']
        if any(m['id']==identifier for m in models):raise ValueError('Идентификатор службы уже существует.')
        from .naming import allocate_acl
        data['acl_prefix']=allocate_acl(data,set(re.findall(r'(?m)^\s*acl\s+(\S+)',baseline))|{m['acl_prefix'] for m in models if m.get('acl_prefix')})
        models.append(manager.normalize(data,identifier))
    candidate,warnings=manager.render(baseline,models,probe=True,owned_bindings=[b for section in bindings(decode(raw)) for b in section['binds']])
    if engine.snapshot()[1]!=revision:raise Conflict('Конфигурация изменилась во время проверки. Повторите план.')
    checked=engine.validate(candidate)
    checked.update(changed=candidate!=raw,diff=''.join(difflib.unified_diff(mask(raw)[0].splitlines(True),mask(candidate)[0].splitlines(True),fromfile='До исправления STARTTLS',tofile='Отдельные входы пулов / DAG')),summary=['Вход '+plan['frontend']+' заменится '+str(len(plan['rows']))+' управляемыми TCP-службами без SNI. Одинаковые пулы объединены; узлы одного пула сохраняются вместе.'],warnings=warnings+['Настройки внешнего NAT, DNS и firewall не изменяются. Исходные backend сохраняются для других протоколов. Старые SNI-условия этого входа удаляются только после применения. Новые пулы независимы от исходных backend.'])
    return checked,dict(raw=candidate,revision=revision,reason='service:starttls-repair')
