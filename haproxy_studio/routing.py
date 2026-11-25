"""Presentation only: describe managed routes without changing HAProxy configuration."""
from .naming import backend_name
import re
from .services import BLOCK,bindings,decode


def describe(raw,sections,models):
    by_id={m['id']:m for m in models};pools={}
    for model in models:
        pools[backend_name(model)]=(model,None)
        for route in model.get('routes',[]):
            if route['action']=='backend':pools[backend_name(model,route)]=(model,route)
    parsed=bindings(decode(raw));parsed_names={s['name']:s for s in parsed}
    named={s['name']:s for s in sections};bridges={}
    # A transport bridge is identified by its destination, never by a guessed name.
    for section in sections:
        if section['type']!='backend' or len(section['servers'])!=1:continue
        if parsed_names.get(section['name'],{}).get('mode')!='tcp':continue
        address=section['servers'][0]['address']
        for target in parsed:
            for bind in target['binds']:
                host=bind['host'];endpoint=('['+host+']' if ':' in host else host)+':'+str(bind['lo'])
                if host in ('127.0.0.1','::1') and bind['tls'] and target['mode']=='http' and bind['lo']==bind['hi'] and address==endpoint:
                    bridges[section['name']]=target['name']
    for section in sections:
        section['display_name']=section['name'];section['purpose']='';section['route_cards']=[]
        if section['type']=='backend':
            if section['name'] in pools:
                model,route=pools[section['name']];section['display_name']=model['name'];section['route_path']=route['path'] if route else ''
            elif section['name'] in bridges:
                section['display_name']='Локальная обработка HTTPS';section['purpose']='Передаёт TLS локальному HTTPS-входу.'
            continue
        if section['type'] not in ('frontend','listen'):continue
        spec=parsed_names.get(section['name'],{});port=', '.join(str(b['lo']) if b['lo']==b['hi'] else str(b['lo'])+'–'+str(b['hi']) for b in spec.get('binds',[]))
        tls=any(b['tls'] for b in spec.get('binds',[]));body=''.join(line for _,line in spec.get('lines',[]))
        if re.search(r'^\s*stats enable\s*$',body,re.M):section.update(display_name='Статистика HAProxy',purpose='Страница статистики и состояния HAProxy.')
        elif section['name'] in bridges.values():section.update(display_name='Локальный вход HTTPS',purpose='Расшифровывает TLS, полученный через локальный мост. Внешний порт указан на общем TLS-входе.')
        elif spec.get('mode')=='http':section['display_name']='Вход '+('HTTPS' if tls else 'HTTP')+(' · '+port if port else '')
        elif 'req.ssl_sni' in body or 'ssl_fc_sni' in body:section.update(display_name='Общий вход TLS'+(' · '+port if port else ''),purpose='Выбирает публикацию по имени домена в TLS (SNI).')
        else:section['display_name']='Вход TCP'+(' / TLS' if tls else '')+(' · '+port if port else '')
        for route in section['routes']:
            target=named.get(route['backend']);model,specific=pools.get(route['backend'],(None,None))
            card=dict(service_id=model['id'] if model else None,kind='proxy',name=model['name'] if model else target.get('display_name',route['backend']) if target else route['backend'],domains=model.get('domains') or ([model['domain']] if model.get('domain') else []) if model else [],path=specific['path'] if specific else model.get('path','/') if model else '',destination=', '.join(s['address'] for s in target['servers']) if target else '',line=route['line'],technical_backend=route['backend'],technical_condition=route['condition'],condition='')
            if model:
                if not route['condition']:card['condition']='Все подключения' if len(section['routes'])==1 and not model.get('sni_routing') else 'Остальные подключения (по умолчанию)'
                elif model.get('sni_routing'):card['condition']='По имени TLS (SNI)'
                elif not model.get('domain'):card['condition']='Все подключения'
                else:card['condition']='Домен и путь' if card['path']!='/' else 'Все пути этого домена'
                if '_exception' in route['condition'] and model.get('http_exceptions'):
                    card.update(path=' | '.join(model['http_exceptions']),condition='HTTP без перенаправления на HTTPS для этих путей')
                if model.get('allowed_ips'):card['condition']+=' · разрешённые источники: '+model['allowed_ips']
            else:
                card['condition']='Остальные подключения' if not route['condition'] else 'Ручное условие — см. технические детали'
            if route['backend'] in bridges:
                card.update(name='Остальные HTTPS-сайты',condition='Если отдельная TLS-публикация не выбрана',destination='Локальный вход HTTPS → '+card['destination'])
            section['route_cards'].append(card)
    # Existing frontends use route blocks; generated frontends contain actions inside
    # their own block. Resolve both so redirects never disappear from the overview.
    text=decode(raw);exposures={}
    for match in BLOCK.finditer(text):
        if match[2] not in ('route','redirect','policy') or match[1] not in by_id:continue
        line=text.count('\n',0,match.start())+1
        section=next((s for i,s in enumerate(sections) if s['type'] in ('frontend','listen') and s['line']<line<(sections[i+1]['line'] if i+1<len(sections) else len(text.splitlines())+1)),None)
        if section is not None:exposures[(section['name'],match[1],match[2])]=line
    for section in sections:
        if section['type']!='frontend' or not section['name'].startswith('studio_fe_'):continue
        spec=parsed_names.get(section['name'],{});body=''.join(line for _,line in spec.get('lines',[]))
        for model in models:
            if not re.search(r'\bacl st_'+re.escape(model['id'])+r'_(?:host|sni)\b',body):continue
            phase='redirect' if model.get('redirect') and any(b['lo']==model['http_port'] and not b['tls'] for b in spec.get('binds',[])) else 'route'
            exposures.setdefault((section['name'],model['id'],phase),section['line']+1)
    for (section_name,identifier,phase),line in exposures.items():
        if phase=='route' and (section_name,identifier,'policy') in exposures:continue
        section=named[section_name]
        model=by_id[identifier];domains=model.get('domains') or ([model['domain']] if model.get('domain') else [])
        def add(kind,path,destination,condition):
            section['route_cards'].append(dict(service_id=model['id'],kind=kind,name=model['name'],domains=domains,path=path,destination=destination,condition=condition,line=line,technical_backend='',technical_condition='Блок сервиса '+model['id']+' · '+phase))
        if phase=='redirect' or model.get('http_action')=='redirect':
            add('redirect',model['path'] if not model.get('http_redirect_all_paths') else '/',model.get('http_redirect_location') or 'HTTPS того же домена','HTTP → HTTPS · код '+str(model.get('redirect_code',301)) if not model.get('http_redirect_location') else 'Перенаправление · код '+str(model.get('redirect_code',301)))
            continue
        if model.get('canonical_slash'):add('redirect',model['path'],model['path']+'/','Добавить / в конце пути · код 302')
        if model.get('root_redirect') and (model.get('path','/')=='/' or model.get('redirect_root')):add('redirect','/',model['root_redirect'],'Перенаправить корень сайта · код 302')
        for route in model.get('routes',[]):
            if route['action']=='deny':add('deny',route['path'],'Ответ 403','Доступ к пути закрыт')
        if model.get('fallback_status') and model.get('routes'):add('deny','', 'Ответ '+str(model['fallback_status']),'Остальные пути, не перечисленные выше')
        if model.get('reject_other_paths'):add('deny','', 'Ответ 404','Пути вне '+model['path'])
    # Keep the same ordering as the actual configuration, including generated actions.
    for section in sections:section['route_cards'].sort(key=lambda card:card['line'])
    return sections


def publications(models,rows,sections):
    """Service-centric view: public address -> application, with infrastructure separate."""
    from .services import PRESETS,address
    from .monitoring import service_status
    result=[]
    for model in models:
        kind=PRESETS[model['protocol']][3];domains=model.get('domains') or ([model['domain']] if model.get('domain') else [])
        web=kind=='http';scheme='https' if model['tls_mode']=='terminate' else 'http'
        if web:
            source=[scheme+'://'+domain+(':'+str(model['port']) if model['port']!=(443 if scheme=='https' else 80) else '')+(model['path'] if model['path']!='/' else '') for domain in domains]
            connection='HTTPS' if scheme=='https' else 'HTTP'
        else:
            source=[domain+':'+str(model['port']) for domain in domains] if domains else [address(model['bind_address'],model['port']) if model['bind_address']!='*' else 'Адрес HAProxy · порт '+str(model['port'])]
            connection=PRESETS[model['protocol']][0]
        if model['protocol'] in ('rdweb','rdgateway','rdwebproxy') and domains:
            from .rdweb import path as portal_path
            source=['https://'+domain+(':'+str(model['port']) if model['port']!=443 else '')+portal_path(model) for domain in domains]
        runtime_pool=[r for r in rows if r['pxname']==backend_name(model) and r['svname'] not in ('FRONTEND','BACKEND')]
        routes=[dict(action=r['action'],rows=[entry for entry in rows if entry['pxname']==backend_name(model,r) and entry['svname'] not in ('FRONTEND','BACKEND')]) for r in model.get('routes',[])]
        cards=[dict(card,entrance=s['display_name'],technical_frontend=s['name']) for s in sections for card in s.get('route_cards',[]) if card.get('service_id')==model['id']]
        from .naming import names as pool_names
        actual_pools=[] if model.get('fallback_status') and model.get('routes') else [model['backends']]
        actual_pools.extend(route['backends'] for route in model.get('routes',[]) if route['action']=='backend')
        actual_servers=[server for pool in actual_pools for server in pool]
        destinations=list(dict.fromkeys(address(server['host'],server['port']) for server in actual_servers))
        server_labels=[];seen=set()
        for pool in actual_pools:
            for i,server in enumerate(pool):
                item=(server.get('name','node'+str(i+1)),address(server['host'],server['port']))
                if item not in seen:server_labels.append(dict(name=item[0],address=item[1]));seen.add(item)
        if model.get('http_action')=='redirect':destinations=[model.get('http_redirect_location') or 'HTTPS того же домена'];connection='HTTP-перенаправление'
        result.append(dict(id=model['id'],name=model['name'],connection=connection,source=source,port=model['port'],destinations=destinations,status=service_status(model,runtime_pool,routes),enabled=model['enabled'],rules=cards,backend_names=pool_names(model),servers=server_labels))
    return result
