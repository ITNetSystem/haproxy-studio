"""Readable runtime identities and service health across independent route pools."""
from .naming import backend_name
def identities(models):
    result={}
    for model in models:
        result[backend_name(model)]=(model['name'],'')
        for route in model.get('routes',[]):
            if route['action']=='backend':result[backend_name(model,route)]=(model['name'],route['path'])
    shared={}
    for model in models:
        if model.get('import_pool'):shared.setdefault(model['import_pool'],[]).append(model['name'])
    for name,labels in shared.items():result[name]=(' / '.join(dict.fromkeys(labels)),'')
    return result

def annotate(rows,sections,models):
    labels=identities(models)
    readable={section['name']:section['display_name'] for section in sections if section.get('display_name') and section['display_name']!=section['name']}
    servers={(section['name'],server['name']):server['address'] for section in sections for server in section.get('servers',[])}
    for row in rows:
        key=(row['pxname'],row['svname'])
        name,path=labels.get(row['pxname'],(readable.get(row['pxname'],row['svname']),''))
        row.update(display_name=name,server_address=servers.get(key,''),route_path=path)
    return rows

def pool_status(rows):
    if not rows:return 'Ожидание данных'
    if any(row['status']=='UP' for row in rows):return 'Сервер доступен'
    if any(row['status'].lower()=='no check' for row in rows):return 'Проверки выключены'
    return 'Сервер недоступен'

def service_status(model,rows,routes):
    if not model['enabled']:return 'Выключен'
    if model.get('http_action')=='redirect':return 'Перенаправление настроено'
    pools=[route['rows'] for route in routes if route['action']=='backend']
    if not (model.get('fallback_status') and model.get('routes')):pools.insert(0,rows)
    if not pools:return 'Маршруты настроены'
    if model['health']=='none' and not model.get('import_pool') and not any(route['action']=='backend' for route in routes):return 'Проверки выключены'
    states=[pool_status(pool) for pool in pools]
    if all(state=='Сервер доступен' for state in states):return 'Сервер доступен'
    if any(state=='Сервер доступен' for state in states):return 'Частично доступен'
    if 'Ожидание данных' in states:return 'Ожидание данных'
    if all(state=='Проверки выключены' for state in states):return 'Проверки выключены'
    return 'Сервер недоступен'

def overview_servers(rows,sections,models,base,settings):
    """One destination per service, preserving every path/server runtime row."""
    import math
    from .exchange_groups import groups
    from .services import bindings
    farms=groups(models,base,settings);member_group={i:g for g in farms for i in g['members']}
    paths={}
    for section in bindings(base):
        for _,line in section['lines']:
            parts=line.partition('#')[0].split()
            if len(parts)>3 and parts[0]=='acl' and parts[2] in ('path','path_beg','path_end'):
                values=[p for p in parts[3:] if p.startswith('/')]
                if values:paths[(section['name'],parts[1])]=values
    owners={}
    for m in models:
        group=member_group.get(m['id']);owner=group['id'] if group else m['id'];name=group['name'] if group else m['name']
        actual=[]
        for slot in m.get('import_acl',{}).get('slots',[]):
            for term in slot['terms']:
                for test in term['tests']:
                    actual+=[('кроме ' if test.startswith('!') else '')+p for p in m.get('import_paths',{}).get(test.lstrip('!'),paths.get((m['import_acl']['frontend'],test.lstrip('!')),[]))]
        label=', '.join(dict.fromkeys(actual)) or (group['roles'].get(m['id'],'') if group else '')
        owners.setdefault(backend_name(m),[]).append((owner,name,label))
        for r in m.get('routes',[]):
            if r['action']=='backend':owners.setdefault(backend_name(m,r),[]).append((owner,name,r['path']))
    buckets={}
    observed={(r['pxname'],r['svname']) for r in rows}
    expanded=list(rows)
    if rows:
        for section in sections:
            if section['name'] not in owners:continue
            for server in section.get('servers',[]):
                if (section['name'],server['name']) not in observed:expanded.append(dict(pxname=section['name'],svname=server['name'],server_address=server['address'],status='Нет данных',scur='',check_status=''))
    for row in expanded:
        if row['svname'] in ('FRONTEND','BACKEND'):continue
        choices=owners.get(row['pxname'],[]);ids={v[0] for v in choices}
        owner=next(iter(ids)) if len(ids)==1 else 'backend:'+row['pxname']
        name=choices[0][1] if len(ids)==1 else row.get('display_name',row['svname'])
        address=row.get('server_address','');key=(owner,address or (row['pxname'],row['svname']))
        entry=buckets.setdefault(key,dict(name=name,address=address,checks=[],scur='',status=''))
        labels=list(dict.fromkeys(v[2] for v in choices if v[2]))
        detail=dict(row);detail['path']=row.get('route_path') or ', '.join(labels) or 'Основной пул'
        entry['checks'].append(detail)
    for entry in buckets.values():
        checks=entry['checks'];states={str(r.get('status') or '') for r in checks}
        healthy=any(s in ('UP','OPEN') for s in states)
        if len(states)==1:entry['status']=next(iter(states))
        elif states<= {'UP','OPEN'}:entry['status']='UP'
        elif healthy and any(s in ('','Нет данных') for s in states):entry['status']='Неполные данные'
        elif healthy:entry['status']='Часть проверок выключена' if all(s in ('UP','OPEN','no check') for s in states) else 'Частично доступен'
        elif all(s.startswith('DOWN') or s=='MAINT' for s in states):entry['status']='DOWN'
        else:entry['status']='Разные состояния'
        values=[]
        for row in checks:
            try:value=float(row.get('scur',''))
            except (TypeError,ValueError):continue
            if math.isfinite(value) and value>=0:values.append(value)
        entry['scur']=sum(values) if values else ''
        entry['partial_connections']=len(values)!=len(checks)
        entry['check_status']=checks[0].get('check_status','') if len(checks)==1 else str(len(checks))+' проверок'
    return list(buckets.values())
