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
