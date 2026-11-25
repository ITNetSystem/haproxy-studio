"""Stable, editable HAProxy names. Legacy models keep their names until reviewed migration."""
import copy
import re
import unicodedata

_RU=dict(zip('абвгдеёжзийклмнопрстуфхцчшщъыьэюя',['a','b','v','g','d','e','e','zh','z','i','y','k','l','m','n','o','p','r','s','t','u','f','kh','ts','ch','sh','shch','','y','','e','yu','ya']))

def slug(value):
    value=''.join(_RU.get(c,c) for c in str(value).lower())
    value=unicodedata.normalize('NFKD',value).encode('ascii','ignore').decode()
    return re.sub(r'[^a-z0-9]+','_',value).strip('_') or 'service'

def automatic_backend(value):
    name=slug(value)
    return (name if name.startswith('be_') else 'be_'+name)[:63]

def valid(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,62}',value):raise ValueError('Имя в конфиге: от 1 до 63 латинских букв, цифр, _, точки или дефиса; первый символ — буква.')
    return value

def backend_name(model,route=None):
    if model.get('import_pool'):return model['import_pool']
    if route is not None:
        if route.get('backend_name'):return route['backend_name']
        from .enterprise import route_key
        return 'studio_be_'+model['id']+'_r'+route_key(model,route)
    return model.get('backend_name') or 'studio_be_'+model['id']

def names(model):
    result=[]
    if model.get('import_pool'):return result
    if model.get('http_action')=='redirect':return result
    if not(model.get('fallback_status') and model.get('routes')):result.append(backend_name(model))
    result.extend(backend_name(model,r) for r in model.get('routes',[]) if r['action']=='backend')
    return result

def normalize(data,model):
    if model.get('import_pool'):return model
    mode=data.get('naming','legacy')
    if mode not in ('legacy','readable'):raise ValueError('Неизвестный режим имён в конфиге.')
    if mode=='legacy':return model
    model['naming']='readable';model['backend_name']=valid(data.get('backend_name') or automatic_backend(model['name']))
    def servers(rows,source):
        used=set()
        for i,server in enumerate(rows):
            custom=source[i].get('name') if i<len(source) else None
            name=valid(custom or ('srv_'+slug(server['host'])+'_'+str(server['port']))[:63])
            if not custom:
                root=name;n=2
                while name.lower() in used:name=root[:58]+'_'+str(n);n+=1
            if name.lower() in used:raise ValueError('Имена серверов в одном пуле должны различаться: '+name)
            used.add(name.lower());server['name']=name
    servers(model['backends'],data.get('backends',[]))
    for index,route in enumerate(model.get('routes',[])):
        if route['action']!='backend':continue
        source=data.get('routes',[])[index] if index<len(data.get('routes',[])) else {}
        route['backend_name']=valid(source.get('backend_name') or model['backend_name'][:35]+'__'+slug(route['path'])[:25])
        if route.get('inherit_pool'):route['backends']=copy.deepcopy(model['backends'])
        else:servers(route['backends'],source.get('backends',[]))
    planned=names(model)
    if len({n.lower() for n in planned})!=len(planned):raise ValueError('Имена backend основного пула и маршрутов должны различаться.')
    return model

def references(base,mapping):
    mapping={old:new for old,new in mapping.items() if old!=new}
    if not mapping:return base
    result=[]
    for line in base.splitlines(keepends=True):
        if line.lstrip().startswith('#'):result.append(line);continue
        match=re.match(r'(\s*(?:use_backend|default_backend)\s+)(\S+)(.*)',line)
        if match and '%' in match[2]:raise ValueError('Есть динамический выбор backend. Проверьте map-файлы перед переименованием.')
        if match and match[2] in mapping:
            line=match[1]+mapping[match[2]]+match[3]+('\n' if line.endswith('\n') else '')
        for old in mapping:
            if re.search(r'(?<![\w.-])'+re.escape(old)+r'(?![\w.-])',line):raise ValueError('Ручная ссылка на '+old+' требует проверки перед переименованием.')
        result.append(line)
    return ''.join(result)

def pool_map(model):
    from .enterprise import route_key
    result={}
    if model.get('http_action')=='redirect':return result
    if not(model.get('fallback_status') and model.get('routes')):result['root']=backend_name(model)
    for row in model.get('routes',[]):
        if row['action']=='backend':result[route_key(model,row)]=backend_name(model,row)
    return result

def changes(old,new):
    before=pool_map(old);after=pool_map(new)
    return {name:after[key] for key,name in before.items() if key in after and name!=after[key]}

def migrate(manager,base,models):
    from .services import bindings
    extra=manager.engine.extra
    manual=base+(''.join(p.read_bytes().decode('utf-8','surrogateescape') for p in sorted(extra.glob('*.cfg'))) if extra and extra.is_dir() else '')
    taken={s['name'].lower() for s in bindings(manual) if s['type'] in ('backend','listen')}
    for model in models:
        if model.get('import_pool'):continue
        if model.get('naming')=='readable':taken.update(n.lower() for n in names(model))
    def unique(value):
        root=value[:63];name=root;n=2
        while name.lower() in taken:
            suffix='_'+str(n);name=root[:63-len(suffix)]+suffix;n+=1
        taken.add(name.lower());return name
    converted=[];mapping={}
    for model in models:
        if model.get('import_pool'):converted.append(model);continue
        if model.get('naming')=='readable':converted.append(model);continue
        data=copy.deepcopy(model);data.update(naming='readable',backend_name=unique(automatic_backend(model['name'])),sni_domains=model.get('domains',[]))
        for route in data.get('routes',[]):
            if route['action']=='backend':route['backend_name']=unique(data['backend_name'][:35]+'__'+slug(route['path'])[:25])
        updated=manager.normalize(data,model['id']);mapping.update(changes(model,updated));converted.append(updated)
    if extra and extra.is_dir():
        for file in extra.glob('*.cfg'):
            text=file.read_bytes().decode('utf-8','surrogateescape')
            if references(text,mapping)!=text:raise ValueError('На переименовываемый backend ссылается дополнительный файл '+file.name+'. Сначала перенесите или измените эти ссылки вручную.')
    return references(base,mapping),converted,mapping
