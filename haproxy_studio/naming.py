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
    # Renaming managed ACLs cannot silently invalidate hand-written conditions.
    from .services import BLOCK,decode
    original=decode(manager.engine.snapshot()[0])
    renaming_ids={m['id'] for m in models if not m.get('acl_prefix')}
    old_acls={name for b in BLOCK.finditer(original) if b[1] in renaming_ids for name in re.findall(r'(?m)^\s*acl\s+(\S+)',b[4])}
    for name in old_acls:
        if re.search(r'(?<![\w.-])'+re.escape(name)+r'(?![\w.-])',manual):raise ValueError('На управляемый ACL '+name+' ссылается ручное правило. Сначала согласуйте его переименование.')
    taken_acl=set(re.findall(r'(?m)^\s*acl\s+(\S+)',manual))|{m['acl_prefix'] for m in converted if m.get('acl_prefix')}
    for index,(before,updated) in enumerate(zip(models,converted)):
        if not updated.get('acl_prefix'):
            updated=dict(updated,acl_prefix=allocate_acl(updated,taken_acl));converted[index]=updated
            mapping[acl_base(before)]=updated['acl_prefix']
    return references(base,mapping),converted,mapping


def acl_base(model):
    return model.get('acl_prefix') or 'st_'+model['id']


def normalize_acl(data,model):
    value=data.get('acl_prefix')
    if value:
        if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,39}',value):raise ValueError('Префикс ACL: до 40 латинских букв, цифр и _, начиная с буквы.')
        model['acl_prefix']=value
    return model


def allocate_acl(model,taken):
    root=('acl_'+slug(backend_name(model).removeprefix('be_') if model.get('import_pool') or model.get('backend_name') else model['name']))[:40]
    candidate=root;n=2
    while any(v.lower()==candidate.lower() or v.lower().startswith(candidate.lower()+'_') for v in taken):
        suffix='_'+str(n);candidate=root[:40-len(suffix)]+suffix;n+=1
    taken.add(candidate);return candidate


def route_acl(model,row):
    from .enterprise import route_key
    if not model.get('acl_prefix'):return acl_base(model)+'_r'+route_key(model,row)
    # Prefix/path modes of a route keep their semantics; only its ACL label changes.
    part=slug(row['path'])[:28]
    peers=[r for r in model.get('routes',[]) if slug(r['path'])[:28]==part]
    suffix='_rule_'+str(next(i for i,r in enumerate(peers) if r['path']==row['path'])+1) if len(peers)>1 else ''
    return acl_base(model)+'_path_'+part+suffix


def imported_acl(model,slot,term=None,path_name=None):
    if not model.get('acl_prefix'):
        return acl_base(model)+'_slot'+str(slot)+('_path'+str(path_name) if term is None else '_term'+str(term))
    root=acl_base(model)+('' if slot==0 else '_rule_'+str(slot+1))
    return root+('_path_'+str(path_name+1) if term is None else '_host'+('' if term==0 else '_'+str(term+1)))
