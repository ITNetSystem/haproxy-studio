"""A unified editor for retained Exchange routes; no lossy template conversion."""
import copy
import hashlib
import json
import re
from .core import Conflict,mask
from .services import clean,bindings,ServiceManager
from .service_types import annotate

SERVICES=r'owa|autodiscover|mapi|activesync|ews|rpc|ecp|oab'

def identity(model):
    pool=model.get('import_pool','')
    match=re.fullmatch(r'be_exchange_(.+)_('+SERVICES+r')',pool,re.I)
    if match:return match[1].lower(),match[2].lower()
    match=re.fullmatch(r'exch_('+SERVICES+r')_(.+)',pool,re.I)
    if match:return match[2].lower(),match[1].lower()
    return None,None

def groups(models,base,settings):
    annotate(models,base,settings);buckets={}
    pools={s['name']:s for s in bindings(base) if s['type']=='backend'}
    for model in models:
        if not model.get('import_pool') or model.get('classification',{}).get('id')!='exchange':continue
        tenant,role=identity(model)
        if not role:
            text=''.join(line for _,line in pools.get(model['import_pool'],{}).get('lines',[]))
            match=re.search(r'/(owa|autodiscover|mapi|microsoft-server-activesync|ews|rpc|ecp|oab)/healthcheck\.htm',text,re.I)
            if match:role='activesync' if match[1].lower()=='microsoft-server-activesync' else match[1].lower()
        if tenant:
            family=('name',tenant)
        else:
            # Without a recognized family, use exact domain + server identity only.
            from .acl_import import pool_servers
            try:servers=pool_servers(pools[model['import_pool']])
            except (ValueError,KeyError):continue
            family=('exact',tuple(sorted(model.get('domains',[]))),tuple(sorted((b['host'],int(b['port'])) for b in servers)))
        acl=model['import_acl'];key=(acl['frontend'],acl['listener_port'],acl['listener_address'],model['tls_mode'],family)
        buckets.setdefault(key,[]).append((model,role))
    result=[]
    for key,entries in buckets.items():
        if len(entries)<2:continue
        # A repeated role may be a second publication, not one Exchange farm.
        roles=[r for _,r in entries if r]
        if len(roles)!=len(set(roles)):continue
        domains=set.intersection(*(set(m.get('domains',[])) for m,_ in entries))
        if not domains and key[4][0]!='name':continue
        ordered=sorted(entries,key=lambda pair:((SERVICES.split('|').index(pair[1]) if pair[1] in SERVICES.split('|') else 99),pair[0]['id']))
        ids=[m['id'] for m,_ in ordered];tenant=identity(entries[0][0])[0]
        result.append(dict(id='exchange-'+hashlib.sha256('\0'.join(sorted(ids)).encode()).hexdigest()[:16],name='Exchange — '+(tenant.upper() if tenant else sorted(domains)[0]),members=ids,roles={m['id']:role or m['name'] for m,role in ordered},domains=sorted({d for m,_ in entries for d in m.get('domains',[])}),tls_mode=key[3],frontend=key[0],port=entries[0][0]['port'],enabled=all(m['enabled'] for m,_ in entries),mixed_enabled=len({m['enabled'] for m,_ in entries})>1))
    from .exchange_mail import attach
    return attach(result,models)

class DraftEngine:
    def __init__(self,parent,raw):self.parent=parent;self.raw=raw
    def __getattr__(self,name):return getattr(self.parent,name)
    def snapshot(self):return self.raw,hashlib.sha256(self.raw).hexdigest()

def preview(manager,value):
    engine=manager.engine
    if engine.settings['read_only']:raise ValueError('Изменения отключены.')
    original,revision=engine.snapshot()
    if value.get('revision')!=revision:raise Conflict('Конфигурация изменилась. Обновите список Exchange.')
    base,models=clean(original);available=groups(models,base,engine.settings);group=next((g for g in available if g['id']==value.get('id')),None)
    if not group:raise ValueError('Группа Exchange изменилась. Обновите список сервисов.')
    action=value.get('action','upsert')
    if action not in ('upsert','enable','disable','delete'):raise ValueError('Неизвестное действие Exchange.')
    submitted=value.get('services',[])
    if action=='upsert':
        if not isinstance(submitted,list) or any(not isinstance(m,dict) or not isinstance(m.get('id'),str) for m in submitted) or len(submitted)!=len(group['members']) or {m.get('id') for m in submitted}!=set(group['members']):raise ValueError('Состав служб Exchange изменился. Передайте все службы группы без повторов.')
        patches={m['id']:copy.deepcopy(m) for m in submitted}
    else:patches={m['id']:dict(m,enabled=action=='enable') for m in models if m['id'] in group['members']}
    # Reject contradictory edits to one shared pool before preparing any change.
    edits={}
    for m in patches.values():
        old=next(x for x in models if x['id']==m['id']);pool=old['import_pool'];change=m.get('import_changes')
        if change:
            signature=json.dumps(change,sort_keys=True,ensure_ascii=True)
            if pool in edits and edits[pool]!=signature:raise ValueError('Разные настройки одного общего backend '+pool+'. Задайте одинаковые параметры.')
            edits[pool]=signature
    from .acl_import import pool_servers
    original_pools={s['name']:s for s in bindings(base) if s['type']=='backend'}
    for m in patches.values():
        old=next(x for x in models if x['id']==m['id'])
        if action=='upsert' and 'backends' in m and m['backends']!=pool_servers(original_pools[old['import_pool']]):raise ValueError('Меняйте серверы через параметры общего backend.')
    draft_engine=DraftEngine(engine,original);child=ServiceManager(draft_engine);notes=[];summary=[]
    for identifier in group['members']:
        m=patches[identifier]
        if action!='delete':
            current_base,_=clean(draft_engine.raw);pool=next(s for s in bindings(current_base) if s['type']=='backend' and s['name']==next(x for x in models if x['id']==identifier)['import_pool']);m['backends']=pool_servers(pool)
        checked,draft=child.preview(m,draft_engine.snapshot()[1],'delete' if action=='delete' else 'upsert',probe=False)
        if not checked['ok']:raise ValueError(checked['output'])
        draft_engine.raw=draft['raw'];notes+=checked.get('warnings',[]);summary+=checked.get('summary',[])
    if engine.snapshot()[1]!=revision:raise Conflict('Конфигурация изменилась во время проверки Exchange.')
    import difflib
    raw=draft_engine.raw;checked=engine.validate(raw)
    checked.update(changed=raw!=original,summary=[('Удалить' if action=='delete' else 'Изменить')+' '+group['name']+': служб '+str(len(group['members']))+'. Все изменения применяются одним файлом и одним reload.']+summary,warnings=list(dict.fromkeys(notes)),diff=''.join(difflib.unified_diff(mask(original)[0].splitlines(True),mask(raw)[0].splitlines(True),fromfile='Текущая конфигурация',tofile=group['name'])))
    return checked,dict(raw=raw,revision=revision,reason='service:exchange-group')
