"""Compound Exchange publication: independent listeners, one reviewed transaction."""
import copy
import difflib
from .core import Conflict,mask
from .services import clean,ServiceManager

def mail_protocol(model):
    value=model.get('classification',{}).get('id')
    return value if value in ('imaps','smtps') else model['protocol']

def attach(result,models):
    for m in models:
        if m['protocol']=='exchange' and not m.get('import_pool'):
            result.append(dict(id='exchange-'+m['id'],name=m['name'],members=[m['id']],roles={m['id']:'HTTPS'},domains=m['domains'],tls_mode=m['tls_mode'],frontend='',port=m['port'],enabled=m['enabled'],mixed_enabled=False,native=m['id']))
    for g in result:g['web_members']=list(g['members'])
    for m in models:
        if mail_protocol(m) not in ('imaps','smtps'):continue
        choices=[g for g in result if m.get('exchange_parent') in g['web_members']] if m.get('exchange_parent') else [g for g in result if set(m.get('domains',[]))&set(g['domains'])]
        if len(choices)!=1:continue
        g=choices[0];g['members'].append(m['id']);g['roles'][m['id']]=mail_protocol(m).upper()
    by_id={m['id']:m for m in models}
    for g in result:
        states={by_id[i]['enabled'] for i in g['members']};g['enabled']=all(states);g['mixed_enabled']=len(states)>1
    return result

def preview(manager,value,revision,action='upsert'):
    from .exchange_groups import DraftEngine,groups
    engine=manager.engine;raw,actual=engine.snapshot()
    if revision!=actual:raise Conflict('Конфигурация изменилась. Обновите сервисы.')
    base,models=clean(raw);group=next((g for g in groups(models,base,engine.settings) if g.get('native')==value.get('id')),None)
    child=ServiceManager(DraftEngine(engine,raw));submitted=copy.deepcopy(value);mail=submitted.pop('exchange_mail',None)
    checked,draft=child.preview(submitted,child.engine.snapshot()[1],action,probe=False)
    if not checked['ok']:return checked,draft
    child.engine.raw=draft['raw'];_,after=clean(draft['raw']);parent=value.get('id') or next(m['id'] for m in after if m['id'] not in {x['id'] for x in models})
    old={m['id']:m for m in models if group and m['id'] in group['members'] and mail_protocol(m) in ('imaps','smtps')}
    if mail is None:mail=[dict(m,enabled=value.get('enabled',m['enabled'])) for m in old.values()]
    if not isinstance(mail,list) or len(mail)>16:raise ValueError('Некорректный список почтовых служб Exchange.')
    seen=set()
    for row in mail:
        if not isinstance(row,dict) or mail_protocol(row) not in ('imaps','smtps'):raise ValueError('Поддерживаются IMAPS и SMTPS.')
        if row.get('id') and (row['id'] not in old or row['id'] in seen):raise ValueError('Почтовая служба не принадлежит этому Exchange или повторяется.')
        if row.get('id'):seen.add(row['id'])
        row=dict(row,exchange_parent=parent)
        row.setdefault('sni_domains',row.get('domains',[]))
        checked,draft=child.preview(row,child.engine.snapshot()[1],'delete' if action=='delete' else 'upsert',probe=False)
        if not checked['ok']:raise ValueError(checked['output'])
        child.engine.raw=draft['raw']
    # Omission never silently removes existing listeners.
    if action!='delete' and set(old)-seen:raise ValueError('Передайте все существующие почтовые службы; для отключения снимите флажок службы.')
    candidate=child.engine.raw;checked=engine.validate(candidate)
    checked.update(changed=candidate!=raw,diff=''.join(difflib.unified_diff(mask(raw)[0].splitlines(True),mask(candidate)[0].splitlines(True),fromfile='До',tofile='Exchange: HTTPS и почта')),summary=['Exchange и почтовые службы применяются одной операцией.'],warnings=['IMAPS/SMTPS должны быть включены на Exchange. На общем порту клиент должен передавать SNI; fallback выбирается явно.'])
    return checked,dict(raw=candidate,revision=actual,reason='service:exchange-mail')
