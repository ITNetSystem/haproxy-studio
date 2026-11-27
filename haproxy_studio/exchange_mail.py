"""Compound Exchange publication: independent listeners, one reviewed transaction."""
import copy
import difflib
from .core import Conflict,mask
from .services import clean,ServiceManager

def mail_protocol(model):
    value=model.get('classification',{}).get('id')
    return value if value in ('imaps','smtps','imap','submission') else model['protocol']

def choose_group(groups,domains,hosts,addresses):
    domain_matches=[g for g in groups if set(domains)&set(g['domains'])]
    address_matches=[g for g in groups if hosts and any(hosts<=addresses.get(i,set()) for i in g['web_members'])]
    if domain_matches and address_matches:
        matches=[g for g in domain_matches if g in address_matches]
    else:matches=domain_matches or address_matches
    return matches[0] if len(matches)==1 else None

def attach(result,models,pool_addresses=None):
    for m in models:
        if m['protocol']=='exchange' and not m.get('import_pool'):
            result.append(dict(id='exchange-'+m['id'],name=m['name'],members=[m['id']],roles={m['id']:'HTTPS'},domains=m['domains'],tls_mode=m['tls_mode'],frontend='',port=m['port'],enabled=m['enabled'],mixed_enabled=False,native=m['id']))
    for g in result:g['web_members']=list(g['members'])
    by_id={m['id']:m for m in models}
    addresses={i:(pool_addresses or {}).get(row.get('import_pool'),{b['host'] for b in row['backends']}) for i,row in by_id.items()}
    for m in models:
        if mail_protocol(m) not in ('imaps','smtps','imap','submission'):continue
        if m.get('exchange_parent'):
            choices=[g for g in result if m['exchange_parent'] in g['web_members']]
            g=choices[0] if len(choices)==1 else None
        else:g=choose_group(result,m.get('domains',[]),{b['host'] for b in m['backends']},addresses)
        if not g:continue
        g['members'].append(m['id']);g['roles'][m['id']]=mail_protocol(m).upper()
    by_id={m['id']:m for m in models}
    for g in result:
        states={by_id[i]['enabled'] for i in g['members']};g['enabled']=all(states);g['mixed_enabled']=len(states)>1
    return result

def preview(manager,value,revision,action='upsert'):
    from .exchange_groups import DraftEngine,groups
    if not isinstance(value,dict) or action not in ('upsert','delete'):raise ValueError('Некорректное действие Exchange.')
    engine=manager.engine;raw,actual=engine.snapshot()
    if revision!=actual:raise Conflict('Конфигурация изменилась. Обновите сервисы.')
    base,models=clean(raw);group=next((g for g in groups(models,base,engine.settings) if g.get('native')==value['id']),None) if value.get('id') else None
    child=ServiceManager(DraftEngine(engine,raw));submitted=copy.deepcopy(value);mail=submitted.pop('exchange_mail',None)
    checked,draft=child.preview(submitted,child.engine.snapshot()[1],action,probe=False)
    if not checked['ok']:return checked,draft
    child.engine.raw=draft['raw'];_,after=clean(draft['raw']);parent=value.get('id') or next(m['id'] for m in after if m['id'] not in {x['id'] for x in models})
    old={m['id']:m for m in models if group and m['id'] in group['members'] and mail_protocol(m) in ('imaps','smtps','imap','submission')}
    if mail is None or action=='delete':mail=[dict(m,enabled=value.get('enabled',m['enabled'])) for m in old.values()]
    if not isinstance(mail,list) or len(mail)>16:raise ValueError('Некорректный список почтовых служб Exchange.')
    seen=set()
    for row in mail:
        if not isinstance(row,dict):raise ValueError('Некорректная почтовая служба Exchange.')
        previous=old.get(row.get('id'))
        kind=mail_protocol(previous) if previous else row.get('protocol')
        if kind not in ('imaps','smtps','imap','submission'):raise ValueError('Поддерживаются IMAPS, SMTPS, IMAP и SMTP Submission.')
        if previous and row.get('protocol')!=previous['protocol']:raise ValueError('Нельзя незаметно менять протокол существующей почтовой службы.')
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
    checked.update(changed=candidate!=raw,diff=''.join(difflib.unified_diff(mask(raw)[0].splitlines(True),mask(candidate)[0].splitlines(True),fromfile='До',tofile='Exchange: HTTPS и почта')),summary=['Exchange и почтовые службы применяются одной операцией.'],warnings=['Почтовые службы должны быть включены на Exchange. SNI применим к IMAPS/SMTPS; IMAP 143 и SMTP Submission 587 передаются с STARTTLS без расшифровки. Для разных организаций на 143/587 нужны отдельные IP/порты либо общий почтовый пул.'])
    return checked,dict(raw=candidate,revision=actual,reason='service:exchange-mail')

def attach_inventory(groups,items,models):
    """Keep legacy rules visible inside Exchange, without claiming their adoption."""
    by_id={m['id']:m for m in models}
    for group in groups:group['retained_mail']=[]
    for item in items:
        if item.get('classification',{}).get('id') not in ('smtp','submission','imap','imaps','smtps'):continue
        item.pop('exchange_group',None)
        group=choose_group(groups,item.get('domains',[]),{s['address'].rsplit(':',1)[0].strip('[]') for s in item['servers']},{i:{b['host'] for b in row['backends']} for i,row in by_id.items()})
        if group:item['exchange_group']=group['id'];group['retained_mail'].append(item)
    return items
