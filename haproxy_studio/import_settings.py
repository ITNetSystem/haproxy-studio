"""Edit representable settings of retained pools without recompiling their policies."""
import re
from .services import bindings, hostname, number, address

SCALARS={'balance':r'balance', 'timeout_server':r'timeout\s+server',
         'health_request':r'option\s+httpchk', 'health_status':r'http-check\s+expect'}
SERVER_VALUES={'weight':(1,256),'maxconn':(0,100000),'inter':None,'rise':(1,100),'fall':(1,100)}
FLAGS={'backup','check','ssl'}
TIME=re.compile(r'(?:0|[1-9][0-9]{0,8})(?:us|ms|s|m|h|d)?\Z')

def section(base,name):
    lines=base.splitlines(True);matches=[s for s in bindings(base) if s['type']=='backend' and s['name']==name]
    if len(matches)!=1:raise ValueError('Общий backend не найден или его имя неоднозначно.')
    item=matches[0];start=item['start'];end=next((s['start'] for s in bindings(base) if s['start']>start),len(lines))
    return lines,start,end

def inspect(base,model,models=()):
    lines,start,end=section(base,model['import_pool']);body=lines[start+1:end];values={};blocked={}
    for key,pattern in SCALARS.items():
        found=[re.match(r'^\s*'+pattern+r'\s+([^#\n]*?)(?:\s*#.*)?\n?$',line) for line in body]
        found=[m[1].strip() for m in found if m]
        values[key]=found[0] if len(found)==1 else ''
        if len(found)>1:blocked[key]='Несколько директив: требуется редактор конфигурации.'
    if values['balance'] and values['balance'] not in ('roundrobin','leastconn','source','first','random'):
        blocked['balance']='Алгоритм с дополнительными аргументами сохраняется без изменений.'
    for key in ('timeout_server',):
        if values[key] and not TIME.fullmatch(values[key]):blocked[key]='Выражение таймаута сохраняется без изменений.'
    request=values.pop('health_request');values['health_method']='';values['health_path']=''
    if request:
        parts=request.split()
        if len(parts)==2 and parts[0] in ('GET','HEAD','OPTIONS') and re.fullmatch(r'/[^\s#\\]*',parts[1]):values.update(health_method=parts[0],health_path=parts[1])
        else:blocked['health_path']='Сложный HTTP-запрос проверки сохраняется без изменений.'
    if any(re.match(r'\s*http-check\s+(?:send|connect|set-var|unset-var)\b',l) for l in body):blocked['health_path']='Многошаговая HTTP-проверка сохраняется без изменений.'
    status=values['health_status']
    if status:
        match=re.fullmatch(r'status ([1-5][0-9]{2})',status)
        if match:values['health_status']=match[1]
        else:blocked['health_status']='Сложное условие проверки сохраняется без изменений.'
    servers=[]
    for line in body:
        match=re.match(r'^\s*server\s+(\S+)\s+(\S+)(.*)$',line.rstrip('\n'))
        if not match:continue
        from .importer import endpoint
        host,port=endpoint(match[2]);tail=match[3];row=dict(name=match[1],host=host,port=str(port))
        # Quoted/escaped option values cannot be safely token-patched.
        if any(c in tail for c in ('"',"'",'\\')):row['blocked']='Сложные параметры сервера: используйте редактор общего пула.'
        words=tail.partition('#')[0].split()
        arity={key:1 for key in SERVER_VALUES}
        arity.update({key:0 for key in FLAGS})
        arity.update({key:1 for key in ('verify','sni','ca-file','crt','verifyhost','alpn','proto','cookie','id','maxqueue','slowstart','port','addr','check-port','check-addr','check-sni','check-alpn','check-proto','agent-port','agent-addr','agent-inter','resolvers','resolve-prefer','init-addr','on-marked-down','on-marked-up','ssl-min-ver','ssl-max-ver','ciphers','ciphersuites','fastinter','downinter','observe','error-limit','on-error')})
        arity.update({key:0 for key in ('send-proxy','send-proxy-v2','check-send-proxy','check-ssl','disabled','enabled','agent-check','no-check','no-ssl','no-backup','no-agent-check','ssl-reuse','no-ssl-reuse')})
        cursor=0;seen=set()
        while cursor<len(words):
            key=words[cursor]
            if key not in arity or key in seen or cursor+arity[key]>=len(words) or any(v in FLAGS|set(SERVER_VALUES)|{'verify'} for v in words[cursor+1:cursor+1+arity[key]]):
                row['blocked']='Сложные или неоднозначные параметры сервера сохраняются без изменений.';break
            seen.add(key);cursor+=1+arity[key]

        for key in SERVER_VALUES:
            row[key]=words[words.index(key)+1] if words.count(key)==1 and words.index(key)+1<len(words) else ''
            if words.count(key)>1:row['blocked']='Повторяющиеся параметры сервера.'
        for key in FLAGS:row[key]=key in words
        row['verify']=words[words.index('verify')+1] if words.count('verify')==1 and words.index('verify')+1<len(words) else ''
        if row['verify'] not in ('','none','required'):row['blocked']='Нестандартная проверка TLS сервера.'
        servers.append(row)
    values['servers']=servers
    values['blocked']=blocked
    values['affected']=[m['name'] for m in models if m.get('import_pool')==model['import_pool']]
    values['backend']=model['import_pool']
    front=next((s for s in bindings(base) if s['type']=='frontend' and s['name']==model['import_acl']['frontend']),None) if model.get('import_acl') else None
    used={t.lstrip('!') for slot in model.get('import_acl',{}).get('slots',[]) for term in slot['terms'] for t in term['tests']}
    definitions={}
    for _,line in (front or {}).get('lines',[]):
        parts=line.partition('#')[0].split()
        if len(parts)>=4 and parts[0]=='acl' and parts[1] in used:definitions.setdefault(parts[1],[]).append(parts)
    values['paths']=[]
    for name,defs in definitions.items():
        if len(defs)!=1:continue
        parts=defs[0];args=parts[3:];ignore=bool(args and args[0]=='-i')
        if ignore:args=args[1:]
        if parts[2] in ('path','path_beg','path_end') and args and all(re.fullmatch(r'/[A-Za-z0-9/_~.\-?=&%]*',v) for v in args):
            values['paths'].append(dict(name=name,match=parts[2],ignore_case=ignore,values=model.get('import_paths',{}).get(name,args),original=args))

    return values

def duration(value):
    if not isinstance(value,str) or not TIME.fullmatch(value):raise ValueError('Таймаут/интервал: число с единицей ms, s, m, h или d. Без единицы — миллисекунды.')
    return value

def patch(base,model,changes,models=()):
    if not isinstance(changes,dict) or set(changes)-{'balance','timeout_server','health_method','health_path','health_status','servers','confirm'}:raise ValueError('Неизвестные настройки импортированного пула.')
    current=inspect(base,model,models)
    if changes.get('confirm') is not True:raise ValueError('Подтвердите изменение общего backend для всех его публикаций.')
    lines,start,end=section(base,model['import_pool']);body=lines[start+1:end]
    def scalar(key,value):
        pattern=SCALARS[key];found=[i for i,line in enumerate(body) if re.match(r'^\s*'+pattern+r'(?:\s|$)',line)]
        if len(found)>1:raise ValueError('Директива неоднозначна. Используйте редактор конфигурации.')
        if found:
            i=found[0];line=body[i];comment=(' #'+line.partition('#')[2].rstrip('\n')) if '#' in line else ''
            body[i]=('    '+re.sub(r'\\s\+', ' ', pattern)+' '+value+comment+'\n') if value else (comment.lstrip()+'\n' if comment else '')
        elif value:body.append('    '+re.sub(r'\\s\+', ' ', pattern)+' '+value+'\n')
    for key in ('balance','timeout_server','health_status'):
        if key not in changes or str(changes[key])==current[key]:continue
        if key in current['blocked']:raise ValueError(current['blocked'][key])
        value=changes[key]
        if not isinstance(value,str):raise ValueError('Настройка должна быть строкой.')
        if key=='balance' and value not in ('','roundrobin','leastconn','source','first','random'):raise ValueError('Выберите алгоритм балансировки.')
        if key=='timeout_server' and value:duration(value)
        if key=='health_status' and value:
            if not re.fullmatch('[1-5][0-9]{2}',value):raise ValueError('Ожидается HTTP-код от 100 до 599.')
            value='status '+value
        scalar(key,value)
    if any(k in changes and changes[k]!=current[k] for k in ('health_method','health_path')):
        if 'health_path' in current['blocked'] or 'health_request' in current['blocked']:raise ValueError(current['blocked'].get('health_path',current['blocked'].get('health_request')))
        method=changes.get('health_method',current['health_method']);path=changes.get('health_path',current['health_path'])
        if method not in ('GET','HEAD','OPTIONS') or not isinstance(path,str) or not re.fullmatch(r'/[^\s#\\]*',path):raise ValueError('Выберите метод и путь HTTP-проверки, начиная с /.')
        scalar('health_request',method+' '+path)
    if 'servers' in changes:
        rows=changes['servers']
        if not isinstance(rows,list) or len(rows)!=len(current['servers']):raise ValueError('Имена, число и порядок серверов должны сохраняться.')
        indices=[i for i,line in enumerate(body) if re.match(r'^\s*server\s',line)]
        for i,old,row in zip(indices,current['servers'],rows):
            allowed={'name','host','port','verify'}|set(SERVER_VALUES)|FLAGS
            if not isinstance(row,dict) or set(row)-allowed or row.get('name')!=old['name']:raise ValueError('Неизвестный сервер или параметр.')
            if all(str(row.get(k,old.get(k)))==str(old.get(k)) for k in row):continue
            if old.get('blocked'):raise ValueError(old['blocked'])
            line=body[i];match=re.match(r'^(\s*server\s+\S+\s+)(\S+)([^\n]*)(\n?)$',line)
            tail,sep,comment=match[3].partition('#')
            def option(key,value,is_flag=False):
                nonlocal tail
                found=list(re.finditer(r'(?<!\S)'+key+r'(?!\S)'+('' if is_flag else r'\s+\S+'),tail))
                if len(found)>1:raise ValueError('Повторяющийся параметр сервера.')
                replacement=(key if is_flag else key+' '+str(value)) if value!='' and value is not False else ''
                if found:
                    m=found[0];tail=tail[:m.start()]+replacement+tail[m.end():]
                elif replacement:tail=tail.rstrip()+' '+replacement+' '
            for key,bounds in SERVER_VALUES.items():
                if key not in row or str(row[key])==old[key]:continue
                value=row[key]
                if not isinstance(value,str):raise ValueError('Параметры сервера должны быть строками.')
                if value:value=str(number(value,key,*bounds)) if bounds else duration(value)
                option(key,value)
            for key in FLAGS:
                if key in row:
                    if not isinstance(row[key],bool):raise ValueError('Ожидается переключатель '+key+'.')
                    if row[key]!=old[key]:option(key,row[key],True)
            if 'verify' in row and row['verify']!=old['verify']:
                if row['verify'] not in ('','none','required'):raise ValueError('Выберите режим проверки TLS.')
                option('verify',row['verify'])
            target=address(hostname(row.get('host',old['host'])),number(row.get('port',old['port']),'Порт сервера'))
            body[i]=match[1]+target+tail+(sep+comment if sep else '')+match[4]
    # Separate appended directives from the next section even if the old file lacked a newline.
    body=[line if not line or line.endswith('\n') else line+'\n' for line in body]
    return ''.join(lines[:start+1]+body+lines[end:]),current['affected']
