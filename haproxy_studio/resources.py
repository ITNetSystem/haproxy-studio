"""Dependency-aware maintenance for certificates and manually configured pools."""
import difflib
import hashlib
import json
import re
import secrets
import shlex
import shutil
from pathlib import Path
from .core import Conflict, decode, encode, mask
from .services import BLOCK, HEADER, clean

class Resources:
    def __init__(self, engine):
        self.engine = engine

    def sources(self):
        return {p: decode(p.read_bytes()) for p in self.engine.config_files()}

    def certificates(self, readonly=False):
        result = self.engine.certificates()
        from .certificate_info import overlap
        for cert in result['certificates']:
            cert['overlaps']=[dict(name=other['name'],key_algorithm=other['key_algorithm'],expired=other['expired'],same_key_type=cert['key_algorithm']==other['key_algorithm']) for other in result['certificates'] if other['name']!=cert['name'] and any(overlap(a,b) for a in cert['domains'] for b in other['domains'])]
            cert['used_by'] = self.certificate_references(cert['name'])
        result['revision']=self.engine.snapshot()[1]
        result['read_only'] = readonly or self.engine.settings['read_only']
        return result

    def certificate_references(self, name):
        target = Path(self.engine.settings['certificate_dir']) / name
        target = target.resolve()
        references = []
        sources = self.sources()
        crt_base = '/etc/ssl/private'
        ca_base = '/etc/ssl/certs'
        for source in sources.values():
            for line in source.splitlines():
                parts = line.strip().split()
                if len(parts)>1 and parts[0]=='crt-base': crt_base=parts[1]
                if len(parts)>1 and parts[0]=='ca-base': ca_base=parts[1]
        def matches(value, base):
            file = Path(value)
            if not file.is_absolute(): file=Path(base)/file
            resolved=file.resolve()
            return resolved==target or (file.is_dir() and resolved in target.parents)
        for file, source in sources.items():
            section = 'global'
            for number, line in enumerate(source.splitlines(),1):
                header=HEADER.match(line.lstrip())
                if header: section=header[2] or header[1]
                try: parts=shlex.split(line,comments=True)
                except ValueError:
                    references.append(dict(source=file.name,section=section,line=number,reason='Не удалось разобрать строку; проверьте вручную.'));continue
                for index, token in enumerate(parts[:-1]):
                    value=parts[index+1]
                    if token in ('crt','ca-file','ca-verify-file','crl-file','ssl-dh-param-file') and matches(value,crt_base if token in ('crt','ssl-dh-param-file') else ca_base):
                        references.append(dict(source=file.name,section=section,line=number))
                    if token=='crt-list':
                        path=Path(value)
                        if not path.is_absolute():path=Path(crt_base)/path
                        try:
                            for entry in path.read_text().splitlines():
                                tokens=shlex.split(entry,comments=True)
                                if tokens and matches(tokens[0],crt_base):references.append(dict(source=file.name,section=section,line=number))
                        except (OSError,ValueError):references.append(dict(source=file.name,section=section,line=number,reason='Не удалось проверить crt-list.'))
            # Disabled services still need their certificate when enabled again.
            try:
                _,models=clean(encode(source))
                if any(name in json.dumps(model,ensure_ascii=False) for model in models):
                    references.append(dict(source=file.name,section='Сохранённые настройки сервиса',line=0))
            except ValueError:
                references.append(dict(source=file.name,section='Повреждённые служебные блоки',line=0))
        return references

    def manage_certificate(self, value):
        if self.engine.settings['read_only']:raise ValueError('Изменения отключены в настройках установки.')
        name=value.get('name')
        if not isinstance(name,str) or Path(name).name!=name or not name.endswith('.pem'):raise ValueError('Некорректное имя сертификата.')
        folder=Path(self.engine.settings['certificate_dir'])
        file=folder/name
        with self.engine.lock:
            if file.is_symlink() or not file.is_file():raise ValueError('Сертификат не найден или является ссылкой.')
            labels_file=self.engine.state/'certificate-labels.json'
            labels=json.loads(labels_file.read_text()) if labels_file.exists() else {}
            action=value.get('action')
            if action=='rename':
                label=value.get('label','')
                if not isinstance(label,str) or not 1<=len(label.strip())<=120 or any(ord(c)<32 for c in label):raise ValueError('Название: от 1 до 120 символов.')
                labels[name]=label.strip()
            elif action=='delete':
                if value.get('confirm') is not True:raise ValueError('Подтвердите удаление сертификата.')
                if self.certificate_references(name):raise ValueError('Сертификат используется. Сначала измените связанные сервисы и TLS-входы.')
                backup=self.engine.state/'deleted-certificates'/secrets.token_hex(16)
                backup.mkdir(parents=True,mode=0o700)
                backup.parent.chmod(0o700)
                shutil.copy2(file,backup/name);(backup/name).chmod(0o600)
                file.unlink();labels.pop(name,None)
            else:raise ValueError('Неизвестное действие с сертификатом.')
            temp=labels_file.with_suffix('.tmp')
            temp.write_text(json.dumps(labels,ensure_ascii=False));temp.chmod(0o600);temp.replace(labels_file)
            self.engine.audit('certificate-'+action,name=name)
        return dict(ok=True,message='Сертификат удалён.' if action=='delete' else 'Название сохранено.')

    def backends(self, readonly=False):
        revision=self.engine.snapshot()[1]
        sources=self.sources();items=[];references=[];dynamic=False
        imported_pools=set()
        for file,source in sources.items():
            blocks=list(BLOCK.finditer(source))
            managed=[(m.start(),m.end()) for m in blocks]
            for model in clean(encode(source))[1]:
                if model.get('import_pool'):imported_pools.add((str(file),model['id'],model['import_pool']))
            headers=list(re.finditer(r'(?m)^[ \t]*(global|defaults|frontend|backend|listen|userlist|resolvers|peers|cache|program|ring|mailers)\b[^\n]*',source))
            for index,head in enumerate(headers):
                end=headers[index+1].start() if index+1<len(headers) else len(source)
                # Keep comments and managed block boundaries preceding the next section.
                for start,stop in managed:
                    if head.start()<start<end:end=start
                tail=source[head.start():end].splitlines(True)
                while len(tail)>1 and (not tail[-1].strip() or tail[-1].lstrip().startswith('#')):
                    end-=len(tail.pop())
                body=source[head.start():end];parts=head[0].split()
                protected=any(start<=head.start()<stop for start,stop in managed)
                if head[1]=='backend' and len(parts)>1:
                    name=parts[1]
                    panel=bool(re.search(r'(?m)^\s*server\s+\S+\s+(?:127\.0\.0\.1|localhost|\[::1\]):'+str(self.engine.settings['port'])+r'\b',body))
                    items.append(dict(id=hashlib.sha256((str(file)+'\0'+name).encode()).hexdigest(),name=name,source=file.name,managed=protected,protected=panel,file=str(file),start=head.start(),end=end,mode=(re.search(r'(?m)^\s*mode\s+(http|tcp)\b',body) or [None,None])[1]))
            section='global';offset=0
            for number,line in enumerate(source.splitlines(True),1):
                h=HEADER.match(line.lstrip())
                if h:section=h[2] or h[1]
                route=re.match(r'^\s*(use_backend|default_backend)\s+(\S+)',line)
                if route:
                    if not re.fullmatch(r'[A-Za-z0-9_.:-]+',route[2]):dynamic=True
                    references.append(dict(service_id=next((m[1] for m in blocks if m.start()<=offset<m.end()),None),backend=route[2],source=file.name,section=section,line=number,file=str(file),offset=offset,length=len(line),managed=any(a<=offset<b for a,b in managed)))
                offset+=len(line)
        for item in items:
            item['references']=[r for r in references if r['backend']==item['name']]
            item['blocked']='Этот пул обслуживает панель управления.' if item['protected'] else 'Пул принадлежит сервису мастера. Удалите его в разделе «Сервисы».' if item['managed'] else 'Есть динамический выбор backend. Измените конфигурацию вручную.' if dynamic else 'Есть правила сервиса мастера, ссылающиеся на этот пул.' if any(r['managed'] for r in item['references']) else ''
        for item in items:
            if not item['blocked'] and any(pool==item['name'] for _,_,pool in imported_pools):item['blocked']='Общий backend используется импортированными сервисами, включая выключенные. Сначала удалите их ссылки.'
            supported=all(not r['managed'] or (r['file'],r['service_id'],item['name']) in imported_pools for r in item['references'])
            item['edit_blocked']=('' if supported and not(item['protected'] or item['managed'] or dynamic) else item['blocked'])
        if self.engine.snapshot()[1]!=revision:raise Conflict('Конфигурация изменилась при чтении. Обновите список.')
        return dict(backends=items,revision=revision,read_only=readonly or self.engine.settings['read_only'])

    def delete_backend(self,value):
        if self.engine.settings['read_only']:raise ValueError('Изменения отключены в настройках установки.')
        with self.engine.lock:
            catalog=self.backends()
            if value.get('revision')!=catalog['revision']:raise Conflict('Конфигурация изменилась. Обновите список backend.')
            item=next((b for b in catalog['backends'] if b['id']==value.get('id')),None)
            if not item:raise ValueError('Backend не найден.')
            if item['blocked']:raise ValueError(item['blocked'])
            if sum(b['name']==item['name'] for b in catalog['backends']) != 1:raise ValueError('Имя backend неоднозначно. Исправьте конфигурацию вручную.')
            replacement=next((b for b in catalog['backends'] if b['id']==value.get('replacement')),None)
            if value.get('replacement') and not replacement:raise ValueError('Backend для замены не найден.')
            if replacement and (replacement['id']==item['id'] or replacement['name']==item['name'] or replacement['protected']):raise ValueError('Выберите другой backend.')
            if replacement and item['mode'] and replacement['mode'] and item['mode']!=replacement['mode']:raise ValueError('Режимы backend должны совпадать.')
            if item['references'] and not replacement and value.get('remove_routes') is not True:raise ValueError('Выберите замену или подтвердите удаление связанных правил.')
            changes={};sources=self.sources();edits={item['file']:[(item['start'],item['end'],'')]}
            for ref in item['references']:
                if ref['file']==item['file'] and item['start']<=ref['offset']<item['end']:continue
                line=sources[Path(ref['file'])][ref['offset']:ref['offset']+ref['length']]
                new=re.sub(r'^(\s*(?:use_backend|default_backend)\s+)\S+',lambda m:m[1]+replacement['name'],line,count=1) if replacement else ''
                edits.setdefault(ref['file'],[]).append((ref['offset'],ref['offset']+ref['length'],new))
            if self.engine.snapshot()[1]!=catalog['revision']:raise Conflict('Конфигурация изменилась. Обновите список.')
            diffs=[]
            for name,patches in edits.items():
                original=sources[Path(name)];candidate=original
                for start,end,new in sorted(patches,reverse=True):candidate=candidate[:start]+new+candidate[end:]
                changes[name]=encode(candidate)
                diffs.append(''.join(difflib.unified_diff(mask(encode(original))[0].splitlines(True),mask(encode(candidate))[0].splitlines(True),fromfile=Path(name).name+' (сейчас)',tofile=Path(name).name+' (после удаления)')))
            raw=changes.get(str(self.engine.config),self.engine.config.read_bytes())
            checked=self.engine.validate(raw,changes)
            checked.update(changed=True,diff='\n'.join(diffs),summary=['Удалить backend '+item['name'],('Перенаправить '+str(len(item['references']))+' правил на '+replacement['name']) if replacement else 'Удалить связанных правил: '+str(len(item['references']))],warnings=[] if replacement or not item['references'] else ['После удаления правил запросы без другого подходящего маршрута могут получить ошибку 503.'])
            return checked,dict(raw=raw,files=changes,revision=catalog['revision'],reason='backend-delete')

    def replace_certificate(self,value):
        """Preview replacing a referenced PEM without appending ambiguous SNI certs."""
        if self.engine.settings['read_only']:raise ValueError('Изменения отключены.')
        from .services import ServiceManager
        manager=ServiceManager(self.engine)
        original=manager.certificate_path(value.get('name'))
        replacement=manager.certificate_path(value.get('replacement'))
        if original==replacement:raise ValueError('Выберите другой, уже загруженный сертификат.')
        if original.is_symlink() or replacement.is_symlink():raise ValueError('Символические ссылки сертификатов нельзя заменять из панели.')
        raw,revision=self.engine.snapshot()
        if value.get('revision')!=revision:raise Conflict('Конфигурация изменилась. Повторите просмотр.')
        # Existing domains must remain covered; rotation must not drop other tenants.
        from .certificate_info import metadata
        old=metadata(self.engine,original);new=metadata(self.engine,replacement)
        for domain in old['domains']:
            if domain.startswith('*.'):
                if domain not in new['domains']:raise ValueError('Новый сертификат не сохраняет wildcard '+domain+'.')
            elif self.engine.command(['openssl','x509','-in',str(replacement),'-noout','-checkhost',domain]).returncode:raise ValueError('Новый сертификат не покрывает '+domain+'.')
        if not new['readable'] or new['expired'] or new['not_yet_valid']:raise ValueError('Новый сертификат не действует.')
        # SSLContext validates the leaf/private-key pair without exposing either.
        import ssl
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:context.load_cert_chain(str(replacement))
        except (OSError,ssl.SSLError):raise ValueError('Сертификат и приватный ключ нового PEM не проходят проверку.')
        before=original.read_bytes();after=replacement.read_bytes()
        candidate=raw.replace(str(original).encode(),str(replacement).encode())
        checked=self.engine.validate(candidate)
        checked.update(changed=before!=after,baseline=self.engine.validate(raw),diff='Заменить содержимое '+original.name+' сертификатом '+replacement.name+'. Приватный ключ и PEM в diff не выводятся.',summary=['Атомарная замена сертификата '+original.name+'. Старый PEM будет сохранён в резервной копии.','SHA-256: '+old['fingerprint']+' → '+new['fingerprint']],warnings=['Затрагиваются: '+', '.join(sorted({r.get('section',r.get('reason','')) for r in self.certificate_references(original.name)})),'После reload проверяется fingerprint на доступных локальных bind с прямым crt или каталогом crt, включая accept-proxy. Для crt-list и внешнего DNS/NAT дополнительно проверьте публичный SNI вручную.'])
        return checked,dict(raw=raw,revision=revision,reason='certificate-replace',certificate_change=dict(target=str(original),previous=before,replacement=after))

    def edit_pool(self,value):
        """Partial management: edit address/port only, preserve every other byte."""
        if self.engine.settings['read_only']:raise ValueError('Изменения отключены.')
        from .services import hostname,number,address
        catalog=self.backends()
        if value.get('revision')!=catalog['revision']:raise Conflict('Конфигурация изменилась. Повторите проверку.')
        item=next((b for b in catalog['backends'] if b['id']==value.get('id')),None)
        if not item or item.get('edit_blocked',item['blocked']):raise ValueError(item.get('edit_blocked',item['blocked']) if item else 'Backend не найден.')
        source=self.sources()[Path(item['file'])];body=source[item['start']:item['end']]
        servers=list(re.finditer(r'(?m)^(\s*server\s+([A-Za-z0-9_.:-]+)\s+)([^\s#]+)',body))
        submitted=value.get('servers')
        if not isinstance(submitted,list) or len(submitted)!=len(servers) or not servers:raise ValueError('Состав серверов изменился или имеет неподдерживаемый синтаксис. Обновите список.')
        for match,row in reversed(list(zip(servers,submitted))):
            if not isinstance(row,dict) or row.get('name')!=match[2]:raise ValueError('Имена и порядок серверов должны оставаться прежними.')
            endpoint=address(hostname(row.get('host')),number(row.get('port'),'Порт сервера'))
            body=body[:match.start(3)]+endpoint+body[match.end(3):]
        candidate=encode(source[:item['start']]+body+source[item['end']:]);changes={item['file']:candidate}
        raw=candidate if Path(item['file'])==self.engine.config else self.engine.config.read_bytes()
        checked=self.engine.validate(raw,changes)
        checked.update(changed=candidate!=encode(source),baseline=self.engine.validate(self.engine.config.read_bytes()),diff=''.join(difflib.unified_diff(mask(encode(source))[0].splitlines(True),mask(candidate)[0].splitlines(True),fromfile=item['source'],tofile=item['source']+' (новые адреса)')),summary=['Изменить адреса серверов общего backend '+item['name']+'. Остальные директивы, комментарии и порядок правил сохраняются.'],warnings=['Затрагиваются все использующие пул входы: '+', '.join(sorted({r['section'] for r in item['references']}))])
        return checked,dict(raw=raw,files=changes,revision=catalog['revision'],reason='pool-edit')
