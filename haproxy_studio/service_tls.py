"""Read-only TLS/certificate coverage from actual bind directives, not backend names."""
import ipaddress
from pathlib import Path
import re
import shlex
import subprocess
from .core import decode
from .services import bindings,overlaps,PRESETS
from .certificate_info import metadata,overlap


def canonical(path):
    try:return str(path.resolve())
    except (OSError,RuntimeError):return str(path.absolute())


class Resolver:
    def __init__(self,engine,raw,certificates=()):
        self.engine=engine;self.sections=bindings(decode(raw));self.crt_base=Path('/etc/ssl/private');self.bundle=True
        self.cache={};self.matches={};self.sources={};self.labels={};self.virtual=0
        directory=Path(engine.settings['certificate_dir'])
        for cert in certificates:
            path=canonical(directory/cert['name']);self.cache[path]=cert;self.labels[path]=cert.get('label',cert['name'])
        for section in self.sections:
            if section['type']!='global':continue
            for _,line in section['lines']:
                try:parts=shlex.split(line,comments=True)
                except ValueError:continue
                if len(parts)==2 and parts[0]=='crt-base':self.crt_base=Path(parts[1])
                if parts[:1]==['ssl-load-extra-files']:self.bundle=any(p in ('all','bundle') for p in parts[1:])

    def path(self,value):return Path(value) if Path(value).is_absolute() else self.crt_base/value

    def certificate(self,path):
        key=canonical(path)
        if key not in self.cache:
            try:self.cache[key]=metadata(self.engine,path)
            except (OSError,ValueError,subprocess.SubprocessError):self.cache[key]=dict(readable=False,domains=[])
        info=self.cache[key]
        return dict(name=path.name,path=str(path),label=self.labels.get(key,path.name),domains=info.get('domains',[]),readable=info.get('readable',False),expired=info.get('expired',False),not_yet_valid=info.get('not_yet_valid',False),not_after=info.get('not_after',''),fingerprint=info.get('fingerprint',''),key_algorithm=info.get('key_algorithm',''))

    def files(self,value,filters,issues):
        if value.startswith('@') or '$' in value:
            issues.append('Источник '+value+' требует разрешения crt-store или переменных; выбор по файлам не подтверждён.');return []
        path=self.path(value)
        try:
            if path.is_dir():
                return [(p,filters) for p in sorted(path.iterdir()) if p.is_file() and not p.name.startswith('.') and p.suffix not in ('.key','.issuer','.ocsp','.sctl')]
            if not path.exists() and self.bundle:
                extra=[Path(str(path)+'.'+suffix) for suffix in ('rsa','ecdsa','dsa') if Path(str(path)+'.'+suffix).is_file()]
                if extra:return [(p,filters) for p in extra]
        except OSError:issues.append('Не удалось прочитать каталог сертификатов '+str(path));return []
        return [(path,filters)]

    def bind_files(self,bind):
        if bind['line'] in self.sources:return self.sources[bind['line']]
        files=[];issues=[]
        try:
            parts=shlex.split(bind['line'],comments=True)
            for i,part in enumerate(parts[:-1]):
                if part=='crt':files+=self.files(parts[i+1],[],issues)
                if part=='crt-list':
                    path=self.path(parts[i+1])
                    try:
                        for line in path.read_text().splitlines():
                            tokens=shlex.split(line,comments=True)
                            if not tokens:continue
                            rest=tokens[1:]
                            if rest and rest[0].startswith('['):
                                stop=next((j for j,t in enumerate(rest) if t.endswith(']')),None)
                                if stop is None:raise ValueError('Незавершённые параметры crt-list')
                                rest=rest[stop+1:]
                            if any(not re.fullmatch(r'!?\*|!?\*?\.?[A-Za-z0-9_.-]+',f) for f in rest):raise ValueError('Неизвестный фильтр crt-list')
                            files+=self.files(tokens[0],rest,issues)
                    except (OSError,ValueError):issues.append('Не удалось полностью разобрать crt-list '+str(path))
        except ValueError:issues.append('Не удалось разобрать TLS bind.')
        result=[];seen=set()
        for path,filters in files:
            key=(canonical(path),tuple(filters))
            if key in seen:continue
            seen.add(key);cert=self.certificate(path)
            if not cert['readable']:issues.append('Не удалось прочитать сертификат '+str(path))
            result.append((cert,filters))
        if not result and not issues:issues.append('Файлы сертификатов этого TLS-входа не определены.')
        self.sources[bind['line']]=(result,list(dict.fromkeys(issues)));return self.sources[bind['line']]

    def covers(self,cert,domain):
        if not domain:return True
        if not cert['readable']:return False
        try:ipaddress.ip_address(domain);option='-checkip'
        except ValueError:
            option='-checkhost'
            if not any(overlap(name.lower(),domain.lower()) for name in cert['domains']):return False
        key=(cert['path'],domain)
        if key not in self.matches:
            try:self.matches[key]=self.engine.command(['openssl','x509','-in',cert['path'],'-noout',option,domain]).returncode==0
            except (OSError,subprocess.SubprocessError):self.matches[key]=False
        return self.matches[key]

    def allowed(self,domain,filters):
        if not domain:return True
        match=lambda f:f=='*' or overlap(f.lower(),domain.lower())
        return not any(match(f[1:]) for f in filters if f.startswith('!')) and (not any(not f.startswith('!') for f in filters) or any(match(f) for f in filters if not f.startswith('!')))

    def model(self,model):
        mode=model.get('tls_mode','plain');protocol=model.get('classification',{}).get('id',model.get('protocol','tcp'))
        if mode=='plain' and protocol in ('smtp','submission','imap','pop3','sieve'):mode='starttls'
        elif mode=='plain' and PRESETS.get(model.get('protocol'),PRESETS['tcp'])[3]!='http':mode='application'
        domains=list(dict.fromkeys(model.get('domains') or ([model['domain']] if model.get('domain') else [''])))
        port=model.get('port');front=model.get('import_acl',{}).get('frontend') or model.get('https_frontend') or model.get('tcp_frontend')
        listener_port=model.get('import_acl',{}).get('listener_port',model.get('listener_port',port));rows=[]
        if mode!='terminate':
            message={'passthrough':'Сертификат отдаёт внутренний сервер. По локальным файлам он не проверялся.','starttls':'STARTTLS и сертификат обслуживает внутренний сервер. По локальным файлам он не проверялся.','plain':'HTTP на входе HAProxy передаётся без TLS.','application':'HAProxy передаёт прикладной протокол прозрачно. Его шифрование, сертификат или ключ узла внутреннего сервера здесь не проверяются.'}.get(mode,'Режим TLS не определён.')
            return dict(mode=mode,enabled=model.get('enabled',True),rows=[dict(domain=d,port=port,frontend=front or '',mode=mode,status='external' if mode!='plain' else 'plain',message=message,certificates=[],warnings=[]) for d in domains])
        kind=PRESETS.get(model.get('protocol'),PRESETS['tcp'])[3]
        listeners=[(s,b) for s in self.sections if s['type'] in ('frontend','listen') and (not front or s['name']==front) and (s['mode']=='http')==(kind=='http') for b in s['binds'] if b['tls'] and b['lo']<=listener_port<=b['hi'] and (front or overlaps(b['host'],model.get('bind_address','*')))]
        if not listeners:self.virtual+=1
        virtual='__virtual_'+str(self.virtual)
        if not listeners and not model.get('enabled',True):
            refs=[];issues=[]
            for name in model.get('certificates') or ([model['certificate']] if model.get('certificate') else []):refs+=self.files(str(Path(self.engine.settings['certificate_dir'])/name),[],issues)
            fake=dict(line=virtual,lo=listener_port,hi=listener_port,host=model.get('bind_address','*'))
            self.sources[virtual]=( [(self.certificate(p),f) for p,f in refs],issues+['Сохранённые настройки выключенного сервиса; активного входа нет.'])
            listeners=[(dict(name='Сохранённые настройки'),fake)]
        if not listeners:listeners=[(dict(name=front or ''),dict(line=virtual,lo=listener_port,hi=listener_port,host=model.get('bind_address','*')))];self.sources.setdefault(virtual,([],['TLS-вход не найден или неоднозначен в текущей конфигурации.']))
        for section,bind in listeners:
            certs,issues=self.bind_files(bind)
            for domain in domains:
                matches=[(c,f) for c,f in certs if self.allowed(domain,f) and self.covers(c,domain)]
                def exact(cert,filters):
                    names=[f for f in filters if not f.startswith('!')] or cert['domains']
                    return bool(domain) and domain.lower() in {n.lower() for n in names}
                exact_algorithms={c['key_algorithm'] for c,f in matches if c['key_algorithm'] and exact(c,f)}
                selected=[c for c,f in matches if exact(c,f) or not c['key_algorithm'] or c['key_algorithm'] not in exact_algorithms]
                unique={c['fingerprint'] or c['path'] for c in selected}
                if issues:status='unknown';message='TLS-вход не удалось проверить полностью; смотрите предупреждения.'
                elif not domain:status='unspecified';message='SNI в настройках сервиса не задан; перечислены файлы входа, конкретный выбор клиента не подтверждён.'
                elif not selected:status='missing';message='На этом входе не найден сертификат, покрывающий домен.'
                elif any(c['expired'] for c in selected):status='expired';message='Есть истёкший сертификат среди подходящих файлов.'
                elif any(c['not_yet_valid'] for c in selected):status='not_yet_valid';message='Есть сертификат, срок действия которого ещё не начался.'
                elif len(unique)>1:
                    algorithms=[c['key_algorithm'] for c in selected]
                    if len(algorithms)==len(set(algorithms)) and all(algorithms):status='alternatives';message='Несколько алгоритмов ключа; выбор зависит от возможностей клиента.'
                    else:status='ambiguous';message='Несколько подходящих сертификатов; однозначный выбор не подтверждён.'
                else:status='ok';message='Сертификат подходит по домену и сроку действия.'
                rows.append(dict(domain=domain,port=port,frontend=section['name'],listener_address=bind.get('host',''),listener_port=listener_port,mode=mode,status=status,message=message,certificates=selected,warnings=issues))
        return dict(mode=mode,enabled=model.get('enabled',True),rows=rows)

    def discovered(self,item):
        section=next((s for s in self.sections if s['name']==item['frontend'] and s['type'] in ('frontend','listen')),None)
        if not section:return dict(mode='unknown',enabled=True,rows=[])
        port=(item.get('ports') or [0])[0];tls=any(b['tls'] for b in section['binds']);protocol=item.get('classification',{}).get('id','tcp')
        passthrough=protocol in ('imaps','smtps','pop3s','tls','rdweb','rdgateway') or any('req.ssl_sni' in line or 'req_ssl_sni' in line for _,line in section['lines'])
        model=dict(protocol='https' if section['mode']=='http' and tls else 'http' if section['mode']=='http' else 'tls' if tls or passthrough else 'tcp',classification=item.get('classification',{}),tls_mode='terminate' if tls else 'passthrough' if passthrough else 'plain',port=port,domains=item.get('domains',[]),bind_address='*',tcp_frontend=section['name'],enabled=True)
        return self.model(model)
