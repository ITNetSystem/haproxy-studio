"""Reviewed certificate file aliases; old files survive for rollback."""
from contextlib import contextmanager
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
from .core import Conflict,encode,decode,mask
from .services import BLOCK,TLSBASE,block,packed,unpacked,clean,ServiceManager
from .certificates import available_name

TOKENS=re.compile(r'''(?:[^\s'"#]+|'[^']*'|"[^"]*")+''')

def preview(engine,value):
    if engine.settings['read_only']:raise ValueError('Изменения отключены.')
    raw,revision=engine.snapshot()
    if value.get('revision')!=revision:raise Conflict('Конфигурация изменилась. Обновите сертификаты.')
    source=ServiceManager(engine).certificate_path(value.get('name'))
    if source.is_symlink():raise ValueError('Символическую ссылку нельзя переименовывать из панели.')
    label=value.get('label','')
    if not isinstance(label,str) or not 1<=len(label.strip())<=80 or any(ord(c)<32 for c in label):raise ValueError('Название сертификата: от 1 до 80 символов.')
    target=source.parent/available_name(source.parent,label,exclude=source.name)
    if target==source:raise ValueError('Имя файла уже соответствует названию. Для изменения только подписи снимите галочку переименования PEM.')
    sources={str(p):p.read_bytes() for p in engine.config_files()}
    crt_base=Path('/etc/ssl/private');ca_base=Path('/etc/ssl/certs')
    for content in sources.values():
        for line in decode(content).splitlines():
            try:parts=shlex.split(line,comments=True)
            except ValueError:continue
            if len(parts)==2 and parts[0]=='crt-base':crt_base=Path(parts[1])
            if len(parts)==2 and parts[0]=='ca-base':ca_base=Path(parts[1])
    def resolves(value,base):return (Path(value) if Path(value).is_absolute() else base/value).resolve()
    for content in sources.values():
        for line in decode(content).splitlines():
            try:parts=shlex.split(line,comments=True)
            except ValueError:
                if source.name in line:raise ValueError('Неоднозначная ссылка на PEM. Сначала исправьте строку конфигурации.')
                continue
            for i,word in enumerate(parts[:-1]):
                if word=='crt' and resolves(parts[i+1],crt_base).is_dir() and resolves(parts[i+1],crt_base) in source.parents:raise ValueError('PEM загружается через каталог crt. Его переименование требует отдельной проверки всего каталога; подпись в панели можно изменить без переименования файла.')
                if word=='crt-list':
                    try:entries=resolves(parts[i+1],crt_base).read_text().splitlines()
                    except OSError:raise ValueError('Не удалось проверить crt-list. Измените только подпись либо проверьте список вручную.')
                    for entry in entries:
                        tokens=shlex.split(entry,comments=True)
                        if tokens and resolves(tokens[0],crt_base)==source:raise ValueError('PEM указан в crt-list. Переименуйте его со списком отдельно либо измените только подпись в панели.')
    def rewrite_line(line):
        spans=list(TOKENS.finditer(line));words=[]
        for m in spans:
            try:items=shlex.split(m[0],comments=False);words.append(items[0] if len(items)==1 else '')
            except ValueError:words.append('')
        if not words or words[0] not in ('bind','server','default-server'):return line
        patches=[]
        for i,key in enumerate(words[:-1]):
            if key not in ('crt','ca-file','ca-verify-file','crl-file'):continue
            value=words[i+1];base=crt_base if key=='crt' else ca_base
            if resolves(value,base)==source:
                replacement=str(target) if Path(value).is_absolute() else str(Path(value).with_name(target.name))
                patches.append((spans[i+1].start(),spans[i+1].end(),replacement))
        for start,end,new in reversed(patches):line=line[:start]+new+line[end:]
        return line
    def lines(text):return ''.join(rewrite_line(line) for line in text.splitlines(True))
    def rewrite(content):
        text=decode(content);parts=[];offset=0
        for m in BLOCK.finditer(text):
            parts.append(lines(text[offset:m.start()]));body=m[4]
            if m[2]=='model':
                found=re.search(r'^# studio-model (\S+)$',body,re.M);model=unpacked(found[1])
                if model.get('certificate')==source.name:model['certificate']=target.name
                if model.get('certificates'):model['certificates']=[target.name if n==source.name else n for n in model['certificates']]
                body=body[:found.start()]+ '# studio-model '+packed(model)+body[found.end():]
            parts.append(block(m[1],m[2],lines(body)));offset=m.end()
        parts.append(lines(text[offset:]));text=''.join(parts)
        def tls(m):
            entry=unpacked(m[1]);entry['line']=rewrite_line(entry['line']);entry['hash']=hashlib.sha256(encode(m[2])).hexdigest()
            return '# studio-tls-base '+packed(entry)+'\n'+m[2]
        text=TLSBASE.sub(tls,text);result=encode(text);clean(result);return result
    changes={name:rewrite(content) for name,content in sources.items()}
    candidate=changes[str(engine.config)]
    # Native validation loads identical existing bytes; no new PEM is written in preview.
    def existing(content):return content.replace(str(target).encode(),str(source).encode()).replace((' '+target.name).encode(),(' '+source.name).encode())
    checked=engine.validate(existing(candidate),{name:existing(content) for name,content in changes.items()})
    fingerprint=hashlib.sha256(source.read_bytes()).hexdigest()
    checked.update(changed=True,diff='\n'.join(''.join(difflib.unified_diff(mask(sources[name])[0].splitlines(True),mask(content)[0].splitlines(True),fromfile=Path(name).name,tofile=Path(name).name+' (новое имя PEM)')) for name,content in changes.items())+'\nPEM: '+source.name+' → '+target.name+' (содержимое и ключ не меняются).',summary=['Имя файла: '+source.name+' → '+target.name+'. Прямые ссылки и сохранённые настройки сервисов обновятся вместе.'],warnings=['Старый PEM сохраняется для отката. Новое имя создаётся только при применении; ссылки вне конфигураций, настроенных в Studio, не меняются.'])
    return checked,dict(raw=candidate,files=changes,revision=revision,reason='service:certificate-name',certificate_alias=dict(source=str(source),target=str(target),fingerprint=fingerprint,label=label.strip()))

@contextmanager
def install(engine,alias):
    if not alias:yield;return
    root=Path(engine.settings['certificate_dir']).resolve();source=Path(alias['source']);target=Path(alias['target'])
    if source.parent!=root or target.parent!=root or source.is_symlink() or not re.fullmatch(r'[A-Za-z0-9_.-]+\.pem',target.name):raise ValueError('Недопустимый путь PEM.')
    if target.exists() or target.is_symlink():raise Conflict('Новое имя PEM уже занято. Повторите проверку.')
    content=source.read_bytes()
    if hashlib.sha256(content).hexdigest()!=alias['fingerprint']:raise Conflict('Сертификат изменён после проверки.')
    labels=engine.state/'certificate-labels.json';before=labels.read_bytes() if labels.exists() else None
    values=json.loads(before) if before else {};values[target.name]=alias['label']
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
        temp=labels.with_suffix('.tmp');temp.write_text(json.dumps(values));temp.chmod(0o600);temp.replace(labels)
        yield
    except BaseException:
        # If restoration itself failed, keep the PEM still referenced by the live file.
        try:still_referenced=any(target.name.encode() in file.read_bytes() for file in engine.config_files())
        except OSError:still_referenced=True
        if still_referenced:raise
        target.unlink(missing_ok=True)
        if before is None:labels.unlink(missing_ok=True)
        else:
            temp=labels.with_suffix('.tmp');temp.write_bytes(before);temp.chmod(0o600);temp.replace(labels)
        raise
