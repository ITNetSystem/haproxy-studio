import csv
import difflib
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time

class Conflict(ValueError):
    pass

def decode(raw):
    return raw.decode('utf-8', 'surrogateescape')

def encode(value):
    return value.encode('utf-8', 'surrogateescape')

def mask(raw):
    hidden, lines = {}, []
    for line in decode(raw).splitlines(keepends=True):
        if re.search(r'(?i)\bstats\s+auth\b|\bpassword\b|\bpasswd\b|\bsecret\b|\btoken\b|\bauthorization\b|PRIVATE KEY', line):
            marker = '# @studio-protected-' + hashlib.sha256(encode(line)).hexdigest()[:20]
            while marker in hidden:
                marker += '-'
            hidden[marker] = line
            lines.append(marker + '\n')
        else:
            lines.append(line)
    return ''.join(lines), hidden

def unmask(content, hidden):
    for marker, original in hidden.items():
        if content.splitlines().count(marker) != 1:
            raise ValueError('Сохраните строки @studio-protected без изменений.')
        content = content.replace(marker + '\n', original) if marker + '\n' in content else content.replace(marker, original)
    if re.search(r'^# @studio-protected-', content, re.M):
        raise ValueError('Неизвестная защищённая строка.')
    return encode(content)

def sections(raw):
    result, current = [], None
    for number, line in enumerate(decode(raw).splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        found = re.match(r'^(global|defaults|frontend|backend|listen)\b(?:\s+(\S+))?', stripped)
        if found:
            current = dict(type=found[1], name=found[2] or found[1], line=number, binds=[], servers=[], routes=[], domains=[])
            result.append(current)
        elif current:
            parts = stripped.split()
            if parts[0] == 'bind' and len(parts) > 1:
                current['binds'].append(parts[1])
            elif parts[0] == 'server' and len(parts) > 2:
                current['servers'].append(dict(name=parts[1], address=parts[2], line=number, disabled='disabled' in parts[3:]))
            elif parts[0] in ('use_backend', 'default_backend') and len(parts) > 1:
                current['routes'].append(dict(backend=parts[1], condition=' '.join(parts[2:]), line=number))
            elif parts[0] == 'acl' and 'hdr(host)' in stripped:
                current['domains'] += [p for p in parts[3:] if '.' in p and not p.startswith('-')]
    return result

class Engine:
    def __init__(self, settings):
        self.settings = settings
        self.config = Path(settings['config_file'])
        self.extra = Path(settings['extra_config_dir']) if settings.get('extra_config_dir') else None
        self.state = Path(settings['state_dir'])
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state.chmod(0o700)
        (self.state / 'backups').mkdir(mode=0o700, exist_ok=True)
        self.lock = threading.RLock()

    def command(self, args, timeout=20):
        return subprocess.run(args, capture_output=True, check=False, timeout=timeout)

    def snapshot(self):
        raw = self.config.read_bytes()
        digest = hashlib.sha256(raw)
        if self.extra and self.extra.is_dir():
            for file in sorted(self.extra.glob('*.cfg')):
                digest.update(str(file).encode())
                digest.update(file.read_bytes())
        return raw, digest.hexdigest()

    def audit(self, action, **fields):
        with (self.state / 'audit.jsonl').open('a') as stream:
            stream.write(json.dumps(dict(time=time.time(), action=action, **fields)) + '\n')

    def validate(self, raw, files=None):
        if self.settings['read_only']:
            raise ValueError('Режим наблюдения: проверка и применение отключены.')
        if files:self.checked_files(files)
        from .selfpublish import protect_publication
        try:protect_publication(self,self.config.read_bytes(),raw,files)
        except ValueError as error:
            return dict(ok=False,output=str(error),diagnostics=[dict(severity='ALERT',message=str(error))])
        if files:
            return self.validate_files(raw, files)
        fd, name = tempfile.mkstemp(prefix='.studio-check-', suffix='.cfg', dir=self.config.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
            args = [self.settings['haproxy_binary'], '-c', '-V', '-f', name]
            if self.extra and self.extra.is_dir():
                args += ['-f', str(self.extra)]
            completed = self.command(args)
            from .diagnostics import result
            return result(completed, raw, dict({str(file):file.read_bytes() for file in self.config_files()[1:]},**{name:raw}))
        finally:
            Path(name).unlink(missing_ok=True)

    def compatibility_preview(self,revision):
        from .diagnostics import compatibility,ssl_issues
        raw,actual=self.snapshot()
        if revision!=actual:raise Conflict('Конфигурация изменилась. Повторите проверку.')
        build=compatibility(self.settings['haproxy_binary'],self.command)
        issues=ssl_issues(raw,build)
        if not issues:raise ValueError('В текущем конфиге нет известных несовместимых DH-директив для этой SSL-библиотеки.')
        targets={i['line'] for i in issues}
        candidate=b''.join((b'# studio compatibility: '+line if n in targets else line) for n,line in enumerate(raw.splitlines(True),1))
        result,draft=self.preview(mask(candidate)[0],revision)
        result['summary']=['Закомментировать только неподдерживаемые настройки DH для AWS-LC. TLS, сертификаты и наборы шифров сохраняются.']
        return result,draft

    def config_files(self):
        return [self.config] + (sorted(self.extra.glob('*.cfg')) if self.extra and self.extra.is_dir() else [])

    def checked_files(self, files):
        allowed = {str(p): p for p in self.config_files()}
        result = {}
        for name, raw in files.items():
            if name not in allowed or allowed[name].is_symlink() or not isinstance(raw, bytes):
                raise ValueError('Недопустимый файл конфигурации.')
            result[allowed[name]] = raw
        return result

    def validate_files(self, raw, files):
        changes = self.checked_files(files)
        with tempfile.TemporaryDirectory(prefix='.studio-check-', dir=self.config.parent) as folder:
            args = [self.settings['haproxy_binary'], '-c', '-V']
            for index, file in enumerate(self.config_files()):
                target = Path(folder) / (str(index) + '.cfg')
                target.write_bytes(changes.get(file, raw if file == self.config else file.read_bytes()))
                args += ['-f', str(target)]
            result = self.command(args)
            from .diagnostics import result as report
            return report(result,raw,{str(Path(folder)/(str(i)+'.cfg')):changes.get(file,raw if file==self.config else file.read_bytes()) for i,file in enumerate(self.config_files())})

    def preview(self, content, revision, backup=None):
        current, actual = self.snapshot()
        if actual != revision:
            raise Conflict('Файл изменён на сервере. Загрузите актуальную версию.')
        files = {}
        if backup:
            if not isinstance(backup, str) or not re.fullmatch(r'\d{8}-\d{6}-[a-f0-9]{8}', backup):
                raise ValueError('Некорректная версия резервной копии.')
            candidate = (self.state / 'backups' / backup / 'haproxy.cfg').read_bytes()
            saved = self.state / 'backups' / backup / 'conf.d'
            if self.extra and saved.is_dir():
                for file in self.config_files()[1:]:
                    old = saved / file.name
                    if old.is_file() and not old.is_symlink():
                        files[str(file)] = old.read_bytes()
        else:
            if not isinstance(content, str):
                raise ValueError('Ожидается текст конфигурации.')
            candidate = unmask(content, mask(current)[1])
        result = self.validate(candidate, files) if files else self.validate(candidate)
        old, new = mask(current)[0], mask(candidate)[0]
        result['baseline']=self.validate(current)
        result.update(diff=''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile='Текущая версия', tofile='Новая версия')), changed=current != candidate)
        for name, raw in files.items():
            previous = Path(name).read_bytes()
            result['changed'] = result['changed'] or previous != raw
            result['diff'] += ''.join(difflib.unified_diff(mask(previous)[0].splitlines(True), mask(raw)[0].splitlines(True), fromfile=Path(name).name + ' (сейчас)', tofile=Path(name).name + ' (восстановление)'))
        return result, dict(raw=candidate, files=files, revision=revision, reason='restore:' + backup if backup else 'edit')

    def atomic_write(self, raw, target=None):
        target = target or self.config
        info = target.stat()
        fd, name = tempfile.mkstemp(prefix='.studio-install-', suffix='.cfg', dir=target.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            shutil.copystat(target, name)
            os.chown(name, info.st_uid, info.st_gid)
            os.replace(name, target)
            directory = os.open(target.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(name).unlink(missing_ok=True)

    def apply(self, draft):
        if self.settings['read_only']:
            raise ValueError('Изменения отключены в настройках установки.')
        with self.lock, (self.state / 'apply.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            previous, revision = self.snapshot()
            if revision != draft['revision']:
                raise Conflict('Конфигурация изменилась после проверки. Повторите проверку.')
            from .certificate_names import install as install_certificate_alias
            with install_certificate_alias(self,draft.get('certificate_alias')):
                files = draft.get('files', {})
                from .selfpublish import protect_publication
                protect_publication(self,previous,draft['raw'],files)
                changes = self.checked_files(files)
                originals = {file: file.read_bytes() for file in changes}
                checked = self.validate(draft['raw'], files) if files else self.validate(draft['raw'])
                if not checked['ok']:
                    raise ValueError(checked['output'])
                cert_change=draft.get('certificate_change')
                if cert_change and (Path(cert_change['target']).is_symlink() or Path(cert_change['target']).read_bytes()!=cert_change['previous']):raise Conflict('Сертификат изменён после проверки.')
                if not cert_change and not draft.get('certificate_alias') and not draft.get('studio_origin') and previous == draft['raw'] and all(originals[p] == raw for p,raw in changes.items()):
                    return dict(ok=True, message='Изменений нет. Перезагрузка не нужна.')
                if draft.get('certificate_alias') and previous==draft['raw'] and all(originals[p]==raw for p,raw in changes.items()):
                    self.audit('certificate-name',name=draft['certificate_alias']['target'])
                    return dict(ok=True,message='Понятное имя PEM сохранено. Ссылок в конфиге не было; reload не требовался. Старый PEM сохранён.')
                backup = time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
                folder = self.state / 'backups' / backup
                folder.mkdir(mode=0o700)
                shutil.copy2(self.config, folder / 'haproxy.cfg')
                if self.extra and self.extra.is_dir():
                    shutil.copytree(self.extra, folder / 'conf.d')
                (folder / 'meta.json').write_text(json.dumps(dict(id=backup, time=time.time(), reason=draft['reason'])))
                if self.snapshot()[1] != revision:
                    raise Conflict('Обнаружено внешнее изменение. Повторите проверку.')
                if cert_change:(folder/'certificate.pem').write_bytes(cert_change['previous'])
                if draft.get('metadata_only'):
                    from .service_types import type_only_change
                    if files or cert_change or draft.get('studio_origin') or not type_only_change(previous,draft['raw']):
                        raise ValueError('Уточнение типа содержит изменения маршрутизации. Повторите проверку.')
                    self.atomic_write(draft['raw'])
                    self.audit('service-type',backup=backup)
                    return dict(ok=True,backup=backup,metadata_only=True,message='Тип сервиса обновлён. Маршрутизация не менялась; перезагрузка HAProxy не потребовалась.')
                previous_worker = None
                try:
                    found = re.search(r'^Pid: (\d+)$', self.runtime('show info'), re.M)
                    previous_worker = found[1] if found else None
                except (OSError, ValueError):
                    pass
                origin_change=draft.get('studio_origin')
                if origin_change and Path(origin_change['path']).read_bytes()!=origin_change['previous']:raise Conflict('Настройки Studio изменены после проверки.')
                if origin_change:(folder/'studio-settings.json').write_bytes(origin_change['previous'])
                if origin_change and not cert_change and previous==draft['raw'] and all(originals[p]==raw for p,raw in changes.items()):
                    from .selfpublish import install
                    install(self,origin_change)
                    self.audit('studio-origin',backup=backup)
                    return dict(ok=True,message='Публичный адрес Studio обновлён. Конфигурация HAProxy не менялась; reload не требовался.',backup=backup,public_url=self.settings['public_url'])
                recovered = False
                try:
                    self.atomic_write(draft['raw'])
                    for file, raw in changes.items():
                        if file != self.config:
                            self.atomic_write(raw, file)
                    if cert_change:
                        self.atomic_write(cert_change['replacement'],Path(cert_change['target']))
                        if not self.validate(draft['raw'])['ok']:raise ValueError('Новая конфигурация сертификата не прошла проверку.')
                    applied = self.command(self.settings['reload_command'], timeout=30).returncode == 0
                    applied = applied and self.command(self.settings['health_command']).returncode == 0
                    if applied and previous_worker and (draft.get('reason', '').startswith('service:') or draft.get('reason') in ('backend-delete','pool-edit')):
                        changed = False
                        for attempt in range(20):
                            try:
                                found = re.search(r'^Pid: (\d+)$', self.runtime('show info'), re.M)
                                changed = bool(found and found[1] != previous_worker)
                            except (OSError, ValueError):
                                pass
                            if changed: break
                            time.sleep(.15)
                        applied = changed
                    if applied and cert_change:
                        from .certificate_probe import verify
                        cert_change['verified_listeners']=verify(self,cert_change)
                    if applied and origin_change:
                        from .selfpublish import install
                        install(self,origin_change)
                except (OSError, ValueError, subprocess.SubprocessError):
                    applied = False
                if not applied:
                    if cert_change:self.atomic_write(cert_change['previous'],Path(cert_change['target']))
                    self.atomic_write(previous)
                    for file, raw in originals.items():
                        if file != self.config:
                            self.atomic_write(raw, file)
                    try:
                        recovered = self.command(self.settings['reload_command'], timeout=30).returncode == 0 and self.command(self.settings['health_command']).returncode == 0
                    except (OSError, subprocess.SubprocessError):
                        pass
                    self.audit('apply-failed', backup=backup, recovered=recovered)
                    raise ValueError('Новый файл отклонён. Старый файл восстановлен. ' + ('Служба работает.' if recovered else 'Проверьте службу вручную: восстановительная перезагрузка не подтверждена.'))
                self.audit('apply', backup=backup,certificate_verified_listeners=cert_change.get('verified_listeners',0) if cert_change else None)
                message='Изменения применены. Выполнена плавная перезагрузка HAProxy.'
                if cert_change:message+=(' Fingerprint проверен на локальных TLS-входах: '+str(cert_change['verified_listeners'])+'.' if cert_change.get('verified_listeners') else ' Прямые TLS-входы для автоматической проверки не найдены; проверьте публичный SNI вручную.')
                return dict(ok=True, message=message, backup=backup,public_url=self.settings['public_url'] if origin_change else None)

    def runtime(self, command):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(3)
            client.connect(self.settings['runtime_socket'])
            client.sendall((command + '\n').encode())
            chunks, total = [], 0
            while True:
                part = client.recv(65536)
                if not part:
                    break
                total += len(part)
                if total > 8 * 1024 * 1024:
                    raise ValueError('Runtime response too large')
                chunks.append(part)
        return b''.join(chunks).decode('utf-8', 'replace')

    def overview(self):
        raw, revision = self.snapshot()
        warning = None
        try:
            info = dict(line.split(': ', 1) for line in self.runtime('show info').splitlines() if ': ' in line)
            data = csv.DictReader(io.StringIO(self.runtime('show stat').lstrip('# ')))
            keys = ('pxname', 'svname', 'status', 'scur', 'stot', 'bin', 'bout', 'rate', 'check_status', 'econ', 'eresp', 'hrsp_5xx')
            rows = [{key: row.get(key, '') for key in keys} for row in data]
            if 'Version' not in info:
                raise ValueError('Invalid runtime response')
        except (OSError, ValueError):
            info, rows = {}, []
            warning = 'Runtime API недоступен. Проверьте путь к socket, права доступа и службу HAProxy.'
        allowed = ('Version', 'Uptime', 'CurrConns', 'CumConns', 'ConnRate', 'Maxconn', 'Nbthread')
        from .services import clean
        from .monitoring import annotate,overview_servers,service_summary
        from .routing import describe,publications
        base,models=clean(raw)
        from .service_types import annotate as annotate_types
        annotate_types(models,base,self.settings)
        parsed=describe(raw,sections(raw),models)
        extra_sections=[]
        for file in self.config_files()[1:]:extra_sections+=sections(file.read_bytes())
        reference_sections=parsed+extra_sections
        annotate(rows,reference_sections,models)
        destinations=overview_servers(rows,reference_sections,models,base,self.settings)
        summary=service_summary(destinations)
        return dict(summary,server_groups=destinations,info={key: info.get(key) for key in allowed}, rows=rows, sections=parsed, publications=publications(models,rows,parsed), revision=revision, warning=warning, time=time.time(), read_only=self.settings['read_only'])

    def history(self):
        backups = [json.loads(p.read_text()) for p in sorted((self.state / 'backups').glob('*/meta.json'), reverse=True)][:50]
        log = self.state / 'audit.jsonl'
        events = [json.loads(line) for line in log.read_text().splitlines()[-50:]][::-1] if log.exists() else []
        return dict(backups=backups, events=events)

    def certificates(self):
        items = []
        labels_path = self.state / 'certificate-labels.json'
        labels = json.loads(labels_path.read_text()) if labels_path.exists() else {}
        for file in sorted(Path(self.settings['certificate_dir']).glob('*.pem')):
            try:
                result = self.command(['openssl', 'x509', '-in', str(file), '-noout', '-subject', '-issuer', '-dates', '-ext', 'subjectAltName'])
                detail = result.stdout.decode('utf-8', 'replace') if result.returncode == 0 else 'Не удалось прочитать сертификат.'
            except (OSError, subprocess.SubprocessError):
                detail = 'Для чтения метаданных установите OpenSSL.'
            from .certificate_info import metadata
            items.append(dict(name=file.name, label=labels.get(file.name, file.name), details=detail,**metadata(self,file)))
        return dict(certificates=items)
