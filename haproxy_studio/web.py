import hashlib
import hmac
import http.cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
from urllib.parse import urlsplit
from . import __version__
from .core import Engine, Conflict, mask
from .resources import Resources
from .accounts import Accounts
from .settings import load
from .startup import diagnostics, notify_ready
from .services import ServiceManager
from .certificates import upload as upload_certificate

STATIC = Path(__file__).parent / 'static'

class Application:
    def __init__(self, settings):
        self.settings = settings
        self.engine = Engine(settings)
        self.services = ServiceManager(self.engine)
        self.resources = Resources(self.engine)
        self.sessions, self.drafts, self.failures = {}, {}, []
        self.lock = threading.RLock()
        auth = self.engine.state / 'auth.json'
        if not auth.exists():
            self.reset_password()
        self.accounts = Accounts(self.engine.state)

    def reset_password(self):
        password, salt = secrets.token_urlsafe(24), secrets.token_bytes(16)
        value = dict(salt=salt.hex(), digest=hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 310000).hex())
        for name, content in [('auth.json', json.dumps(value)), ('initial-password', password + '\n')]:
            file = self.engine.state / name
            fd = os.open(file, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(content)
            file.chmod(0o600)
        if hasattr(self, "accounts"):
            self.accounts.recover_admin(password)
        self.sessions.clear()
        self.drafts.clear()

    def store_draft(self, checked, draft, session_key):
        with self.lock:
            now = time.time()
            for old in [k for k, v in self.drafts.items() if v['expires'] < now or v['session'] == session_key]:
                self.drafts.pop(old, None)
            if checked['ok'] and checked['changed']:
                token = secrets.token_urlsafe(32)
                draft.update(session=session_key, expires=now + 600)
                self.drafts[token] = draft
                checked['token'] = token
        return checked

    def handler(self):
        app = self
        base = self.settings['base_path']
        origin = self.settings['public_url']
        host = urlsplit(origin).netloc
        class Handler(BaseHTTPRequestHandler):
            server_version = 'HAProxyStudio'
            sys_version = ''
            def log_message(self, *_):
                pass
            def reply(self, status, data, kind='application/json; charset=utf-8', cookie=None):
                payload = json.dumps(data).encode() if isinstance(data, (dict, list)) else data
                self.send_response(status)
                for key, value in {
                    'Content-Type': kind, 'Content-Length': str(len(payload)),
                    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
                    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                }.items():
                    self.send_header(key, value)
                if cookie:
                    self.send_header('Set-Cookie', cookie)
                self.end_headers()
                self.wfile.write(payload)
            def session(self):
                cookie = http.cookies.SimpleCookie()
                try:
                    cookie.load(self.headers.get('Cookie', ''))
                    key = cookie['studio_session'].value
                except (KeyError, http.cookies.CookieError):
                    return None, None
                with app.lock:
                    value = app.sessions.get(key)
                    user = app.accounts.get(value['user']['id']) if value else None
                    if value and value['expires'] > time.time() and user and user['enabled'] and user['generation'] == value['user']['generation']:
                        value['user'] = user
                        return key, value
                    app.sessions.pop(key, None)
                return None, None
            def data(self):
                if self.headers.get('Transfer-Encoding'):
                    raise ValueError('Неподдерживаемый формат запроса.')
                length = int(self.headers.get('Content-Length', '0'))
                if length < 0 or length > 2 * 1024 * 1024:
                    raise ValueError('Максимальный размер запроса — 2 МБ.')
                if self.headers.get_content_type() != 'application/json':
                    raise ValueError('Ожидается JSON.')
                value = json.loads(self.rfile.read(length))
                if not isinstance(value, dict):
                    raise ValueError('Ожидается JSON-объект.')
                return value
            def guarded(self, operation):
                try:
                    operation()
                except (BrokenPipeError, ConnectionResetError):
                    return
                except PermissionError as error:
                    self.reply(403, dict(error=str(error)))
                except Conflict as error:
                    self.reply(409, dict(error=str(error)))
                except (ValueError, TypeError, KeyError) as error:
                    self.reply(400, dict(error=str(error)[:1000]))
                except (OSError, subprocess.SubprocessError):
                    self.reply(503, dict(error='Операция не завершена. Проверьте настройки установки и состояние службы.'))
            def do_GET(self):
                self.guarded(self.get)
            def get(self):
                origin=app.settings['public_url']
                host=urlsplit(origin).netloc
                path = urlsplit(self.path).path
                if path == base + '/api/health':
                    return self.reply(200, dict(ok=True))
                if self.headers.get('Host') != host:
                    return self.reply(403, dict(error='Адрес не совпадает с public_url.'))
                if base and path == base:
                    query=urlsplit(self.path).query
                    self.send_response(302)
                    self.send_header('Location',base+'/' + ('?'+query if query else ''))
                    self.send_header('Content-Length','0')
                    self.send_header('Cache-Control','no-store')
                    self.end_headers()
                    return
                key, session = self.session()
                if path == base + '/api/session':
                    return self.reply(200, dict(authenticated=bool(session), csrf=session['csrf'] if session else None, user=session['user'] if session else None))
                if path.startswith(base + '/api/'):
                    if not session:
                        return self.reply(401, dict(error='Войдите в панель.'))
                    readonly = app.settings['read_only'] or session['user']['role'] != 'admin'
                    if path == base + '/api/users':
                        if session['user']['role'] != 'admin':
                            raise PermissionError('Требуется администратор.')
                        return self.reply(200, dict(users=app.accounts.list()))
                    if path == base + '/api/account':
                        return self.reply(200, dict(user=session['user']))
                    if path == base + '/api/backends':
                        return self.reply(200, app.resources.backends(readonly))
                    if path == base + '/api/services':
                        return self.reply(200, dict(app.services.catalog(), read_only=readonly))
                    if path == base + '/api/overview':
                        return self.reply(200, dict(app.engine.overview(), read_only=readonly))
                    if path == base + '/api/config':
                        raw, revision = app.engine.snapshot()
                        return self.reply(200, dict(content=mask(raw)[0], revision=revision, read_only=readonly, path=str(app.engine.config)))
                    if path == base + '/api/history':
                        return self.reply(200, app.engine.history())
                    if path == base + '/api/certificates':
                        return self.reply(200, app.resources.certificates(readonly))
                    return self.reply(404, dict(error='Раздел не найден.'))
                suffix = path[len(base):] if path.startswith(base) else None
                names = {'/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css', '/manrope.ttf': 'manrope.ttf', '/manrope-OFL.txt': 'manrope-OFL.txt', '/preserve.js': 'preserve.js', '/import.js': 'import.js', '/services.js': 'services.js', '/import-settings.js': 'import-settings.js', '/exchange.js': 'exchange.js', '/admin.js': 'admin.js', '/service-tls.js': 'service-tls.js'}
                if suffix in names:
                    file = STATIC / names[suffix]
                    content = file.read_bytes()
                    if suffix == '/':
                        content = content.replace(b'__BASE__', base.encode()).replace(b'__VERSION__', __version__.encode())
                    return self.reply(200, content, mimetypes.guess_type(file)[0] or 'application/octet-stream')
                return self.reply(404, dict(error='Страница не найдена.'))
            def do_POST(self):
                self.guarded(self.post)
            def post(self):
                origin=app.settings['public_url']
                host=urlsplit(origin).netloc
                if self.headers.get('Host') != host or self.headers.get('Origin') != origin:
                    return self.reply(403, dict(error='Откройте панель по её основному адресу.'))
                origin=app.settings['public_url']
                host=urlsplit(origin).netloc
                path = urlsplit(self.path).path
                value = self.data()
                if path == base + '/api/login':
                    password = value.get('password', '')
                    if not isinstance(password, str) or len(password) > 1024:
                        raise ValueError('Некорректный пароль.')
                    with app.lock:
                        app.failures = [t for t in app.failures if t > time.time() - 300]
                        if len(app.failures) >= 10:
                            return self.reply(429, dict(error='Слишком много попыток. Подождите пять минут.'))
                        app.failures.append(time.time())
                    user = app.accounts.authenticate(value.get('username'), password)
                    if not user:
                        return self.reply(401, dict(error='Неверное имя пользователя или пароль.'))
                    key, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                    with app.lock:
                        now = time.time()
                        for old in [k for k, v in app.sessions.items() if v['expires'] < now]:
                            app.sessions.pop(old, None)
                        app.sessions[key] = dict(csrf=csrf, expires=now + 28800, user=user)
                        app.failures.clear()
                    secure = '; Secure' if origin.startswith('https:') else ''
                    app.engine.audit('login')
                    return self.reply(200, dict(ok=True, csrf=csrf, user=user), cookie=f'studio_session={key}; Path={base}/; HttpOnly; SameSite=Strict; Max-Age=28800{secure}')
                key, session = self.session()
                if not session:
                    return self.reply(401, dict(error='Войдите в панель.'))
                if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
                    return self.reply(403, dict(error='Сессия страницы устарела. Обновите страницу.'))
                if path == base + '/api/logout':
                    with app.lock:
                        app.sessions.pop(key, None)
                        for token in [k for k, v in app.drafts.items() if v['session'] == key]:
                            app.drafts.pop(token, None)
                    return self.reply(200, dict(ok=True), cookie=f'studio_session=; Path={base}/; HttpOnly; SameSite=Strict; Max-Age=0')
                if path == base + '/api/account/password':
                    user = app.accounts.change_password(session['user']['id'], value.get('current'), value.get('password'), value.get('confirmation'))
                    with app.lock:
                        session['user'] = user
                        for old in [k for k,v in app.sessions.items() if k != key and v['user']['id'] == user['id']]:
                            app.sessions.pop(old, None)
                        app.drafts.clear()
                    app.engine.audit('password-changed', username=user['username'])
                    return self.reply(200, dict(ok=True, user=user))
                if session['user']['role'] != 'admin':
                    raise PermissionError('У вашего аккаунта доступ только для просмотра.')
                if path == base + '/api/users/manage':
                    user = app.accounts.manage(session['user']['id'], value)
                    app.engine.audit('user-' + value.get('action', 'create'), username=user['username'])
                    return self.reply(200, dict(ok=True, users=app.accounts.list()))
                if path == base + '/api/certificates/preview-rename':
                    from .certificate_names import preview as preview_certificate_name
                    checked,draft=preview_certificate_name(app.engine,value)
                    return self.reply(200,app.store_draft(checked,draft,key))
                if path == base + '/api/certificates/preview-replace':
                    checked,draft=app.resources.replace_certificate(value)
                    return self.reply(200,app.store_draft(checked,draft,key))
                if path == base + '/api/certificates/manage':
                    return self.reply(200, app.resources.manage_certificate(value))
                if path == base + '/api/backends/preview-edit':
                    checked,draft=app.resources.edit_pool(value)
                    return self.reply(200,app.store_draft(checked,draft,key))
                if path == base + '/api/backends/preview-delete':
                    checked, draft = app.resources.delete_backend(value)
                    return self.reply(200, app.store_draft(checked, draft, key))
                if path in (base + '/api/services/import/scan', base + '/api/services/import/preview'):
                    from .importer import Importer
                    importer=Importer(app.services)
                    if path.endswith('/scan'):return self.reply(200, importer.scan(value))
                    checked,draft=importer.preview(value)
                    return self.reply(200, app.store_draft(checked,draft,key))
                if path == base + '/api/compatibility/preview':
                    checked,draft=app.engine.compatibility_preview(value.get('revision'))
                    return self.reply(200,app.store_draft(checked,draft,key))
                if path == base + '/api/services/names/preview':
                    checked,draft=app.services.preview_names(value.get('revision'))
                    return self.reply(200, app.store_draft(checked,draft,key))
                if path == base + '/api/services/replace/preview':
                    from .replacement import preview as preview_replacement
                    checked,draft=preview_replacement(app.services,value.get('service'),value.get('revision'),value.get('target_id'),value.get('confirm'),value.get('keep_redirect',True))
                    return self.reply(200, app.store_draft(checked,draft,key))
                if path == base + '/api/services/starttls/preview':
                    from .starttls import preview as preview_starttls
                    checked,draft=preview_starttls(app.services,value)
                    return self.reply(200,app.store_draft(checked,draft,key))
                if path == base + '/api/services/exchange/preview':
                    from .exchange_groups import preview as preview_exchange
                    checked,draft=preview_exchange(app.services,value)
                    return self.reply(200,app.store_draft(checked,draft,key))
                if path == base + '/api/services/preview':
                    service=value.get('service', {})
                    from .services import clean as clean_services
                    existing=next((m for m in clean_services(app.engine.snapshot()[0])[1] if m['id']==service.get('id')),None)
                    if service.get('protocol')=='exchange' or existing and existing['protocol']=='exchange' or 'exchange_mail' in service:
                        from .exchange_mail import preview as preview_mail
                        checked,draft=preview_mail(app.services,service,value.get('revision'),value.get('action','upsert'))
                    else:checked, draft = app.services.preview(service, value.get('revision'), value.get('action', 'upsert'))
                    return self.reply(200, app.store_draft(checked, draft, key))
                if path == base + '/api/services/check':
                    return self.reply(200, app.services.connectivity(value.get('service', {})))
                if path == base + '/api/certificates/upload':
                    return self.reply(200, upload_certificate(app.engine, value))
                if path == base + '/api/preview':
                    checked, draft = app.engine.preview(value.get('content'), value.get('revision'), value.get('backup'))
                    app.store_draft(checked, draft, key)
                    return self.reply(200, checked)
                if path == base + '/api/apply':
                    if value.get('confirm') is not True:
                        raise ValueError('Подтвердите применение изменений.')
                    with app.lock:
                        draft = app.drafts.pop(value.get('token', ''), None)
                    if not draft or draft['session'] != key or draft['expires'] < time.time():
                        raise Conflict('Проверка устарела. Проверьте изменения повторно.')
                    return self.reply(200, app.engine.apply(draft))
                return self.reply(404, dict(error='Действие не найдено.'))
        return Handler

def main():
    import argparse
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--reset-password', action='store_true', help='Rotate credentials, then restart the service')
    group.add_argument('--check', action='store_true', help='Check settings and HAProxy version without changing state')
    args = parser.parse_args()
    os.umask(0o077)
    settings = load()
    if args.check:
        diagnostics(settings)
        return
    app = Application(settings)
    if args.reset_password:
        app.reset_password()
        print('Password updated in state_dir/initial-password. Restart the service to revoke existing sessions.')
        return
    server = ThreadingHTTPServer((settings['bind'], settings['port']), app.handler())
    server.daemon_threads = True
    notify_ready()
    print('HAProxy Studio готова. Данные: '+str(app.engine.state)+'. Пароль не выводится в журнал.', flush=True)
    server.serve_forever()
