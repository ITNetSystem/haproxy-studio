"""Checked, local-only publication of Studio. No weakening of browser checks."""
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import urlsplit
from .core import Conflict

def local_target(settings,model):
    servers=model.get('backends',[])
    if len(servers)!=1 or servers[0]['port']!=settings['port']:return False
    host=servers[0]['host'];bind=settings['bind']
    loopback=('localhost','127.0.0.1','::1')
    return host==bind or host in loopback and bind in loopback+('0.0.0.0','::')

def prepare(engine,model,data):
    if model['protocol']!='studio':
        if local_target(engine.settings,model) and model.get('domain') and model['tls_mode']=='terminate' and 'https://'+model['domain']+(':'+str(model['port']) if model['port']!=443 else '')!=engine.settings['public_url']:raise ValueError('Обнаружена публикация самой панели с другим публичным адресом. Выберите тип «HAProxy Studio — эта панель», чтобы проверить base_path и смену public_url.')
        return None
    base=engine.settings['base_path'] or '/'
    if model['path']!=base or model['strip_prefix'] or model['upstream_tls'] or model['proxy_protocol']:
        raise ValueError('Публикация Studio: сохраните base_path, HTTP до локальной панели, без удаления префикса и PROXY protocol.')
    if not local_target(engine.settings,model):
        raise ValueError('Публикация этой Studio должна вести на её настроенные bind и port.')
    origin='https://'+model['domain']+(':'+str(model['port']) if model['port']!=443 else '')
    if origin==engine.settings['public_url']:return None
    if not data.get('update_public_url'):raise ValueError('Подтвердите смену public_url на '+origin+'. После применения войдите в панель по новому адресу.')
    path=engine.settings.get('_config_path')
    if not path or not Path(path).is_file():raise ValueError('Для смены public_url запустите Studio с STUDIO_CONFIG, указывающим на постоянный JSON-файл.')
    raw=Path(path).read_bytes();value=json.loads(raw)
    if value.get('public_url',engine.settings['public_url'])!=engine.settings['public_url']:raise Conflict('Настройки Studio изменены вне панели; перезапустите службу перед публикацией.')
    return dict(origin=origin,path=path,previous=raw)

def probe(engine):
    import http.client
    host=engine.settings['bind']
    if host in ('0.0.0.0','::'):host='127.0.0.1' if host=='0.0.0.0' else '::1'
    for suffix in ('/api/health','/'):
        client=http.client.HTTPConnection(host,engine.settings['port'],timeout=3)
        try:
            client.request('GET',engine.settings['base_path']+suffix,headers={'Host':urlsplit(engine.settings['public_url']).netloc})
            response=client.getresponse();response.read(1024)
            if response.status!=200:raise ValueError('Локальный API или интерфейс Studio не прошёл проверку доступности.')
        finally:client.close()

def install(engine,change):
    probe(engine)
    path=Path(change['path'])
    if path.read_bytes()!=change['previous']:raise Conflict('Настройки Studio изменены после предварительного просмотра.')
    value=json.loads(change['previous']);value['public_url']=change['origin']
    fd,name=tempfile.mkstemp(prefix='.studio-settings-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write((json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode());stream.flush();os.fsync(stream.fileno())
        info=path.stat();os.chmod(name,info.st_mode);os.chown(name,info.st_uid,info.st_gid);os.replace(name,path)
    finally:Path(name).unlink(missing_ok=True)
    engine.settings['public_url']=change['origin']
