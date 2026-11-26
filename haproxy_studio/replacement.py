"""Explicit atomic replacement of an HTTP publication by an RD Gateway/Web tunnel."""
from .core import Conflict
from .services import clean,PRESETS,overlaps

def preview(manager,data,revision,target_id,confirm,keep_redirect=True):
    if manager.engine.settings['read_only']:raise ValueError('Замена недоступна в режиме наблюдения.')
    raw,actual=manager.engine.snapshot()
    if actual!=revision:raise Conflict('Конфигурация изменилась. Обновите список сервисов.')
    if not isinstance(keep_redirect,bool):raise ValueError('Выберите, сохранять ли HTTP-перенаправление.')
    if confirm is not True:raise ValueError('Подтвердите замену существующей публикации.')
    if not isinstance(data,dict) or data.get('id'):raise ValueError('Замену выбирают при создании новой публикации RD Gateway или RD Web.')
    _,models=clean(raw);old=next((m for m in models if m['id']==target_id),None)
    if old is None:raise ValueError('Заменяемая публикация не найдена. Обновите список сервисов.')
    if PRESETS[old['protocol']][3]!='http' or old.get('http_action')=='redirect':raise ValueError('Этот мастер заменяет только существующую веб-публикацию.')
    if data.get('protocol') not in ('rdgateway','rdweb','rdwebproxy'):raise ValueError('Выберите RD Gateway или RD Web для замены веб-публикации.')
    candidate=dict(data,id=target_id,imported=False);candidate.setdefault('naming','readable')
    if old.get('allowed_ips') and not candidate.get('allowed_ips'):candidate['allowed_ips']=old['allowed_ips']
    if keep_redirect is True and old.get('redirect'):
        if old.get('path','/')!='/' and not old.get('http_redirect_all_paths'):raise ValueError('Старое HTTP-перенаправление ограничено путём. Согласуйте его отдельно перед заменой.')
        if old.get('http_exceptions'):raise ValueError('У старой публикации есть HTTP-исключения. Их нужно согласовать отдельно перед заменой.')
        for key in ('redirect','http_port','redirect_code','http_host_match','http_redirect_location','http_redirect_mode','http_redirect_all_paths'):
            if key in old:candidate[key]=old[key]
    proxy=data.get('protocol')=='rdwebproxy'
    if proxy and old.get('https_frontend') and not candidate.get('https_frontend'):candidate['https_frontend']=old['https_frontend']
    model=manager.normalize(candidate,target_id)
    old_domains=set(old.get('domains') or [old['domain']]);new_domains=set(model.get('domains',[]))
    if old_domains!=new_domains or old['port']!=model['port'] or not overlaps(old['bind_address'],model['bind_address']):raise ValueError('Для замены должны совпадать все домены и внешний порт. Для нового адреса создайте отдельный сервис.')
    checked,draft=manager.preview(candidate,revision,probe=False)
    checked['summary'].insert(0,'Заменить существующую публикацию «'+old['name']+'» на «'+model['name']+'» одной операцией.')
    if proxy:
        from .rdweb import path
        checked['summary'].append('TLS принимает HAProxy. Корень HTTPS → '+path(model)+'. Другие запросы передаются внутреннему серверу; RD Gateway этим шаблоном отдельно не настраивается.')
    else:checked['summary'].append('TLS для этого домена будет передаваться до Windows без расшифровки на HAProxy. RD Web и RD Gateway публикуются одной TLS-публикацией при общем домене.')
    if old.get('routes'):checked['summary'].append('Старые HTTP-маршруты по путям будут удалены: '+', '.join(r['path'] for r in old['routes'])+'.')
    blocked=[r['path'] for r in old.get('routes',[]) if r['action']=='deny']
    if blocked:checked['warnings'].append('Ограничения путей старой HTTP-публикации снимаются: '+', '.join(blocked)+'. Доступ к приложениям и шлюзу должен контролироваться на Windows.')
    if old.get('cookie_name'):checked['warnings'].append('Cookie-привязка старого HTTP-backend не переносится. Новый пул использует выбранную балансировку.')
    if old.get('redirect'):
        checked['summary'].append('Существующее HTTP-перенаправление '+('сохранено.' if keep_redirect is True else 'не переносится; используются настройки нового сервиса.'))
    checked['warnings'].append('Проверьте выбранный сертификат HAProxy и параметры HTTPS до Windows. Файлы сертификатов и другие публикации сохраняются.' if proxy else 'Перед применением проверьте роль RD Gateway/RD Web и сертификат публичного домена на Windows. Файлы сертификатов и другие публикации сохраняются.')
    draft['reason']='service:replace'
    return checked,draft
