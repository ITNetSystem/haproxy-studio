"""Portal entry paths are client URLs, not HTTP rewrites inside TLS passthrough."""
PATHS={'standard':'/RDWeb/','html5':'/RDWeb/webclient/','none':''}

def normalize(data,model):
    if model['protocol'] in ('rdweb','rdgateway','rdwebproxy') and 'rdweb_client' in data:
        value=data['rdweb_client']
        if not isinstance(value,str) or value not in PATHS or model['protocol'] in ('rdweb','rdwebproxy') and value=='none':raise ValueError('Выберите обычный портал RD Web или HTML5-клиент.')
        model['rdweb_client']=value
    access=data.get('rdweb_access','both')
    if access not in ('both','standard','html5'):raise ValueError('Выберите доступные интерфейсы RD Web.')
    if access!='both' and model['protocol']!='rdwebproxy':raise ValueError('Ограничение интерфейсов требует RD Web с TLS-терминацией на HAProxy. При passthrough настройте ограничения в IIS.')
    if model['protocol']=='rdwebproxy' and access!='both':
        model['rdweb_access']=access
        model['rdweb_client']=access
    if model['protocol']=='rdwebproxy':
        if model['path']!='/':raise ValueError('RD Web с редиректом HAProxy должен обслуживать весь домен: путь /.')
        model['root_redirect']=path(model)
        model['redirect_root']=True
    return model

def path(model):
    return PATHS.get(model.get('rdweb_client','standard' if model['protocol'] in ('rdweb','rdwebproxy') else 'none'),'')


def access_rules(model,condition,redirect=False):
    if model['protocol']!='rdwebproxy' or model.get('rdweb_access','both')=='both':return ''
    from .naming import acl_base
    ident=acl_base(model)+'_portal';mode=model['rdweb_access']
    # Filter decoded, case-insensitive paths. Ambiguous encodings and traversal
    # are rejected rather than interpreted differently by HAProxy and IIS.
    rules='    acl '+ident+'_unsafe path,url_dec -m sub % .. /./ //\n'
    rules+='    acl '+ident+'_unsafe path,url_dec -m end /.\n'
    rules+='    acl '+ident+"_unsafe path,url_dec -m reg '[. ](/|$)'\n"
    rules+='    acl '+ident+"_unsafe path,url_dec -m reg '[[:cntrl:]]'\n"
    rules+='    acl '+ident+"_unsafe path,url_dec -m reg '[\\\\]'\n"
    rules+='    http-request deny deny_status 403 if '+condition+' '+ident+'_unsafe\n'
    blocked='/rdweb/webclient' if mode=='standard' else '/rdweb/pages'
    rules+='    acl '+ident+'_blocked path,url_dec,lower -m str '+blocked+'\n'
    rules+='    acl '+ident+'_blocked path,url_dec,lower -m beg '+blocked+'/\n'
    rules+='    http-request deny deny_status 403 if '+condition+' '+ident+'_blocked\n'
    if mode=='html5' and not redirect:
        rules+='    http-request redirect location /RDWeb/webclient/ code 302 if '+condition+' { path,url_dec,lower -m str /rdweb /rdweb/ } { method GET HEAD }\n'
    return rules
