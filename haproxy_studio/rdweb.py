"""Portal entry paths are client URLs, not HTTP rewrites inside TLS passthrough."""
PATHS={'standard':'/RDWeb/','html5':'/RDWeb/webclient/','none':''}

def normalize(data,model):
    if model['protocol'] in ('rdweb','rdgateway') and 'rdweb_client' in data:
        value=data['rdweb_client']
        if not isinstance(value,str) or value not in PATHS or model['protocol']=='rdweb' and value=='none':raise ValueError('Выберите обычный портал RD Web или HTML5-клиент.')
        model['rdweb_client']=value
    return model

def path(model):
    return PATHS.get(model.get('rdweb_client','standard' if model['protocol']=='rdweb' else 'none'),'')
