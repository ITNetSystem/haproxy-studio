"""Non-mutating container readiness check using the configured listener and URL prefix."""
import json
import sys
import urllib.request
from .settings import load


def check(settings):
    host={'0.0.0.0':'127.0.0.1','::':'::1','*':'127.0.0.1'}.get(settings['bind'],settings['bind'])
    host='['+host+']' if ':' in host else host
    url='http://'+host+':'+str(settings['port'])+settings['base_path']+'/api/health'
    # A local readiness request must not be routed through an environment proxy.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url,timeout=3) as response:
        if response.status!=200 or json.load(response).get('ok') is not True:raise ValueError('Studio is not ready')


def main():
    try:check(load())
    except (OSError,ValueError,TypeError,AttributeError):
        print('Studio healthcheck failed',file=sys.stderr)
        raise SystemExit(1)


if __name__=='__main__':main()
