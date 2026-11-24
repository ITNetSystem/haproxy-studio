"""Startup diagnostics and systemd readiness using the Python standard library."""
import os
from pathlib import Path
import re
import socket
import subprocess

MINIMUM = (2, 4)
MAXIMUM = (3, 4)

def haproxy_version(binary):
    if not binary:
        return dict(version=None,supported=False,message='HAProxy не найден. В режиме наблюдения это допустимо; для управления задайте haproxy_binary.')
    try:
        result=subprocess.run([binary,'-v'],capture_output=True,timeout=10,check=False)
    except (OSError,subprocess.SubprocessError):
        return dict(version=None,supported=False,message='Не удалось запустить HAProxy: проверьте haproxy_binary и права на исполняемый файл.')
    text=(result.stdout+result.stderr).decode('utf-8','replace')
    match=re.search(r'HAProxy version (\d+)\.(\d+)\.(\d+)([^\s]*)',text)
    if result.returncode or not match:
        return dict(version=None,supported=False,message='Не удалось определить версию HAProxy через -v.')
    version=tuple(map(int,match.group(1,2,3)));label='.'.join(map(str,version))+match[4]
    supported=MINIMUM<=version[:2]<=MAXIMUM and not re.search(r'dev|rc',match[4],re.I)
    return dict(version=label,supported=supported,message='Ветка проверяется матрицей совместимости.' if supported else 'Режим управления поддерживает стабильные HAProxy 2.4–3.4. Для этой версии оставьте read_only: true.')

def require_compatible(binary):
    result=haproxy_version(binary)
    if not result['supported']:raise ValueError(result['message'])
    return result

def diagnostics(settings):
    result=haproxy_version(settings['haproxy_binary'])
    state=Path(settings['state_dir'])
    print('Режим: '+('наблюдение' if settings['read_only'] else 'управление'))
    print('HAProxy: '+(result['version'] or 'не определён')+' — '+result['message'])
    print('Основной конфиг: '+str(settings['config_file'])+' — '+('существует' if Path(settings['config_file']).is_file() else 'НЕ НАЙДЕН'))
    print('Каталог данных: '+str(state))
    print('Начальный пароль: '+str(state/'initial-password')+' — '+('файл существует (после смены пароль в нём устарел)' if (state/'initial-password').is_file() else 'файла нет; при первом запуске создаётся автоматически'))
    print('Runtime socket: '+str(settings['runtime_socket'])+' — '+('существует' if Path(settings['runtime_socket']).exists() else 'НЕ НАЙДЕН; статистика будет недоступна'))
    print('Адрес браузера: '+settings['public_url']+settings['base_path']+'/')
    print('Проверка настроек завершена. Файлы, пароли и конфигурация HAProxy не изменялись.')

def notify_ready():
    address=os.environ.get('NOTIFY_SOCKET')
    if not address:return False
    if address.startswith('@'):address='\0'+address[1:]
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as client:
        client.connect(address)
        client.sendall(b'READY=1\nSTATUS=HTTP listener and account database are ready')
    return True
