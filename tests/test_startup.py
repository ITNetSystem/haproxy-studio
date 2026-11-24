import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from haproxy_studio.settings import DEFAULTS,load
from haproxy_studio.startup import haproxy_version,require_compatible,notify_ready

class StartupTests(unittest.TestCase):
    def test_release_detection_and_rejection(self):
        for label,expected in [('2.4.36',True),('2.8.14-c23fe91',True),('3.4.6-56332c5',True),('1.8.30',False),('2.2.34',False),('3.5.0',False),('3.4.0-dev2',False),('3.4.0-rc1',False)]:
            with self.subTest(label=label),patch('haproxy_studio.startup.subprocess.run',return_value=subprocess.CompletedProcess([],0,('HAProxy version '+label+' 2026/01/01\n').encode(),b'')):
                self.assertEqual(expected,haproxy_version('/fake/haproxy')['supported'])
                if not expected:
                    with self.assertRaises(ValueError):require_compatible('/fake/haproxy')
        with patch('haproxy_studio.startup.subprocess.run') as run:
            self.assertFalse(haproxy_version(None)['supported']);run.assert_not_called()
    def test_readonly_does_not_require_supported_binary(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'settings.json';file.write_text(json.dumps(dict(read_only=True,haproxy_binary='/nonexistent')))
            with patch('haproxy_studio.startup.require_compatible') as check:load(file);check.assert_not_called()
    def test_notify_without_systemd_is_noop(self):
        with patch.dict(os.environ,{},clear=True),patch('haproxy_studio.startup.socket.socket') as sock:
            self.assertFalse(notify_ready());sock.assert_not_called()
    def test_notify_sent_only_after_http_and_accounts_are_ready(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);receiver=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM);receiver.bind(str(root/'notify'));receiver.settimeout(10)
            config=root/'settings.json';settings=copy.deepcopy(DEFAULTS)
            settings.update(state_dir=str(root/'state'),config_file=str(root/'haproxy.cfg'),haproxy_binary='/nonexistent',read_only=True)
            with socket.socket() as free:free.bind(('127.0.0.1',0));settings['port']=free.getsockname()[1]
            config.write_text(json.dumps(settings));env=dict(os.environ,STUDIO_CONFIG=str(config),NOTIFY_SOCKET=str(root/'notify'),PYTHONDONTWRITEBYTECODE='1')
            process=subprocess.Popen([sys.executable,'-m','haproxy_studio'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                packet=receiver.recv(4096);self.assertIn(b'READY=1',packet)
                self.assertTrue((root/'state/initial-password').is_file());self.assertTrue((root/'state/users.json').is_file())
                with socket.create_connection(('127.0.0.1',settings['port']),timeout=2) as client:
                    client.sendall(b'GET /haproxy-admin/api/health HTTP/1.0\r\n\r\n');self.assertIn(b'200',client.recv(4096))
                self.assertIsNone(process.poll())
            finally:
                process.terminate();process.communicate(timeout=5);receiver.close()
    def test_check_is_nonmutating_and_does_not_print_password(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);settings=copy.deepcopy(DEFAULTS);settings.update(state_dir=str(root/'absent-state'),config_file=str(root/'missing.cfg'),haproxy_binary='/nonexistent',read_only=True)
            # A configured but missing executable is reported without creating state.
            path=root/'settings.json';path.write_text(json.dumps(settings));env=dict(os.environ,STUDIO_CONFIG=str(path),PYTHONDONTWRITEBYTECODE='1')
            result=subprocess.run([sys.executable,'-m','haproxy_studio','--check'],env=env,capture_output=True)
            self.assertEqual(0,result.returncode,result.stderr.decode());self.assertFalse((root/'absent-state').exists());self.assertIn('не изменялись',result.stdout.decode())
