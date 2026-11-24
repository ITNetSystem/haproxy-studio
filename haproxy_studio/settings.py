import json
import os
from pathlib import Path
import shutil
from urllib.parse import urlsplit

DEFAULTS = {
    "bind": "127.0.0.1", "port": 9130, "base_path": "/haproxy-admin",
    "public_url": "http://127.0.0.1:9130", "state_dir": "/var/lib/haproxy-studio",
    "haproxy_binary": "auto", "config_file": "/etc/haproxy/haproxy.cfg",
    "extra_config_dir": "/etc/haproxy/conf.d", "runtime_socket": "/var/lib/haproxy/stats",
    "certificate_dir": "/etc/haproxy/certificates", "ca_bundle": "auto", "read_only": True,
    "reload_command": ["systemctl", "reload", "haproxy"],
    "health_command": ["systemctl", "is-active", "--quiet", "haproxy"],
}

def executable(value):
    if value != "auto":
        return str(value)
    found = shutil.which("haproxy")
    if found:
        return found
    for name in ("/usr/local/sbin/haproxy", "/usr/sbin/haproxy"):
        if os.access(name, os.X_OK):
            return name
    return None

def load(path=None):
    result = dict(DEFAULTS)
    path = path or os.environ.get("STUDIO_CONFIG")
    if path:
        result.update(json.loads(Path(path).read_text()))
    if not isinstance(result["read_only"], bool):
        raise ValueError("read_only must be a boolean")
    for key in ("reload_command", "health_command"):
        command = result[key]
        if not isinstance(command, list) or any(not isinstance(arg, str) or not arg for arg in command):
            raise ValueError(key + " must be an array of arguments")
    result["haproxy_binary"] = executable(result["haproxy_binary"])
    if not result["read_only"] and (not result["haproxy_binary"] or not result["reload_command"] or not result["health_command"]):
        raise ValueError("Write mode requires HAProxy binary, reload and health commands")
    if not result['read_only']:
        from .startup import require_compatible
        require_compatible(result['haproxy_binary'])
    origin = urlsplit(result["public_url"])
    if origin.scheme not in ("http", "https") or not origin.netloc or origin.path not in ("", "/") or origin.query or origin.fragment or origin.username:
        raise ValueError("public_url must be an HTTP(S) origin")
    if origin.scheme == "http" and origin.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Public access requires HTTPS; HTTP is allowed only on loopback")
    result["public_url"] = result["public_url"].rstrip("/")
    if not isinstance(result["base_path"], str) or not result["base_path"].startswith("/") or any(x in result["base_path"] for x in ("..", "?", "#", ";")):
        raise ValueError("Invalid base_path")
    result["base_path"] = result["base_path"].rstrip("/")
    return result
