"""Persistent local accounts with legacy migration and session generations."""
from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time

ROLES = ('admin', 'viewer')

def password_record(password):
    if not isinstance(password,str) or not 12<=len(password)<=1024:
        raise ValueError('Новый пароль должен содержать от 12 до 1024 символов.')
    salt=secrets.token_bytes(16)
    return dict(salt=salt.hex(),digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,310000).hex(),iterations=310000)

def verifies(record,password):
    if not isinstance(password,str) or len(password)>1024:return False
    candidate=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(record['salt']),record.get('iterations',310000)).hex()
    return hmac.compare_digest(candidate,record['digest'])

def public(user):
    return {key:user[key] for key in ('id','username','role','enabled','generation','created')}

class Accounts:
    def __init__(self,state):
        self.state=Path(state);self.file=self.state/'users.json';self.lock=threading.RLock()
        with self.transaction() as users:
            if users is None:
                old=json.loads((self.state/'auth.json').read_text())
                users=[dict(id=secrets.token_hex(16),username='admin',role='admin',enabled=True,generation=1,created=time.time(),**old)]
                self.write(users)
    @contextmanager
    def transaction(self):
        with self.lock:
            fd=os.open(self.state/'users.lock',os.O_CREAT|os.O_RDWR,0o600)
            with os.fdopen(fd,'a') as guard:
                fcntl.flock(guard,fcntl.LOCK_EX)
                yield json.loads(self.file.read_text())['users'] if self.file.exists() else None
    def write(self,users):
        temporary=self.state/('users-'+secrets.token_hex(8)+'.tmp')
        fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        try:
            with os.fdopen(fd,'w') as stream:
                json.dump(dict(schema=1,users=users),stream);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,self.file)
            directory=os.open(self.state,os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
        finally:temporary.unlink(missing_ok=True)
    def list(self):
        with self.transaction() as users:return [public(user) for user in users]
    def get(self,user_id):
        with self.transaction() as users:
            found=next((u for u in users if u['id']==user_id),None)
            return public(found) if found else None
    def authenticate(self,username,password):
        username=username.strip().lower() if isinstance(username,str) else ''
        with self.transaction() as users:
            user=next((u for u in users if u['username']==username),None)
            target=user or users[0]
            valid=verifies(target,password)
            return public(user) if user and user['enabled'] and valid else None
    def change_password(self,user_id,current,new,confirmation):
        if new!=confirmation:raise ValueError('Новый пароль и повтор не совпадают.')
        credential=password_record(new)
        with self.transaction() as users:
            user=next((u for u in users if u['id']==user_id),None)
            if not user or not user['enabled'] or not verifies(user,current):raise ValueError('Текущий пароль неверен.')
            user.update(credential);user['generation']+=1;self.write(users);return public(user)
    def manage(self,actor_id,data):
        action=data.get('action','create')
        with self.transaction() as users:
            actor=next((u for u in users if u['id']==actor_id and u['enabled'] and u['role']=='admin'),None)
            if not actor:raise PermissionError('Требуется администратор.')
            if action=='create':
                username=data.get('username','')
                if not isinstance(username,str):raise ValueError('Некорректный логин.')
                username=username.strip().lower()
                if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{1,63}',username):raise ValueError('Логин: 2–64 латинских символа, цифры, точка, дефис или _.')
                if any(u['username']==username for u in users):raise ValueError('Пользователь с таким логином уже существует.')
                role=data.get('role','viewer')
                if role not in ROLES:raise ValueError('Выберите допустимый уровень доступа.')
                user=dict(id=secrets.token_hex(16),username=username,role=role,enabled=True,generation=1,created=time.time(),**password_record(data.get('password')))
                users.append(user)
            else:
                user=next((u for u in users if u['id']==data.get('id')),None)
                if not user:raise ValueError('Пользователь не найден.')
                if action=='delete':
                    if data.get('confirm') is not True:raise ValueError('Подтвердите удаление пользователя.')
                    if user['id']==actor_id:raise ValueError('Нельзя удалить свой текущий аккаунт.')
                    users.remove(user)
                elif action=='update':
                    if user['id']==actor_id and data.get('password'):raise ValueError('Смените свой пароль в разделе «Мой аккаунт» с подтверждением текущего пароля.')
                    role=data.get('role',user['role']);enabled=data.get('enabled',user['enabled'])
                    if role not in ROLES or not isinstance(enabled,bool):raise ValueError('Некорректные права или состояние аккаунта.')
                    if user['id']==actor_id and (role!='admin' or not enabled):raise ValueError('Нельзя отключить или понизить свой текущий аккаунт.')
                    user.update(role=role,enabled=enabled)
                    if data.get('password'):user.update(password_record(data['password']))
                    user['generation']+=1
                else:raise ValueError('Неизвестное действие с пользователем.')
            if not any(u['enabled'] and u['role']=='admin' for u in users):raise ValueError('Должен остаться хотя бы один включённый администратор.')
            self.write(users);return public(user)
    def recover_admin(self,password):
        record=password_record(password)
        with self.transaction() as users:
            user=next((u for u in users if u['username']=='admin'),None)
            if user:user.update(record,role='admin',enabled=True,generation=user['generation']+1)
            else:users.append(dict(id=secrets.token_hex(16),username='admin',role='admin',enabled=True,generation=1,created=time.time(),**record))
            self.write(users)
