#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import requests
import sys
import time


class HTTP:
    server = None
    token = None

    @classmethod
    def get_token(cls, username, password):
        data = {'username': username, 'password': password}
        url = "/api/v1/authentication/auth/"
        res = requests.post(cls.server + url, data)
        res_data = res.json()

        if res.status_code in [200, 201] and res_data:
            token = res_data.get('token')
            cls.token = token
            print("获取 token ：" + token)
        else:
            print("获取 token 错误, 请检查输入项是否正确")
            sys.exit()

    @classmethod
    def get(cls, url, params=None, **kwargs):
        url = cls.server + url
        headers = {
            'Authorization': "Bearer {}".format(cls.token),
            'X-JMS-ORG': '00000000-0000-0000-0000-000000000002'
        }
        kwargs['headers'] = headers
        res = requests.get(url, params, **kwargs)
        return res

    @classmethod
    def post(cls, url, data=None, json=None, **kwargs):
        url = cls.server + url
        headers = {
            'Authorization': "Bearer {}".format(cls.token),
            'X-JMS-ORG': '00000000-0000-0000-0000-000000000002'
        }
        kwargs['headers'] = headers
        res = requests.post(url, data, json, **kwargs)
        return res


class User(object):

    def __init__(self):
        self.id = None
        self.name = user_name
        self.username = user_username
        self.email = user_email

    def exist(self):
        url = '/api/v1/users/users/'
        params = {'username': self.username}
        res = HTTP.get(url, params=params)
        res_data = res.json()
        if res.status_code in [200, 201] and res_data:
            self.id = res_data[0].get('id')
        else:
            self.create()

    def create(self):
        print("创建用户 {}".format(self.username))
        url = '/api/v1/users/users/'
        data = {
            'name': self.name,
            'username': self.username,
            'email': self.email,
            'is_active': True
        }
        res = HTTP.post(url, json=data)
        self.id = res.json().get('id')

    def perform(self):
        self.exist()


class Node(object):

    def __init__(self):
        self.id = None
        self.name = asset_node_name

    def exist(self):
        url = '/api/v1/assets/nodes/'
        params = {'value': self.name}
        res = HTTP.get(url, params=params)
        res_data = res.json()
        if res.status_code in [200, 201] and res_data:
            self.id = res_data[0].get('id')
        else:
            self.create()

    def create(self):
        print("创建资产节点 {}".format(self.name))
        url = '/api/v1/assets/nodes/'
        data = {
            'value': self.name
        }
        res = HTTP.post(url, json=data)
        self.id = res.json().get('id')

    def perform(self):
        self.exist()


class AdminUser(object):

    def __init__(self):
        self.id = None
        self.name = assets_admin_name
        self.username = assets_admin_username
        self.password = assets_admin_password

    def exist(self):
        url = '/api/v1/assets/admin-user/'
        params = {'username': self.name}
        res = HTTP.get(url, params=params)
        res_data = res.json()
        if res.status_code in [200, 201] and res_data:
            self.id = res_data[0].get('id')
        else:
            self.create()

    def create(self):
        print("创建管理用户 {}".format(self.name))
        url = '/api/v1/assets/admin-users/'
        data = {
            'name': self.name,
            'username': self.username,
            'password': self.password
        }
        res = HTTP.post(url, json=data)
        self.id = res.json().get('id')

    def perform(self):
        self.exist()


class Asset(object):

    def __init__(self):
        self.id = None
        self.name = asset_name
        self.ip = asset_ip
        self.platform = asset_platform
        self.protocols = asset_protocols
        self.admin_user = AdminUser()
        self.node = Node()

    def exist(self):
        url = '/api/v1/assets/assets/'
        params = {
            'hostname': self.name
        }
        res = HTTP.get(url, params)
        res_data = res.json()
        if res.status_code in [200, 201] and res_data:
            self.id = res_data[0].get('id')
        else:
            self.create()

    def create(self):
        print("创建资产 {}".format(self.ip))
        self.admin_user.perform()
        self.node.perform()
        url = '/api/v1/assets/assets/'
        data = {
            'hostname': self.ip,
            'ip': self.ip,
            'platform': self.platform,
            'protocols': self.protocols,
            'admin_user': self.admin_user.id,
            'nodes': [self.node.id],
            'is_active': True
        }
        res = HTTP.post(url, json=data)
        self.id = res.json().get('id')

    def perform(self):
        self.exist()


class SystemUser(object):

    def __init__(self):
        self.id = None
        self.name = assets_system_name
        self.username = assets_system_username

    def exist(self):
        url = '/api/v1/assets/system-users/'
        params = {'name': self.name}
        res = HTTP.get(url, params)
        res_data = res.json()
        if res.status_code in [200, 201] and res_data:
            self.id = res_data[0].get('id')
        else:
            self.create()

    def create(self):
        print("创建系统用户 {}".format(self.name))
        url = '/api/v1/assets/system-users/'
        data = {
            'name': self.name,
            'username': self.username,
            'login_mode': 'auto',
            'protocol': 'ssh',
            'auto_push': True,
            'sudo': 'All',
            'shell': '/bin/bash',
            'auto_generate_key': True,
            'is_active': True
        }
        res = HTTP.post(url, json=data)
        self.id = res.json().get('id')

    def perform(self):
        self.exist()


class AssetPermission(object):

    def __init__(self):
        self.name = perm_name
        self.user = User()
        self.asset = Asset()
        self.system_user = SystemUser()

    def create(self):
        print("创建资产授权名称 {}".format(self.name))
        url = '/api/v1/perms/asset-permissions/'
        data = {
            'name': self.name,
            'users': [self.user.id],
            'assets': [self.asset.id],
            'system_users': [self.system_user.id],
            'actions': ['all'],
            'is_active': True,
            'date_start': perm_date_start,
            'date_expired': perm_date_expired
        }
        res = HTTP.post(url, json=data)
        res_data = res.json()
        if res.status_code in [200, 201] and res_data:
            print("创建资产授权规则成功: ", res_data)
        else:
            print("创建授权规则失败: ", res_data)

    def perform(self):
        self.user.perform()
        self.asset.perform()
        self.system_user.perform()
        self.create()

class CommandExecutions(object):
    def __init__(self):
        self.asset_node_name = asset_node_name
        self.asset_ip = asset_ip



class APICreateAssetPermission(object):

    def __init__(self):
        self.jms_url = jms_url
        self.username = jms_username
        self.password = jms_password
        self.token = None
        self.server = None

    def init_http(self):
        HTTP.server = self.jms_url
        print("get_token")
        HTTP.get_token(self.username, self.password)

    def perform(self):
        self.init_http()
        self.perm = AssetPermission()
       # self.perm.perform()


if __name__ == '__main__':
    # jumpserver url 地址
    jms_url = 'http://192.168.8.96'

    # 管理员账户
    jms_username = 'admin'
    jms_password = 'qaz@wsx#zimo2021'

    # 资产节点
    asset_node_name = 'test'

    # 资产信息
    asset_name = 'zimo2_test'
    asset_ip = '120.27.225.217'
    asset_platform = 'Linux'
    asset_protocols = ['ssh/22']

    # 资产管理用户
    assets_admin_name = 'root'
    assets_admin_username = 'root'
    assets_admin_password = 'test123456'

    # 资产系统用户
    assets_system_name = 'test'
    assets_system_username = 'test'

    # 用户用户名
    user_name = '测试用户'
    user_username = 'test'
    user_email = 'test@jumpserver.org'

    # 资产授权
    perm_name = 'AutoPerm' + '_' + (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    perm_date_start = '2021-05-01 14:25:47 +0800'
    perm_date_expired = '2021-06-01 14:25:47 +0800'

    api = APICreateAssetPermission()
    api.perform()
