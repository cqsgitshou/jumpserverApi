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


class AssetsAssets(object):

    def __init__(self):
        self.asset_ip = asset_ip
        self.asset_name = asset_name
        self.asset_id = None

    def get(self):
        print('/api/v1/assets/assets/')
        url = '/api/v1/assets/assets/'
        params = {'ip': self.asset_ip,
                  'hostname': self.asset_name}
        res = HTTP.get(url, params)
        res_data = res.json()
        print(res_data)
        if res.status_code in [200, 201] and res_data:
            self.asset_id = res_data[0].get('id')
            print(res_data[0].get('id'))


class CommandExecutions(object):
    def __init__(self):
        self.asset_node_name = asset_node_name
        self.asset_ip = asset_ip
        self.command = command
        self.run_as = run_as

    def create(self, asset_id):
        print("创建执行命令 ", self.asset_ip)
        url = '/api/v1/ops/command-executions/'
        data = {
            'command': self.command,
            'run_as': self.run_as,
            'hosts': [asset_id]
        }
        res = HTTP.post(url, json=data)
        res_data = res.json()
        if res.status_code in [200, 201] and res_data:
            print("创建执行命令成功: ", res_data)
            print("创建执行命令成功: ", res_data.get('id'))
            print("创建执行命令成功: ", res_data.get("result"))
        else:
            print("创建执行命令失败: ", res_data)

    def get(self):
        url = '/api/v1/ops/command-executions/'
        params = {

        }
        res = HTTP.get(url, params)
        res_data = res.json()
        print(res_data)
        if res.status_code in [200, 201] and res_data:
            print(res_data[0].get('id'))


class APICreateAssetPermission(object):

    def __init__(self):
        self.jms_url = jms_url
        self.username = jms_username
        self.password = jms_password
        self.token = None
        self.server = None
        self.asset = AssetsAssets()
        self.perm = CommandExecutions()

    def init_http(self):
        HTTP.server = self.jms_url
        print("get_token")
        HTTP.get_token(self.username, self.password)

    def perform(self):
        self.init_http()
        self.asset.get()
        self.perm.create(self.asset.asset_id)


if __name__ == '__main__':
    # jumpserver url 地址
    jms_url = 'http://192.168.8.96'

    # 管理员账户
    jms_username = 'admin'
    jms_password = ''

    matrix = sys.argv[1].split(',')

    print(matrix)
    # 资产节点 test
    asset_node_name = matrix[0]
    print(asset_node_name)
    # 资产信息 zimo2_test
    asset_name = matrix[1]
    print(asset_name)
    # '120.27.225.217'
    asset_ip = matrix[2]
    print(asset_ip)
    # "docker stop zcs"
    command = matrix[3]
    print(command)
    run_as = '7c19edf4-24eb-4fa4-9186-7fe857c074e9'
    api = APICreateAssetPermission()
    api.perform()
