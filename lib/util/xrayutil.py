#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import re
import os
import yaml
import random
import json
import traceback
from lib.util.cipherutil import md5
from lib.util.cipherutil import base64decode
from lib.util.cipherutil import base64encode
from lib.util.cipherutil import urlencode
from lib.util.cipherutil import urldecode
from lib.util.util import random_lowercase_digits


def import_xray_poc_file(pocs_path=None, dnslog_domain=None):
    """
       载入xray_poc
       dnslog_domain 反连用
    """

    poc_list = []
    poc_path_list = []
    if pocs_path:
        if os.path.isdir(pocs_path):
            for parent, dirnames, filenames in os.walk(pocs_path, followlinks=True):
                for each in filenames:
                    if '__init__' in each or each.startswith('.') or not each.endswith('.yml'):
                        continue
                    poc_path = os.path.join(parent, each)
                    poc_path_list.append(poc_path)
        else:
            if pocs_path.endswith('.yml'):
                poc_path_list.append(pocs_path)

        for poc_path in poc_path_list:
            poc = XrayPOC(poc_path, dnslog_domain)
            poc_list.append(poc)
    return poc_list


def load_yaml(yaml_str):
    yaml_data = yaml.safe_load(yaml_str)
    return yaml_data

def load_yaml_by_file(file_path):
    with open(file_path) as yaml_str:
        yaml_data = yaml.safe_load(yaml_str)
    return yaml_data

def xray_cel_random_int(x,y):
    return random.randint(x,y)

def xray_cel_random_lowercase(r1):
    result = ''
    s = 'qwertyuioplkjhgfdsazxcvbnm'
    for i in range(0, r1):
        result += random.choice(s)
    return result

def xray_cel_sleep(var):
    return True

def xray_cel_base64(var):
    return base64encode(var)

def xray_cel_urlencode(var):
    return urlencode(var)

def xray_cel_urldecode(var):
    return urldecode(var)

def xray_cel_reverse_wait(x):
    """注释掉"""
    return False

def xray_cel_new_reverse():
    """注释掉"""
    pass

def xray_cel_substr(message, index, len):
    return message[index:index + len]


def xray_cel_md5(message):
    return md5(message)

def xray_cel_string(message):
    return str(message)

def xray_cel_bytes(message):
    return bytes(message, encoding="utf-8")

def xray_cel_contains(target, val):
    if isinstance(val, str):
        val = bytes(val, encoding="utf-8")

    if isinstance(target, str):
        target = bytes(target, encoding="utf-8")

    if val in target:
        return True
    else:
        return False

def xray_cel_icontains(target, val):
    if isinstance(val, str):
        val = bytes(val, encoding="utf-8")

    if isinstance(target, str):
        target = bytes(target, encoding="utf-8")

    if val in target:
        return True
    else:
        return False

def xray_cel_bcontains(target, val):
    if isinstance(val, str):
        val = bytes(val, encoding="utf-8")

    if isinstance(target, str):
        target = bytes(target, encoding="utf-8")

    if val in target:
        return True
    else:
        return False

def xray_cel_bmatches(rex, target):
    """
    "root:[x*]:0:0:".bmatches(
    """
    if isinstance(target, str):
        target = bytes(target, encoding="utf-8")

    res = re.match(rex, target)
    if res:
        return res.group()

def xray_cel_bsubmatch(rex, target):
    """
    "activemq.home=(?P<home>.*?),".bsubmatch(
    """


    if isinstance(target, str):
        target = bytes(target, encoding="utf-8")

    res = re.search(rex, target)
    if res:
        return res.groupdict()



class XrayPOC:

    def __init__(self, yaml_file, dnslog_domain):

        self.yaml_file = yaml_file
        self.yaml_poc = load_yaml_by_file(yaml_file)

        self.name = "Base Xray Poc Name"
        self.detail = "Base Xray Poc Detail"


        self.set = {}  # set 参数
        self.rules = {}  # rules 集合
        self.rules_result = {}  # rules result 集合
        self.search = {}  # rules search 集合
        self.expression = {}  # expression 项目

        self.dnslog_wait = False # dnslog
        self.dnslog_domain = dnslog_domain.format(value=random_lowercase_digits())
        self.dnslog_path = random_lowercase_digits(5)

        self.get_name()
        self.get_detail()

        self.get_set()
        self.get_rules()
        self.get_expression()

    def get_name(self):
        self.name = self.yaml_poc.get("name", "")

    def get_detail(self):
        self.detail = json.dumps(self.yaml_poc.get("detail", ""))

    def get_expression(self):
        self.expression = self.yaml_poc.get("expression", {})

    def get_set(self):
        """
        获取set变量
        """
        for set_name in self.yaml_poc.get("set", {}).keys():
            set_value = self.yaml_poc.get("set", {}).get(set_name, "")
            x = set_value

            # 替换函数名称，防止与内置函数冲突
            set_value = set_value.replace("randomInt", "xray_cel_random_int")
            set_value = set_value.replace("randomLowercase", "xray_cel_random_lowercase")
            set_value = set_value.replace("urlencode", "xray_cel_urlencode")
            set_value = set_value.replace("base64", "xray_cel_base64")
            if "everse" in set_value:
                set_value = set_value.replace("newReverse", "xray_cel_new_reverse")
                set_value = set_value.replace("reverse.url.host", self.dnslog_domain)
                set_value = set_value.replace("reverse.url.path", self.dnslog_path)
                set_value = set_value.replace("reverse.url", f"http://{self.dnslog_domain}/{self.dnslog_path}")
                self.set[set_name] = set_value
                self.dnslog_wait = True
            elif "request" in set_value:
                set_value = set_value.replace("request.url.scheme", "http")
                set_value = set_value.replace("request.url.host", "127.0.0.1")
                self.set[set_name] = set_value
            else:
                # 注册变量名
                var_names = locals()
                for _set_key, _set_value in self.set.items():
                    var_names[_set_key] = _set_value
                for _search_key, _search_value in self.search.items():
                    var_names[_search_key] = _search_value

                try:
                    self.set[set_name] = eval(set_value)
                except:
                    traceback.print_exc()

    def get_rules(self):
        """
        获取rule
        """
        for rule in self.yaml_poc.get("rules", {}).keys():
            self.rules[rule] = self.yaml_poc.get("rules", {}).get(rule, "")


    def replace_request_by_var(self, content):
        """替换set的参数"""

        var_dict = {}
        var_dict.update(self.set)
        var_dict.update(self.search)

        for var_name, var_value in var_dict.items():
            if isinstance(content, bytes):
                content = content.replace(b"{{" + var_name + b"}}", var_value)
            elif isinstance(content, dict):
                for _key, _value in content.items():
                    content[_key] = self.replace_request_by_var(_value)
            elif isinstance(content, list):
                for i in content:
                    content[i] = self.replace_request_by_var(content[i])
            else:
                if isinstance(var_value, bytes):
                    var_value = str(var_value, "utf-8")
                else:
                    var_value = str(var_value)
                content = content.replace("{{" + var_name + "}}", var_value)


        return content

    def generate_request_by_rule_request(self, rule_request, method, path, headers, data, follow_redirects):
        """
        将请求根据 rule 中的规则对请求变形
        """

        if 'method' in rule_request.keys():
            method = self.replace_request_by_var(rule_request['method'])

        if 'path' in rule_request.keys():
            path = self.replace_request_by_var(rule_request['path'])

        if 'headers' in rule_request.keys():
            temp_headers = rule_request.get("headers", {})
            for key, value in temp_headers.items():
                headers[key] = self.replace_request_by_var(value)

        if 'body' in rule_request.keys():
            data = self.replace_request_by_var(rule_request['body'])

        if 'follow_redirects' in rule_request.keys():
            follow_redirects = rule_request['follow_redirects']

        return method, path, headers, data, follow_redirects

    def deal_cel(self, cel, status=0, headers=None, content=b''):
        """
        处理cel表达式
        """
        if headers is None:
            headers = {}
        content_type = headers.get("Content-Type", "")

        cel = self.replace_request_by_var(cel.strip().rstrip())

        # 替换函数名称，防止与内置函数冲突
        cel = cel.replace("string", "xray_cel_string")
        cel = cel.replace("bytes", "xray_cel_bytes")
        cel = cel.replace("md5", "xray_cel_md5")
        cel = cel.replace("substr", "xray_cel_substr")
        cel = cel.replace("sleep", "xray_cel_sleep")

        cel = re.sub('response.body.contains\S*?\((b)*', "xray_cel_contains(content, ", cel, flags=re.S)
        cel = re.sub('response.body.bcontains\S*?\((b)*', "xray_cel_bcontains(content, ", cel, flags=re.S)
        cel = re.sub('response.content_type.icontains\S*?\((b)*', "xray_cel_icontains(content_type, ", cel, flags=re.S)
        cel = re.sub('response.content_type.contains\S*?\((b)*', "xray_cel_contains(content_type, ", cel, flags=re.S)

        cel = re.sub('\".+?\"\.bsubmatch\S*?\(', lambda x: "xray_cel_bsubmatch(r" + x.group(0).rstrip(".bsubmatch(") + ", ", cel, flags=re.S)
        cel = re.sub('\".+?\"\.bmatches\S*?\(', lambda x: "xray_cel_bmatches(r" + x.group(0).rstrip(".bmatches(") + ", ", cel, flags=re.S)

        cel = cel.replace("response.headers", "headers")
        cel = cel.replace("response.status", "status")
        cel = cel.replace("response.body", "content")
        cel = cel.replace("response.body", "content")

        cel = cel.replace("reverse.wait", "xray_cel_reverse_wait")


        # 替换运算符号，防止与内置函数冲突
        cel = cel.replace("&&", " and ")
        cel = cel.replace("||", " or ")
        cel = cel.replace(" !xray", " not xray")

        # 替换 bool
        cel = cel.replace("true", "True")
        cel = cel.replace("false", "False")

        # 替换r0() - r5() 等函数名称与结果
        for rules_key, rules_value in self.rules_result.items():
            cel = cel.replace(rules_key + "()", str(rules_value))

        # 注册变量名
        var_names = locals()
        for set_key, set_value in self.set.items():
            var_names[set_key] = set_value
        for search_key, search_value in self.search.items():
            var_names[search_key] = search_value

        try:
            return eval(cel)
        except Exception as e:
            msg = str(e)
            if not ("is not defined" in msg and "name" in msg and "()" in cel):
                traceback.print_exc()
                print(f'Error eval, name: {self.name}, cel: {cel}, error : {msg}')
            return False
