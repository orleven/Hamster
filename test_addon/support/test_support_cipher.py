#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from addon import BaseAddon
from mitmproxy import http
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from lib.util.cipherutil import base64decode
from lib.util.cipherutil import base64encode

class Addon(BaseAddon):
    """
    测试加解密, 给body加解密， 与server/test_server_cipher.py 对应，
    request 函数 负责给agent的数据包加密， 便于漏洞扫描，
    response函数，看实际情况评估是否需要解密
    """
    def __init__(self):
        BaseAddon.__init__(self)
        self.name = 'TestSupportCipher'
        self.addon_type = AddonType.URL_ONCE
        self.vul_name = "测试加解密",
        self.level = VulLevel.NONE,
        self.vul_type = VulType.NONE,
        self.scopen = "",
        self.description = "测试加解密",
        self.impact = "",
        self.suggestions = "",
        self.mark = ""

        self.servers = [
            "localhost",
        ]

    def request(self, flow: http.HTTPFlow):
        """解码请求包"""
        host = self.get_host(flow)
        method = self.get_method(flow)
        if host in self.servers and method in ['GET', 'POST']:
            data = self.get_request_content(flow)
            data = base64encode(data)
            data = bytes(base64encode(data), 'utf-8')
            self.set_request_content(flow, data)
            self.log.info('Support request ipher Success: ' + flow.request.url)

    # def response(self, flow: http.HTTPFlow):
    #     """解码返回包"""
    #     host = self.get_host(flow)
    #     method = self.get_method(flow)
    #     if host in self.servers and method in ['GET', 'POST']:
    #         data = self.get_response_content(flow)
    #         data = base64decode(data)
    #         self.set_response_content(flow, data)
    #         self.log.info('Support reponse Cipher Success: ' + flow.request.url)