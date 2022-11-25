#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from addon import BaseAddon
from mitmproxy import http
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from lib.util.cipherutil import base64decode

class Addon(BaseAddon):
    """
    测试加解密, 给body加解密， 与support/test_support_cipher.py 对应，
    request函数负责给先解密数据包，然后发送到agent扫描
    """
    def __init__(self):
        BaseAddon.__init__(self)
        self.name = 'TestServerCipher'
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
            data = base64decode(data)
            self.set_request_content(flow, data)
            self.log.info('Server request cipher Success: ' + flow.request.url)
