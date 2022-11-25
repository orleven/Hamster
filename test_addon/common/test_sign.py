#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from addon import BaseAddon
from mitmproxy import http
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from datetime import datetime
from httpsig import HeaderSigner

class Addon(BaseAddon):
    """
    测试签名, 给参数签名

    pip install httpsig==1.3.0
    """
    def __init__(self):
        BaseAddon.__init__(self)
        self.name = 'TestSign'
        self.addon_type = AddonType.URL_ONCE
        self.vul_name = "测试签名",
        self.level = VulLevel.NONE,
        self.vul_type = VulType.NONE,
        self.scopen = "",
        self.description = "测试签名",
        self.impact = "",
        self.suggestions = "",
        self.mark = ""

        self.servers = [
            "localhost",
        ]
        self.app_key = 'test'
        self.app_secret = 'test'

    def request(self, flow: http.HTTPFlow):
        """server/support 请求包函数入口"""
        host = self.get_host(flow)
        method = self.get_method(flow)
        if host in self.servers and method in ['GET', 'POST']:
            path = self.get_path_no_query(flow)
            method = self.get_method(flow)
            gmt_format = '%a, %d %b %Y %H:%M:%S CST'
            data = datetime.utcnow().strftime(gmt_format)
            signature_headers = ['(request-target)', 'accept', 'date']
            auth = HeaderSigner(key_id=self.app_key, secret=self.app_secret, algorithm='hmac-sha256', headers=signature_headers)
            signed_headers_dict = auth.sign({"Date": data, "Host": host, 'Accept': 'application/json'}, method=method, path=path)
            for key, value in signed_headers_dict.items():
                flow.request.headers[key] = value
            self.log.info('Sign Success: ' + flow.request.url)
