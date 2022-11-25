#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from addon import BaseAddon
from mitmproxy import http
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from lib.util.util import random_lowercase_digits

class Addon(BaseAddon):
    """
    测试WAF, 添加 1024 * 10 长度的参数， 适用于超长数据包绕过场景
    """

    def __init__(self):
        BaseAddon.__init__(self)
        self.name = 'TestWAF'
        self.addon_type = AddonType.URL_ONCE
        self.vul_name = "测试WAF",
        self.level = VulLevel.NONE,
        self.vul_type = VulType.NONE,
        self.scopen = "",
        self.description = "测试WAF",
        self.impact = "",
        self.suggestions = "",
        self.mark = ""

        self.servers = [
            "localhost",
        ]

    def request(self, flow: http.HTTPFlow):
        """server/support 请求包函数入口"""
        host = self.get_host(flow)
        method = self.get_method(flow)
        if host in self.servers and method in ['GET', 'POST']:
            data = self.get_request_content(flow)
            boundary = self.get_request_boundary(flow)

            # 解析body参数
            source_parameter_dic = self.parser_parameter(data, boundary)

            # 添加 1024 * 10 长度的参数
            name = random_lowercase_digits(16)
            value = random_lowercase_digits(1024 * 10)
            temp_sub_parameter_dic = self.create_child_parameter(name, value)
            source_parameter_dic["value"].append(temp_sub_parameter_dic)

            # 重新生成参数
            temp_content, temp_boundary = self.generate_content(source_parameter_dic)

            # 修改flow参数即可
            self.set_request_content(flow, temp_content)
            self.log.info('Waf Success: ' + flow.request.url)

