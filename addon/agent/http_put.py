#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.util.aiohttputil import ClientSession
from lib.util.util import random_lowercase_digits


class Addon(AgentAddon):
    """
    PUT文件上传
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'HTTPPUT'
        self.addon_type = AddonType.DIR_ALL
        self.vul_name = "PUT文件上传"
        self.level = VulLevel.MEDIUM
        self.vul_type = VulType.FILE_UPLOAD
        self.description = "PUT等可上传相关文件。"
        self.scopen = ""
        self.impact = "1. 攻击者可以上传恶意文件。"
        self.suggestions = "1. 禁止相关请求方法。"
        self.mark = ""
        self.suffix_list = [
            '',
            '/',
            '::$DATA',
            '%20'
        ]


    async def generate_payload(self, text=None):
        for suffix in self.suffix_list:
            file = random_lowercase_digits() + '.txt'
            payload = file + suffix
            yield payload, file

    async def prove(self, flow: HTTPFlow):
        url_no_query = self.get_url_no_query(flow)
        method = self.get_method(flow)
        if method in ['GET'] and url_no_query[-1] == '/':
            async with ClientSession(self.addon_path) as session:
                keyword = random_lowercase_digits(16)
                headers = self.get_request_headers(flow)
                async for payload, file in self.generate_payload():
                    url1 = url_no_query + payload
                    async with session.put(url=url1, headers=headers, data=keyword, allow_redirects=True) as res1:
                        if res1:
                            if res1.status == 200 or res1.status == 201 or res1.status == 204:
                                url2 = url_no_query + file
                                async with session.get(url=url2, headers=headers, allow_redirects=True) as res2:
                                    if res2:
                                        text2 = await res2.text()
                                        if keyword in text2:
                                            detail = text2
                                            await self.save_vul(res1, detail)
                                            return