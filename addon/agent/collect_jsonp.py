#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import re
from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.core.g import jsonp_queue
from lib.util.aiohttputil import ClientSession
from lib.util.cipherutil import md5


class Addon(AgentAddon):
    """
    记录数据包jsonp，并存入数据库。
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'CollectJsonp'
        self.addon_type = AddonType.URL_ONCE
        self.vul_name = "Jsonp收集"
        self.level = VulLevel.NONE
        self.vul_type = VulType.NONE
        self.scopen = ""
        self.description = "Jsonp漏洞被广泛的应用到渗透测试的信息搜集环节，攻击者在搞定一个站点之后，可以通过xss等形式插入jsonp漏洞利用代码，从而获取到浏览网站的用户的私人信息。"
        self.impact = "1. 黑客可通过钓鱼等手段窃取用户信息。"
        self.suggestions = "json正确的http头输出尽量避免跨域的数据传输，对于同域的数据传输使用xmlhttp的方式作为数据获取的方式，依赖于javascript在浏览器域里的安全性保护数据。如果是跨域的数据传输，必须要对敏感的数据获取做权限认证。"
        self.mark = ""

        self.skip_scan_media_types = [
            "image", "video", "audio"
        ]
        self.skip_collect_extensions = [
            "js", "css", "ico", "png", "jpg", "video", "audio", "ttf", "jpeg", "gif", "woff",
            "map", 'woff2', 'bin', 'wav', 'md', "mp3", "vue", "jpeg"
        ]
        self.jsonp_string = '&callback=jsonp1&cb=jsonp2&jsonp=jsonp3&jsonpcallback=jsonp4&jsonpcb=jsonp5&jsonp_cb' \
                            '=jsonp6&call=jsonp7&jcb=jsonp8&json=jsonp9&cbk=jsonp10&jsonpCallback=jsonp11' \
                            '&jsoncallback=jsonp12&method=jsonp13&callbackStatus=jsonp14&jsonp_callback=jsonp15 '
        self.jsonp_dict = {
            'callback': 'jsonp1', 'cb': 'jsonp2', 'jsonp': 'jsonp3', 'jsonpcallback': 'jsonp4',
            'jsonpcb': 'jsonp5', 'jsonp_cb': 'jsonp6', 'call': 'jsonp7', 'jcb': 'jsonp8',
            'json': 'jsonp9', 'cbk': 'jsonp10', 'jsonpCallback': 'jsonp11', 'jsoncallback': 'jsonp12',
            'method': 'jsonp13', 'callbackStatus': 'jsonp14', 'jsonp_callback': 'jsonp15'
        }

    def is_collect(self, flow):
        """
        是否跳过数据包，不进行捕获。
        """

        method = self.get_method(flow)
        response_media_type = self.get_response_media_type(flow)
        ext = self.get_extension(flow)

        if method != "GET":
            return False

        if response_media_type in self.skip_scan_media_types:
            return False

        if ext in self.skip_collect_extensions:
            return False

        return True

    def check_jsonp(self, regex_keyword, content):
        if content:
            jsonp_pattern = regex_keyword + '\(\{.*?\}\)'
            try:
                if re.findall(jsonp_pattern, content, re.S):
                    return True
            except:
                return False
        return False

    async def save_jsonp(self, packet):
        """保存jsonp信息"""

        jsonp = await self.parser_packet(packet)
        if jsonp:
            jsonp["md5"] = md5('|'.join([jsonp.get('method'), jsonp.get('url')]))
            await self.put_queue(jsonp, jsonp_queue)

    async def prove_jsonp(self, keyword, method, url, data, headers):
        async with ClientSession(self.addon_path) as session:
            async with session.request(method, url, data=data, headers=headers, allow_redirects=False) as res:
                if res and res.status == 200:
                    text = await res.text()
                    if keyword:
                        if self.check_jsonp(keyword, text):
                            await self.save_jsonp(res)
                    else:
                        for key, value in self.jsonp_dict.items():
                            if self.check_jsonp(value, text):
                                await self.save_jsonp(res)

    async def prove(self, flow: HTTPFlow):
        if self.is_collect(flow):
            url = self.get_url(flow)
            method = self.get_method(flow)
            query = self.get_query(flow)
            headers = self.get_request_headers(flow)
            data = self.get_request_content(flow)
            body = self.get_response_text(flow)

            if query != '':
                split_params = query.split('&')
                for param in split_params:
                    if '=' in param:
                        if len(param.split('=')) == 2:
                            key, value = param.split('=')
                            if value != '' and self.check_jsonp(value, body):
                                keyword = "mYj50Np233333333"
                                test_url = url.replace(value, keyword)
                                await self.prove_jsonp(keyword, method, test_url, data, headers)

                test_url = url + self.jsonp_string
                await self.prove_jsonp(None, method, test_url, data, headers)

            else:
                test_url = url + self.jsonp_string[1:]
                await self.prove_jsonp(None, method, test_url, data, headers)
