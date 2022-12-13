#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.core.g import cors_queue
from lib.util.aiohttputil import ClientSession
from lib.util.cipherutil import md5


class Addon(AgentAddon):
    """
    cors扫描
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'CORS'
        self.addon_type = AddonType.HOST_ONCE
        self.vul_name = "CORS收集",
        self.level = VulLevel.INFO,
        self.vul_type = VulType.CORS,
        self.scopen = ""
        self.description = "CORS全称为Cross-Origin Resource Sharing即跨域资源共享，用于绕过SOP（同源策略）来实现跨域资源访问的一种技术。而CORS漏洞则是利用CORS技术窃取用户敏感数据。以往与CORS漏洞类似的JSONP劫持虽然已经出现了很多年，但由于部分厂商对此不够重视导致其仍在不断发展和扩散。"
        self.impact = "1. 黑客可通过钓鱼等手段窃取用户信息。"
        self.suggestions = "1. 严格校验Origin头，避免出现权限泄露。2. 不要配置Access-Control-Allow-Origin: null。3. HTTPS网站不要信任HTTP域。4. 不要信任全部自身子域，减少攻击面。5. 不要配置Origin:*和Credentials: true。 6. 增加Vary: Origin头。"
        self.mark = ""

        self.skip_scan_media_types = [
            "image", "video", "audio"
        ]
        self.skip_collect_extensions = [
            "js", "css", "ico", "png", "jpg", "video", "audio", "ttf", "jpeg", "gif", "woff",
            "map", 'woff2', 'bin', 'wav', 'md', "mp3", "vue", "jpeg"
        ]
        self.poc_domain = ".thisisatestdomain.com"
        self.poc_characters = '!@#$%^&*()_+~/*'

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

    async def prove_cors(self, keyword, method, url, data, headers):
        async with ClientSession(self.addon_path) as session:
            async with session.request(method, url, data=data, headers=headers, allow_redirects=False) as res:
                if res:
                    detail = res.headers.get('Access-Control-Allow-Origin', "")
                    if detail != "" and detail == keyword:
                        await self.save_cors(res)
                        return True
        return False

    async def save_cors(self, packet):
        """保存cors信息"""

        cors = await self.parser_packet(packet)
        if cors:
            cors["md5"] = md5('|'.join([cors.get('method'), cors.get('url')]))
            await self.put_queue(cors, cors_queue)

    async def prove(self, flow: HTTPFlow):
        if self.is_collect(flow):
            url = self.get_url(flow)
            host = self.get_host(flow)
            scheme = self.get_scheme(flow)
            method = self.get_method(flow)
            request_headers = self.get_request_headers(flow)
            response_headers = self.get_response_headers(flow)
            data = self.get_request_content(flow)

            if "Access-Control-Allow-Origin" and "Access-Control-Allow-Credentials" in response_headers.keys():
                test_headers = request_headers
                keyword = scheme + '://www' + self.poc_domain
                test_headers['Origin'] = keyword
                if not await self.prove_cors(keyword, method, url, data, test_headers):
                    keyword = scheme + '://' + host + self.poc_domain
                    test_headers['Origin'] = keyword
                    if not await self.prove_cors(keyword, method, url, data, test_headers):
                        for character in self.poc_characters:
                            keyword = scheme + '://' + host + character + self.poc_domain
                            test_headers['Origin'] = keyword
                            await self.prove_cors(keyword, method, url, data, test_headers)
