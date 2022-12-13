#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.util.aiohttputil import ClientSession
from lib.util.cipherutil import base64encode

class Addon(AgentAddon):
    """
    HTTP Basic Auth Burst
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'HTTPBasicAuthBurst'
        self.addon_type = AddonType.DIR_ALL
        self.vul_name = "HTTPBasic弱口令"
        self.level = VulLevel.MEDIUM
        self.vul_type = VulType.WEAKPASS
        self.description = "HTTPBasic认证是一种比较常见的认证方式，但这种认证方式容易被暴力破解，一旦系统存在弱口令账户，攻击者可直接登陆系统。"
        self.impact = "1. 登陆系统，进行进一步攻击，甚至获取服务器权限。"
        self.scopen = ""
        self.mark = ""
        self.file_list = [
            "",
            "manager/html",
            "host-manager/html",
        ]

    async def prove(self, flow: HTTPFlow):
        url_no_query = self.get_url_no_query(flow)
        method = self.get_method(flow)
        if method in ['GET'] and url_no_query[-1] == '/':
            async with ClientSession(self.addon_path) as session:
                headers = self.get_request_headers(flow)
                for file in self.file_list:
                    url = url_no_query + file
                    async with session.get(url=url, headers=headers, allow_redirects=False) as res:
                        try:
                            text = await res.text()
                            if res and (
                                # HTTP basic auth
                                (res.status == 401 and 'WWW-Authenticate' in res.headers.keys()) or

                                # Spring Security Application
                                (text and res.status == 200 and "Full authentication is required to access this resource" in text)
                            ):
                                async for (username, password) in self.generate_auth_dict():
                                    key = base64encode(bytes(":".join([username, password]), 'utf-8'))
                                    headers["Authorization"] = 'Basic %s' % key
                                    async with session.get(url=url, headers=headers) as res1:
                                        if res1:
                                            if res1.status != 401:
                                                detail = username + "/" + password
                                                await self.save_vul(res1, detail)
                                                return

                        except:
                            pass