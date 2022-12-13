#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import re
from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.util.aiohttputil import ClientSession

class Addon(AgentAddon):
    """
    敏感文件泄露扫描
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'DirectoryList'
        self.addon_type = AddonType.DIR_ALL
        self.vul_name = "目录列表显示漏洞"
        self.level = VulLevel.LOWER
        self.vul_type = VulType.INFO
        self.description = "由于错误配置导致服务器存在目录列表显示问题。"
        self.scopen = ""
        self.impact = "1. 利用该漏洞，可以遍历当前目录所有文件信息。"
        self.suggestions = "1. 修改配置以解决此问题。"
        self.mark = ""

    async def prove(self, flow: HTTPFlow):
        url_no_query = self.get_url_no_query(flow)
        method = self.get_method(flow)
        if method in ['GET'] and url_no_query[-1] == '/':
            async with ClientSession(self.addon_path) as session:
                headers = self.get_request_headers(flow)
                async with session.get(url=url_no_query, headers=headers, allow_redirects=False) as res:
                    if res and res.status == 200:
                        content = await res.text()
                        flag = False
                        if '<title>Index of' in content and '<h1>Index of' in content:
                            flag = True
                        if '<title>Directory listing' in content:
                            flag = True
                        if '[To Parent Directory]</A>' in content and '</H1><hr>' in content:
                            flag = True
                        if '.bash_history' in content and ".bash_profile" in content:
                            flag = True
                        if 'etc' in content and "var" in content and 'sbin' in content and 'tmp' in content:
                            flag = True

                        test_num = 0
                        lines = re.findall('<a href="(.*)">(.*)</a>', content, re.IGNORECASE)
                        for href, value in lines:
                            if href == value:
                                test_num += 1
                            if test_num > 3:
                                flag = True
                                break

                        if flag:
                            detail = content
                            await self.save_vul(res, detail)

