#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from copy import deepcopy
from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import ParameterType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from lib.util.aiohttputil import ClientSession
from addon.agent import AgentAddon


class Addon(AgentAddon):
    """
    测试脚本
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'TestAgentAddon'  # 脚本名称，唯一标识
        self.addon_type = AddonType.URL_ONCE  # 脚本类型，对应不同扫描方式
        self.vul_name = "TestAgent"
        self.level = VulLevel.NONE
        self.vul_type = VulType.NONE
        self.description = ""
        self.scopen = ""
        self.impact = ""
        self.suggestions = ""
        self.mark = ""

        self.black_media_type_list = ["image", "video", "audio"]
        self.black_ext_list = ['jpg', 'png', 'pdf', 'png', 'docx', 'doc', 'jpeg', 'xlsx', 'csv']
        self.black_headers_list = ["Cookie", "Origin", "Connection", "Accept-Encoding", "Accept-Language",
                                   "Accept", "Upgrade-Insecure-Requests", "Sec-Fetch-Site", "Sec-Fetch-Mode",
                                   "Sec-Fetch-Dest", "Sec-Fetch-User", "If-None-Match",
                                   "X-Requested-With", "Cache-Control", "content-encoding", "If-Modified-Since"]
        self.black_headers_list += [item.lower() for item in self.black_headers_list]

    async def prove(self, flow: HTTPFlow):
        """agent扫描函数入口"""

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

            # 挨个替换headers参数
            for header_key, header_value in headers.items():
                if header_key not in self.black_headers_list:
                    test_headers = deepcopy(headers)
                    async for payload, keyword in self.generate_payload():
                        test_headers[header_key] = payload
                        if await self.prove_test(keyword, method, url, data, test_headers):
                            return

            # 挨个替换path参数
            for i in range(0, len(path_component)):
                async for payload, keyword in self.generate_payload():
                    temp_path_component = deepcopy(path_component)
                    temp_path_component[i] = payload
                    temp_path = '/'.join(temp_path_component)
                    test_url = f'{base_url}{temp_path}?{query}'
                    if await self.prove_test(keyword, method, test_url, data, headers):
                        return

            # 挨个替换cookies参数
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
                    if await self.prove_test(keyword, method, url, data, test_headers):
                        return

            # 挨个替换query参数
            source_parameter_dic = self.parser_parameter(query)
            async for res_function_result in self.generate_parameter_dic_by_function(source_parameter_dic, self.generate_payload):
                temp_parameter_dic = res_function_result[0]
                keyword = res_function_result[1]
                temp_content, temp_boundary = self.generate_content(temp_parameter_dic)
                test_url = url_no_query + '?' + str(temp_content, encoding="utf-8")
                if await self.prove_test(keyword, method, test_url, data, headers):
                    return

            # 挨个替换body参数
            source_parameter_dic = self.parser_parameter(data, boundary)
            async for res_function_result in self.generate_parameter_dic_by_function(source_parameter_dic, self.generate_payload):
                temp_parameter_dic = res_function_result[0]
                keyword = res_function_result[1]
                temp_content, temp_boundary = self.generate_content(temp_parameter_dic)
                test_data = temp_content
                if await self.prove_test(keyword, method, url, test_data, headers):
                    return

            keyword = "test"

            # 当值符合条件时替换
            source_parameter_dic = self.parser_parameter(headers)
            for child_parameter_dic in self.get_parameter_list(source_parameter_dic):
                temp_parameter_dic = deepcopy(source_parameter_dic)
                child_parameter_index = child_parameter_dic.get("index", None)
                child_parameter_value = child_parameter_dic.get("value", None)
                if child_parameter_value == 'test':
                    self.update_parameter_by_index(temp_parameter_dic, child_parameter_index, None, '123456', None)
                    temp_headers, temp_boundary = self.generate_content(temp_parameter_dic)
                    await self.prove_test(keyword, method, url, data, temp_headers)

            # 通过参数名称替换全部参数值
            temp_parameter_dic = self.replace_parameter_dic_by_name(source_parameter_dic, "ticket", None, "123456")
            temp_content, temp_boundary = self.generate_content(temp_parameter_dic, boundary)
            await self.prove_test(keyword, method, url, temp_content, headers)

            # 通过参数名称挨个替换参数值
            async for temp_parameter_dic in self.generate_parameter_dic_by_name(source_parameter_dic, "ticket", None, "123456", None):
                temp_content, temp_boundary = self.generate_content(temp_parameter_dic, boundary)
                await self.prove_test(keyword, method, url, temp_content, headers)

            # 通过参数类型挨个替换参数值
            async for temp_parameter_dic in self.generate_parameter_dic_by_type(source_parameter_dic, ParameterType.JSON, None, {"a": "123456"}, ParameterType.JSON):
                temp_content, temp_boundary = self.generate_content(temp_parameter_dic, boundary)
                await self.prove_test(keyword, method, url, temp_content, headers)

    async def prove_test(self, keyword, method, url, data, headers):
        async with ClientSession(self.addon_path) as session:
            async with session.request(method, url, data=data, headers=headers, allow_redirects=False) as res:
                if res:
                    text = await res.text()
                    if text and keyword in text:
                        detail = "Test"
                        await self.save_vul(res, detail)
                        return True
        return False


    async def generate_payload(self, content=None):
        yield "payload", "keyword"
