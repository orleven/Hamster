#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import re
import traceback
from copy import deepcopy
from mitmproxy.http import HTTPFlow
from lib.core.data import log
from lib.core.enums import AddonType
from lib.core.enums import ParameterType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from lib.util.aiohttputil import ClientSession
from addon.agent import AgentAddon


class Addon(AgentAddon):
    """
    测试Websockett脚本
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'TestAgentAddonWS'  # 脚本名称，唯一标识
        self.addon_type = AddonType.WEBSOCKET_ONCE  # 脚本类型，对应不同扫描方式
        self.vul_name = "TestAgentWS"
        self.level = VulLevel.NONE
        self.vul_type = VulType.NONE
        self.description = ""
        self.scopen = ""
        self.impact = ""
        self.suggestions = ""
        self.mark = ""

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
                if await self.prove_test(keyword, method, url, message, headers, message_list):
                    return

    async def prove_test(self, keyword, method, url, message, headers, message_list):
        async with ClientSession(self.addon_path) as session:
            async with session.ws_connect(url, method=method, headers=headers, message_list=message_list, message=message) as ws:
                if message.is_text:
                    await ws.send_str(str(message.content, 'utf-8'))
                else:
                    await ws.send_bytes(message.content)
                if ws:
                    msg = await ws.receive_bytes()
                    if msg and bytes(keyword, "utf-8") in msg:
                        detail = f"test"
                        await self.save_vul(ws, detail)
                        return True
        return False

    async def generate_payload(self, content=None):
        yield "payload", "keyword"
