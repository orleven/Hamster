#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from addon import BaseAddon
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel

class Addon(BaseAddon):
    """
    测试脚本, 替换Websocket某个字符串
    """

    def __init__(self):
        BaseAddon.__init__(self)
        self.name = 'TestWebsocket'
        self.addon_type = AddonType.URL_ONCE
        self.level = VulLevel.NONE,
        self.vul_type = VulType.NONE,
        self.scopen = "",
        self.description = "测试加解密",
        self.impact = "",
        self.suggestions = "",
        self.mark = ""

        self.servers = [
            "localhost",
        ]

    def websocket_message(self, flow):
        """server/support websoocket入口"""

        host = self.get_host(flow)
        if host in self.servers:
            last_message = flow.websocket.messages[-1]
            if flow.websocket and last_message.from_client:
                flow.websocket.messages[-1] = bytes(str(flow.websocket.messages[-1].content, 'utf-8').replace('test', 'test123'), 'utf-8')

