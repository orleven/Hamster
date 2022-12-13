#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.core.g import packet_queue


class Addon(AgentAddon):
    """
    记录数据包扫描的数据包，并存入数据库。
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'CollectPacketWS'
        self.addon_type = AddonType.WEBSOCKET_ONCE
        self.vul_name = "WS数据包收集"
        self.level = VulLevel.NONE
        self.vul_type = VulType.NONE
        self.scopen = ""
        self.description = "将需要扫描的WS数据包进行记录。"
        self.impact = ""
        self.suggestions = ""
        self.mark = ""

    async def save_packet(self, packet):
        """保存扫描的数据包"""

        packet = await self.parser_packet(packet, more_detail_flag=True)
        if packet:
            await self.put_queue(packet, packet_queue)

    async def prove(self, flow: HTTPFlow):
        await self.save_packet(flow)
