#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import asyncio
import traceback
from addon.server import ServerAddon
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from lib.core.enums import AddonType

class Addon(ServerAddon):
    """
    捕获Websocket原始数据包，可作为后续的分析/扫描处理，比如通过rabbitmq推至web扫描器等。
    """

    def __init__(self):
        ServerAddon.__init__(self)
        self.name = 'ScanWS'
        self.addon_type = AddonType.WEBSOCKET_ONCE
        self.level = VulLevel.NONE
        self.vul_type = VulType.NONE
        self.vul_name = "Websocket数据包推送"
        self.scopen = ""
        self.description = "Websocket数据包推送至扫描器"
        self.impact = ""
        self.suggestions = ""
        self.mark = ""

    def websocket_message(self, flow):
        asyncio.get_event_loop().create_task(self.websocket_message_inject(flow))

    async def websocket_message_inject(self, flow):
        if self.is_scan_to_client(flow):
            await self.push_scan_queue(flow)
        else:
            url = self.get_url(flow)
            self.log.debug(f"Bypass scan websocket message flow, url: {url}, addon: {self.name}")


