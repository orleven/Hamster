#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from addon import BaseAddon
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from lib.core.enums import AddonType
from lib.core.g import mq_queue


class ServerAddon(BaseAddon):
    """
    Addon Server类
    """

    def __init__(self):
        BaseAddon.__init__(self)
        self.name = 'ServerAddon'
        self.addon_type = AddonType.NONE
        self.level = VulLevel.NONE
        self.vul_type = VulType.NONE

    async def push_scan_queue(self, flow, addon_list=None, routing_key=None):
        """
        推送至扫描队列，进行漏洞扫描
        :param flow: flow数据包
        :param addon_list: 需要扫描的addon列表，None为扫描全部 addon.agent
        :return:
        """
        await mq_queue.put((flow, addon_list, routing_key))
