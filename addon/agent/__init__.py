#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import asyncio
from lib.core.g import log
from lib.core.g import conf
from lib.core.g import task_queue
from addon import BaseAddon
from lib.core.common import handle_flow

class AgentAddon(BaseAddon):

    def __init__(self):
        BaseAddon.__init__(self)
        self.__hash_list = []  # simple 模式去重

    async def prove(self, flow):
        """预留函数， agent扫描使用"""


    async def handle_response(self, flow):
        """处理response函数"""
        async for flow_hash, flow_addon_list, flow_addon_type, flow in handle_flow(flow, self.__hash_list, [self.name]):
            if flow_addon_list is None or (flow_addon_list and self.name in flow_addon_list):
                if self.addon_type == flow_addon_type:
                    log.info(f"Push packet to queue, flow_hash: {flow_hash}")
                    await task_queue.put((flow_hash, flow, self))

    def response(self, flow):
        """
        simple 模式使用
        :param flow:
        :return:
        """
        if self.is_scan_response(flow):
            asyncio.get_event_loop().create_task(self.handle_response(flow))
        else:
            url = self.get_url(flow)
            if self.dnslog_top_domain not in url and conf.basic.listen_domain not in url:
                log.debug(f"Bypass scan response packet, url: {url}, addon: {self.addon_path}")

    def websocket_message(self, flow):
        """
        simple 模式使用
        :param flow:
        :return:
        """

        if self.is_scan_to_client(flow):
            asyncio.get_event_loop().create_task(self.handle_response(flow))
        else:
            url = self.get_url(flow)
            if self.dnslog_top_domain not in url and conf.basic.listen_domain not in url:
                log.debug(f"Bypass scan websocket message packet, url: {url}, addon: {self.addon_path}")

    async def generate_username_dict(self):
        """
        生成爆破用户名字典
        :return: username
        """

        dict_username = [x.get("value", "") for x in conf.scan.dict_username]
        for username in dict_username:
            yield username

    async def generate_password_dict(self):
        """
        生成爆破密码字典
        :return: password
        """

        dict_password = [x.get("value", "") for x in conf.scan.dict_password]
        for password in dict_password:
            if '%user%' not in password:
                yield password

    async def generate_auth_dict(self):
        """
        生成爆破字典
        :return: username, password
        """

        dict_username = [x.get("value", "") for x in conf.scan.dict_username]
        dict_password = [x.get("value", "") for x in conf.scan.dict_password]
        for username in dict_username:
            username = username.replace('\r', '').replace('\n', '').strip().rstrip()
            for password in dict_password:
                if '%user%' not in password:
                    password = password
                else:
                    password = password.replace("%user%", username)
                password = password.replace('\r', '').replace('\n', '').strip().rstrip()
                yield username, password

                # 首位大写也爆破下
                if len(password) > 2:
                    password2 = password[0].upper() + password[1:]
                    if password2 != password:
                        yield username, password2