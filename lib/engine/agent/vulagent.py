#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
import json
import asyncio
import traceback
from lib.core.g import log, rabbitmq
from lib.core.enums import EngineType
from lib.engine.agent import BaseAgent
from lib.util.flowutil import flow_loads
from lib.util.cipherutil import base64decode
from lib.util.addonutil import import_addon_file

class VulAgent(BaseAgent):
    """
    VulAgent
    """

    def __init__(self):
        super().__init__()

        # Engine 属性
        self.engine_type = EngineType.VUL_AGENT
        self.id = f'{HOSTNAME}_{self.engine_type}'

    def configure_addons(self):
        """加载脚本，子类实现"""

        self.addon_list = [addon for addon in import_addon_file(AGENT_ADDON_PATH) if hasattr(addon, 'prove')]

    async def consumer_message(self, message):
        message_body = message.body.decode()
        try:
            message_dic = json.loads(message_body)
            flow = flow_loads(base64decode(message_dic['flow_base64_data']))
            flow_addon_type = message_dic['flow_addon_type']
            flow_hash = message_dic['flow_hash']
            flow_addon_list = None if message_dic['flow_addon_list'] is None or message_dic['flow_addon_list'] == "ALL" else json.loads(message_dic['flow_addon_list'])
        except Exception as e:
            msg = str(e)
            log.error(f"Error load message, error: {msg}")
        else:
            # 匹配addon脚本
            if flow_addon_list is None:
                addon_list = self.addon_list
            else:
                if isinstance(flow_addon_list, list):
                    addon_list = []
                    for addon_path in flow_addon_list:
                        for addon in self.addon_list:
                            if addon_path == addon.info().get("addon_path", ""):
                                addon_list.append(addon)
                                break
                else:
                    addon_list = self.addon_list

            if len(addon_list) and addon_list[0].is_scan_response(flow):
                for addon in addon_list:
                    try:
                        addon_type = addon.info().get("addon_type", None)
                        if addon_type == flow_addon_type:
                            if addon.enable:
                                await self.put_task_queue(flow_hash, flow, addon)
                            else:
                                log.info(f"Bypass addon scan, hash: {flow_hash}, addon: {addon.name}")
                    except Exception as e:
                        msg = str(e)
                        log.error(f"Error addon scan, hash: {flow_hash}, addon: {addon.name}, error: {msg}")
            else:
                log.info(f"Bypass scan response packet, hash: {flow_hash}")

    async def do_scan(self, flow_hash, flow, addon):
        """扫描函数"""

        try:
            if addon.is_scan_response(flow):
                log.info(f"Start scan, hash: {flow_hash}, addon: {addon.name}")
                res = await addon.prove(flow)
                log.info(f"Final scan, hash: {flow_hash}, addon: {addon.name}")
            else:
                log.info(f"Skip scan, hash: {flow_hash}, addon: {addon.name}")
        except (ConnectionResetError, ConnectionAbortedError, TimeoutError, asyncio.TimeoutError):
            pass
        except (asyncio.CancelledError, ConnectionRefusedError, OSError):
            pass
        except Exception:
            msg = str(traceback.format_exc())
            log.error(f"Error scan, hash: {flow_hash}, addon: {addon.name}, error: {msg}")