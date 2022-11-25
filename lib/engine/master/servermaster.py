#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import traceback
from lib.core.env import *
import json
import asyncio
from mitmproxy.addons import asgiapp
from lib.engine.master import BaseMaster
from lib.core.g import log
from lib.core.g import conf
from lib.core.g import mq_queue
from lib.core.g import redis
from lib.core.g import rabbitmq
from lib.hander import app
from lib.core.common import handle_flow
from lib.core.enums import EngineType
from lib.util.flowutil import flow_dumps
from lib.util.cipherutil import base64encode

class ServerMaster(BaseMaster):
    """
    Server Master为主代理监听模块
    """

    def __init__(self):
        super().__init__()

        # Engine 属性
        self.engine_type = EngineType.SERVER_MASTER
        self.id = f'{HOSTNAME}_{self.engine_type}'

        # 属性初始化
        self.addon_list = []
        self.addon_top_path_list = [SERVER_ADDON_PATH, COMMON_ADDON_PATH]

        # 加载配置
        self.options.listen_host = conf.server.listen_host
        self.options.listen_port = conf.server.listen_port
        self.addons.add(asgiapp.WSGIApp(app, conf.basic.listen_domain, 80))

    def hook(self):
        """运行相关伴随线程"""

        # 加载配置
        self.configure_addons()

        # 启动心跳
        asyncio.ensure_future(self.heartbeat())

        # 启动任务推送
        asyncio.ensure_future(self.task_center())



    async def task_center(self):
        """直接调用mitm的线程，容易造成mysql链接阻塞，因此需要单独线程推送数据包到消息队列"""

        log.info("Starting task center... ")
        await rabbitmq.connect()
        await redis.connect()

        while True:
            try:
                if not mq_queue.empty():
                    (flow, addon_list, routing_key) = await mq_queue.get()
                    await self.handle_task(flow, addon_list, routing_key)
                else:
                    await asyncio.sleep(0.1)
            except Exception as e:
                msg = str(e)
                traceback.print_exc()
                log.error(f"Error listener center, error: {msg}")



    async def handle_task(self, flow, addon_list=None, routing_key=None):
        """
        flow 去重，并添加扫描队列
        :param flow: 扫描的数据包
        :param addon_list: 需要扫描的addon列表， 空为全部
        """

        async for flow_hash, flow_addon_list, flow_addon_type, flow in handle_flow(flow, None, addon_list):
            message = {
                'flow_addon_list': flow_addon_list,
                'flow_addon_type': flow_addon_type,
                'flow_hash': flow_hash,
                'flow_base64_data': base64encode(flow_dumps(flow))
            }
            await self.push_data_to_mq(message, routing_key)


    async def push_data_to_mq(self, data, routing_key=None):
        """推送至扫描队列"""

        if routing_key and not routing_key.startswith(rabbitmq.pre_name):
            routing_key = f'{rabbitmq.pre_name}_{routing_key}'
        else:
            routing_key = rabbitmq.default_routing_key

        flow_hash = data['flow_hash']
        try:
            message = json.dumps(data).encode("utf-8")
            await rabbitmq.publish(message, routing_key=routing_key)
            log.info(f"Push packet to mq, flow_hash: {flow_hash}, routing_key: {routing_key}")
        except:
            log.error(f"Error push packet to flow_hash, hash: {flow_hash}, routing_key: {routing_key}")