#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
import asyncio
from lib.core.g import log
from lib.core.g import conf
from lib.core.g import redis
from lib.core.g import rabbitmq
from lib.core.g import task_queue
from lib.core.asyncpool import PoolCollector
from lib.core.enums import EngineType
from lib.core.enums import EngineStatus
from lib.engine import BaseEngine
from lib.util.util import get_host_ip


class BaseAgent(BaseEngine):
    """Agent 基础类"""

    def __init__(self):
        super().__init__()

        # Engine 属性
        self.engine_type = EngineType.BASE_AGENT
        self.id = f'{HOSTNAME}_{self.engine_type}'
        self.ip = get_host_ip()
        self.status = EngineStatus.OK


        # 加载配置
        self.addon_async = conf.basic.addon_async

        # 属性初始化
        self.max_data_queue_num = conf.basic.max_data_queue_num
        self.scan_max_task_num = conf.scan.scan_max_task_num
        self.num_workers = 500
        self.remaining = 0
        self.scanning = 0
        self.queue_num = 0
        self.dnslog_api_key = conf.platform.dnslog_api_key


    def do_scan(self, flow_hash, flow, addon):
        """虚函数，子类实现"""

    async def consumer_message(self, message):
        """虚函数，子类实现"""

    def configure_addons(self):
        """加载脚本，子类实现"""

    def print_status(self):
        """打印状态"""

        self.remaining = task_queue.qsize()
        self.queue_num = self.get_data_queue_size()
        log.info(
            f"Engine: {self.id}, Status: {self.status}, Remaining: {self.remaining}, Scanning: {self.scanning}, Queue: {self.queue_num}, Max: {self.scan_max_task_num}")

    async def put_task_queue(self, flow_hash, flow, addon):
        """推送flow到任务队列"""

        while True:
            if task_queue.empty() and self.status != EngineStatus.STOP:
                await task_queue.put((flow_hash, flow, addon))
                break
            await asyncio.sleep(0.1)

    async def listen_task(self):
        """监听任务"""

        log.info("Starting listen task... ")

        # 等待配置加载完毕
        await asyncio.sleep(30)
        while True:
            try:
                await rabbitmq.consumer(self.consumer_message)
            except Exception as e:
                msg = str(e)
                log.error(f"Error listen_task, error: {msg}")
            finally:
                await rabbitmq.close()
                await asyncio.sleep(0.1)

    async def submit_task(self, manager: PoolCollector):
        """提交任务到扫描模块"""
        log.info("Starting submit task... ")
        try:
            while True:
                self.scanning = manager.scanning_task_count + manager.remain_task_count
                if not task_queue.empty() and self.scanning < self.scan_max_task_num:
                    self.queue_num = self.get_data_queue_size()
                    if self.queue_num < self.max_data_queue_num:
                        flow_hash, flow, addon = await task_queue.get()
                        await manager.submit(self.do_scan, flow_hash, flow, addon)
                    else:
                        await asyncio.sleep(0.1)
                else:
                    await asyncio.sleep(0.1)
        except Exception as e:
            msg = str(e)
            log.error(f"Error submit_task, error: {msg}")
        finally:
            await manager.shutdown()


    async def running(self):
        """启动agent"""

        await rabbitmq.connect()
        await redis.connect()

        async with PoolCollector.create(num_workers=self.num_workers) as manager:
            asyncio.ensure_future(self.submit_task(manager))
            asyncio.ensure_future(self.listen_task())
            asyncio.ensure_future(self.data_center())
            asyncio.ensure_future(self.cache_center())
            asyncio.ensure_future(self.heartbeat())
            async for result in manager.iter():
                pass

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.running())