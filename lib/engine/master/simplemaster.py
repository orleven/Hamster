#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import traceback
from lib.core.env import *
import asyncio
from mitmproxy.addons import asgiapp
from lib.engine.master import BaseMaster
from lib.core.asyncpool import PoolCollector
from lib.core.g import conf
from lib.core.g import log
from lib.core.g import task_queue
from lib.hander import app
from lib.core.enums import EngineType

class SimpleMaster(BaseMaster):
    """
    Simple Master为测试模块
    """

    def __init__(self):
        super().__init__()

        # Engine 属性
        self.engine_type = EngineType.SIMPLE_MASTER
        self.id = f'{HOSTNAME}_{self.engine_type}'

        # 属性初始化
        self.num_workers = 500
        self.addon_list = []
        if conf.scan.test:
            self.addon_top_path_list = [TEST_ADDON_PATH]
        else:
            self.addon_top_path_list = [AGENT_ADDON_PATH, COMMON_ADDON_PATH]

        # 加载配置
        self.options.listen_host = conf.simple.listen_host
        self.options.listen_port = conf.simple.listen_port

        # 加载测试配置
        self.addons.add(asgiapp.WSGIApp(app, conf.basic.listen_domain, 80))


    def hook(self):
        """运行相关伴随线程"""

        # dnslog
        asyncio.ensure_future(self.init_dnslog())

        # 启动心跳
        asyncio.ensure_future(self.heartbeat())

        # 数据处理
        asyncio.ensure_future(self.data_center())

        # 缓存处理
        asyncio.ensure_future(self.cache_center())

        # 任务处理
        asyncio.ensure_future(self.task_center())



    def print_status(self):
        """打印状态"""

        self.remaining = task_queue.qsize()
        self.queue_num = self.get_data_queue_size()
        log.info(f"Remaining: {self.remaining}, Scanning: {self.scanning}, Queue: {self.queue_num}, Max: {self.scan_max_task_num}")


    async def task_center(self):
        async with PoolCollector.create(num_workers=self.num_workers) as manager:
            asyncio.ensure_future(self.submit_task(manager))
            async for result in manager.iter():
                pass

    async def submit_task(self, manager: PoolCollector):
        """提交任务到扫描模块"""
        log.info("Starting submit task... ")
        try:
            while True:
                await asyncio.sleep(0.1)
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

    async def do_scan(self, flow_hash, flow, addon):
        """扫描函数"""

        try:
            log.info(f"Start scan, hash: {flow_hash}, addon: {addon.name}")
            res = await addon.prove(flow)
            log.info(f"Final scan, hash: {flow_hash}, addon: {addon.name}")
        except (ConnectionResetError, ConnectionAbortedError, TimeoutError, asyncio.TimeoutError):
            pass
        except (asyncio.CancelledError, ConnectionRefusedError, OSError):
            pass
        except Exception:
            msg = str(traceback.format_exc())
            log.error(f"Error scan, hash: {flow_hash}, addon: {addon.name}, error: {msg}")