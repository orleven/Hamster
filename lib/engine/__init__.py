#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

import traceback


from lib.core.env import *
import os
import asyncio
from copy import deepcopy
from lib.core.g import conf
from lib.core.g import log
from lib.core.g import redis
from lib.core.g import rabbitmq
from lib.core.g import cache_queue
from lib.core.g import vul_queue
from lib.core.g import packet_queue
from lib.core.g import path_queue
from lib.core.g import param_queue
from lib.core.g import email_queue
from lib.core.g import cors_queue
from lib.core.g import jsonp_queue
from lib.core.enums import EngineStatus
from lib.core.enums import AddonEnable
from lib.core.enums import ScanMode
from lib.core.api import get_dnslog_recode
from lib.core.api import get_addons_file_info
from lib.core.api import get_addons_file_content
from lib.core.data import save_addon
from lib.core.data import save_engine
from lib.core.data import query_scan_black_list
from lib.core.data import query_scan_white_list
from lib.core.data import query_dict_password_list
from lib.core.data import query_dict_username_list
from lib.core.data import query_scan_time_list
from lib.core.data import query_vul_filter_list
from lib.core.data import query_engine_info_by_id
from lib.core.data import save_vul
from lib.core.data import save_email_list
from lib.core.data import save_cache_list
from lib.core.data import save_packet_list
from lib.core.data import save_path_list
from lib.core.data import save_param_list
from lib.core.data import save_cors_list
from lib.core.data import save_jsonp_list
from lib.core.data import query_addon_info_by_addon_path
from lib.core.data import delete_cache_before_day
from lib.core.data import query_cache_by_keyword
from lib.core.common import vul_filter
from lib.util.util import get_time
from lib.util.util import get_timestamp
from lib.util.util import get_time_str
from lib.util.cipherutil import md5
from lib.util.cipherutil import get_file_md5

class BaseEngine(object):
    """
    Engine 基础类
    """

    def configure_addons(self):
        """虚函数，子类实现"""

    def print_status(self):
        """虚函数，子类实现"""

    async def async_engine_info(self):
        """
        加载数据库Engine配置, 并同步
        """
        engine_info = await query_engine_info_by_id(self.id)
        if engine_info:
            self.status = EngineStatus.OK if engine_info.get("status", None) != EngineStatus.STOP else EngineStatus.STOP
            self.addon_async = engine_info.get("addon_async", True)
            self.scan_max_task_num = engine_info.get("scan_max_task_num", conf.scan.scan_max_task_num)

        self.queue_num = self.get_data_queue_size()

        update_time = get_time()
        engine = dict(id=self.id, ip=self.ip, name=self.id, update_time=update_time,
                      engine_type=self.engine_type, status=self.status, task_num=self.scanning,
                      scan_max_task_num=self.scan_max_task_num, queue_num=self.queue_num)

        await save_engine(engine)

    async def async_addon_info(self):
        """加载数据库Addon配置, 并同步"""

        for addon in self.addon_list:
            info = addon.info()
            addon_md5 = info.get("addon_md5", "")
            addon_name = info.get("addon_name", "")
            addon_type = info.get("addon_type", "")
            addon_file_name = info.get("addon_file_name", "")
            addon_path = info.get("addon_path", "")
            file_update_time = info.get("file_update_time", "")
            file_create_time = info.get("file_create_time", "")
            vul_name = info.get("vul_name", "")
            level = info.get("level", "")
            vul_type = info.get("vul_type", "")
            description = info.get("description", "")
            scopen = info.get("scopen", "")
            impact = info.get("impact", "")
            suggestions = info.get("suggestions", "")
            mark = info.get("mark", "")
            enable = info.get("enable ", AddonEnable.ENABLE)
            if addon_path:
                addon_info = await query_addon_info_by_addon_path(addon_path)
                if addon_info:
                    # 由于遵循数据库优先原则，其余字段变动不更新到数据库
                    addon_info_addon_md5 = addon_info.get("addon_md5", "")
                    addon_info_addon_name = addon_info.get("addon_name", "")
                    addon_info_file_update_time = addon_info.get("file_update_time", "")

                    # 数据库更新到内存
                    addon_info_enable = addon_info.get("enable", AddonEnable.ENABLE)
                    addon.enable = addon_info_enable

                    if addon_info_addon_md5 == addon_md5 and addon_info_addon_name == addon_name and addon_info_file_update_time == file_update_time:
                        continue

                update_time = get_time()
                addon = dict(addon_md5=addon_md5, addon_name=addon_name, addon_path=addon_path, addon_type=addon_type,
                             addon_file_name=addon_file_name, vul_name=vul_name, level=level, vul_type=vul_type,
                             description=description, scopen=scopen, impact=impact, suggestions=suggestions, file_create_time=file_create_time,
                             update_time=update_time, enable=enable, file_update_time=file_update_time, mark=mark)
                await save_addon(addon)

    async def async_addons_file_content(self, addon_path):
        """同步脚本内容"""

        content = await get_addons_file_content(addon_path, id=self.id)
        if content:
            path = os.path.join(ROOT_PATH, addon_path)
            with open(path, 'wb') as f:
                f.write(content)
            log.success(f"Async addons file content, addon_path: {addon_path}")

    async def async_addons_file_info(self):
        """同步脚本信息"""

        recode_list = await get_addons_file_info(None, self.id)
        for addon_dic in recode_list:
            addon_absolute_path = os.path.join(ROOT_PATH, addon_dic["addon_path"])
            addon_md5 = get_file_md5(addon_absolute_path)
            if addon_md5 != addon_dic["addon_md5"]:
                await self.async_addons_file_content(addon_dic["addon_path"])

    async def data_center(self):
        """数据处理中心"""

        log.info("Starting data center... ")
        while True:
            try:
                if not vul_queue.empty():
                    (vul, addon_path) = await vul_queue.get()
                    addon = await query_addon_info_by_addon_path(addon_path)
                    vul["addon_id"] = addon.get("id", "") if addon and isinstance(addon, dict) else None
                    if not vul_filter(vul):
                        await save_vul(vul)

                cache_list = []
                while not cache_queue.empty() and len(cache_list) < self.max_data_queue_num:
                    (cache, addon_path) = await cache_queue.get()
                    cache["addon_path"] = addon_path
                    cache_list.append(cache)
                if len(cache_list) > 0:
                    await save_cache_list(cache_list)

                email_list = []
                while not email_queue.empty() and len(email_list) < self.max_data_queue_num:
                    (email, addon_path) = await email_queue.get()
                    email_list.append(email)
                if len(email_list) > 0:
                    await save_email_list(email_list)

                path_list = []
                while not path_queue.empty() and len(path_list) < self.max_data_queue_num:
                    (path, addon_path) = await path_queue.get()
                    path_list.append(path)
                if len(path_list) > 0:
                    await save_path_list(path_list)

                param_list = []
                while not param_queue.empty() and len(param_list) < self.max_data_queue_num:
                    (param, addon_path) = await param_queue.get()
                    param_list.append(param)
                if len(param_list) > 0:
                    await save_param_list(param_list)

                jsonp_list = []
                while not jsonp_queue.empty() and len(jsonp_list) < self.max_data_queue_num:
                    (jsonp, addon_path) = await jsonp_queue.get()
                    jsonp_list.append(jsonp)
                if len(jsonp_list) > 0:
                    await save_jsonp_list(jsonp_list)

                cors_list = []
                while not cors_queue.empty() and len(cors_list) < self.max_data_queue_num:
                    (cors, addon_path) = await cors_queue.get()
                    cors_list.append(cors)
                if len(cors_list) > 0:
                    await save_cors_list(cors_list)

                packet_list = []
                while not packet_queue.empty() and len(packet_list) < self.max_data_queue_num:
                    (packet, addon_path) = await packet_queue.get()
                    packet_list.append(packet)
                if len(packet_list) > 0:
                    await save_packet_list(packet_list)

                await asyncio.sleep(0.1)

            except Exception as e:
                msg = str(e)
                log.error(f"Error data_center, error: {msg}")

    async def cache_center(self):
        """cache处理中心"""

        if conf.scan.scan_mode == ScanMode.CACHE:
            log.info("Starting cache center... ")
            cache_laster = dnslog_laster = get_time(0)
            while True:
                # 同步dnslog的漏洞
                temp = get_time(get_timestamp() - conf.platform.dnslog_async_time)

                if temp > dnslog_laster:
                    await self.async_dnslog_recode()
                    dnslog_laster = get_time()

                # 删除老旧缓存数据
                temp = get_time(get_timestamp() - conf.cache.cache_deal_time)
                if temp > cache_laster:
                    await delete_cache_before_day(conf.cache.cache_db_stored_day)
                    cache_laster = get_time()

                await asyncio.sleep(0.1)

    async def async_dnslog_recode(self):
        """从DNSLog同步DNS记录，并从Cache里检测是否有漏洞。"""

        try:
            dnslog_list = await get_dnslog_recode(None)
            for dnslog in dnslog_list:
                recode_domain = dnslog.get("keyword", None)
                cache = await query_cache_by_keyword(recode_domain)
                if cache:
                    vul = deepcopy(cache)
                    addon_path = vul.get("addon_path", "")
                    addon = await query_addon_info_by_addon_path(addon_path)
                    vul["detail"] = f"Add from cache, Keyword: {recode_domain}"
                    vul["addon_path"] = addon_path
                    vul["md5"] = md5('|'.join([vul.get('method'), vul.get('url'), addon_path]))
                    vul["addon_id"] = addon.get("id", "") if addon and isinstance(addon, dict) else None
                    del vul["id"]
                    del vul["keyword"]
                    await vul_queue.put((vul, addon_path))
        except Exception as e:
            msg = str(e)
            traceback.print_exc()
            log.error(f"Error async dnslog recode, error: {msg}")

    async def heartbeat(self):
        """注册引擎、心跳"""

        log.info("Starting heartbeat... ")
        laster = get_time(0)
        while True:
            temp = get_time(get_timestamp() - conf.basic.heartbeat_time)
            if temp > laster:
                laster = get_time()
                try:
                    # 加载数据库Engine配置, 并同步
                    await self.async_engine_info()

                    # 同步插件,并加载
                    if self.addon_async:
                        await self.async_addons_file_info()

                    # 配置插件，同步插件信息到数据库
                    self.configure_addons()
                    await self.async_addon_info()

                    # 加载扫描配置信息
                    conf.scan.scan_white = await query_scan_white_list()
                    conf.scan.scan_black = await query_scan_black_list()
                    conf.scan.scan_time = await query_scan_time_list()
                    conf.scan.dict_username = await query_dict_username_list()
                    conf.scan.dict_password = await query_dict_password_list()
                    conf.scan.vul_fillter = await query_vul_filter_list()

                    if MAIN_NAME != 'simple':
                        # 检查redis状态
                        if not redis or not redis.redis_conn or not await redis.ping():
                            await redis.connect()

                    if MAIN_NAME == 'agent':
                        # 切换time路由
                        await self.bind_current_time_routing_key()

                    # 打印状态
                    self.print_status()
                except Exception as e:
                    msg = str(e)
                    traceback.print_exc()
                    log.error(f"Error heartbeat, error: {msg}")
            await asyncio.sleep(0.1)

    def get_data_queue_size(self):
        """计算所有queue总和"""

        queue_num = cache_queue.qsize() + param_queue.qsize() + path_queue.qsize() + email_queue.qsize() + \
                    vul_queue.qsize() + packet_queue.qsize() + cors_queue.qsize() + jsonp_queue.qsize()

        return queue_num

    async def bind_current_time_routing_key(self):
        if rabbitmq.channel:
            set_scan_time = [] # 表中的scan_time
            total_scan_time = []  # 表中的scan_time + 内存中的scan_time

            # 表中的scan_time
            set_scan_time.append(rabbitmq.default_routing_key)
            total_scan_time.append(rabbitmq.default_routing_key)
            if conf.scan.scan_time:
                for scan_time_dic in conf.scan.scan_time:
                    start_time = scan_time_dic.get("start_time", "")
                    end_time = scan_time_dic.get("end_time", "")
                    scan_time = f'{rabbitmq.pre_name}_{start_time}_{end_time}'

                    now_time = get_time_str(fmt="%H:%M:%S")
                    if start_time < now_time < end_time:
                        total_scan_time.append(scan_time)
                        set_scan_time.append(scan_time)

            for scan_time in rabbitmq.get_routing_key_list():
                if scan_time not in total_scan_time:
                    total_scan_time.append(scan_time)

            for scan_time in total_scan_time:
                if scan_time not in rabbitmq.get_routing_key_list():
                    log.info(f"Set bind routing key: {scan_time}")
                    await rabbitmq.bind_routing_key(scan_time)
                if scan_time not in set_scan_time:
                    log.info(f"Set unbind routing key: {scan_time}")
                    await rabbitmq.unbind_routing_key(scan_time)

