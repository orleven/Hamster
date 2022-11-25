#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
import json
from copy import deepcopy
from lib.core.g import log
from lib.core.g import conf
from lib.core.g import redis
from addon import BaseAddon
from lib.core.enums import AddonType
from lib.core.enums import FlowType
from lib.util.util import get_time_str
from lib.util.util import get_url_normpath_list
from lib.util.cipherutil import md5


async def handle_flow(flow, scan_list=None, addon_list=None):
    """
    flow 去重，并添加扫描队列

    :param flow: 扫描的数据包
    :param addon_list: 需要扫描的addon列表， 空为全部
    """
    method = BaseAddon.get_method(flow)
    url = BaseAddon.get_url(flow)
    url_base = BaseAddon.get_base_url(flow)
    url_no_query = BaseAddon.get_url_no_query(flow)
    status = BaseAddon.get_status(flow)

    # 替换扫描的headers，如果这里改了header，会盖掉pushtask的header
    for key, value in conf.scan.scan_headers.items():
        if isinstance(key, str) and isinstance(value, str):
            flow.request.headers[key] = value

    if addon_list:
        flow_addon_list = addon_list
    else:
        flow_addon_list = json.dumps(addon_list)


    if flow.websocket:
        # Websocket数据包
        flow_type = FlowType.WEBSOCKET

        # AddonType.URL_ONCE
        parameter_list = '&'.join(BaseAddon.get_parameter_name_list(flow))
        # 解决日志乱码问题
        if not parameter_list.isprintable():
            parameter_list = md5(parameter_list)
        flag, flow_hash = await hander_scan_list(scan_list, AddonType.WEBSOCKET_ONCE, flow_addon_list, flow_type, method, url_no_query + '?' + parameter_list)
        if flag:
            yield flow_hash, flow_addon_list, AddonType.WEBSOCKET_ONCE, flow
    else:
        # 非Websocket数据包
        flow_type = FlowType.WEB

        # AddonType.HOST_ONCE
        # 每个主机只扫一次
        flag, flow_hash = await hander_scan_list(scan_list, AddonType.HOST_ONCE, flow_addon_list, flow_type, method, url_base)
        if flag:
            yield flow_hash, flow_addon_list, AddonType.HOST_ONCE, flow

        # AddonType.URL_ONCE
        # 每个URL都扫，以参数名作为唯一标志符
        parameter_list = '&'.join(BaseAddon.get_parameter_name_list(flow))
        # 解决日志乱码问题
        if not parameter_list.isprintable():
            parameter_list = md5(parameter_list)
        flag, flow_hash = await hander_scan_list(scan_list, AddonType.URL_ONCE, flow_addon_list, flow_type, method, url_no_query + '?' + parameter_list)
        if flag:
            yield flow_hash, flow_addon_list, AddonType.URL_ONCE, flow

        # AddonType.Dir_ALL
        # 扫描父目录
        for sub_url in sorted(get_url_normpath_list(url, './'), reverse=True):
            sub_url_no_query = sub_url[:sub_url.index('?')] if '?' in sub_url else sub_url

            # 扫描目录，跳过常规url
            if '://' not in sub_url:
                continue

            flag, flow_hash = await hander_scan_list(scan_list, AddonType.DIR_ALL, flow_addon_list,  flow_type, method, sub_url_no_query)
            if flag:
                if '?' in sub_url or sub_url[-1] != '/':
                    yield flow_hash, flow_addon_list, AddonType.DIR_ALL, flow
                else:
                    sub_flow = deepcopy(flow)
                    sub_flow.request.url = sub_url
                    sub_flow.request.content = b''
                    sub_flow.response.content = b''
                    sub_flow.response.status_code = 200
                    sub_flow.response.reason = 'OK'
                    yield flow_hash, flow_addon_list, AddonType.DIR_ALL, sub_flow

        # AddonType.FILE_ONCE
        # 一个File扫一次
        flag, flow_hash = await hander_scan_list(scan_list, AddonType.FILE_ONCE, flow_addon_list, flow_type, method, url_no_query)
        if flag:
            yield flow_hash, flow_addon_list, AddonType.FILE_ONCE, flow


async def hander_scan_list(scan_list, addon_type, addon_list, flow_type, method, url):
    """处理扫描去重"""

    if scan_list is not None and isinstance(scan_list, list):
        for addon_name in addon_list:
            flow_hash = '|'.join([REDIS_SCAN_RECODE_PRIFIX, addon_type, addon_name, flow_type, method, url])
            if flow_hash not in scan_list:
                scan_list.append(flow_hash)
                return True, flow_hash
    else:
        flow_hash = '|'.join([REDIS_SCAN_RECODE_PRIFIX, addon_type, flow_type, method, url])
        try:
            if not await redis.redis_conn.exists(flow_hash):
                await redis.redis_conn.set(flow_hash, get_time_str(), ex=conf.redis.ex)
                return True, flow_hash
        except Exception as e:
            log.error(f"Error hander_scan_list, url: {url}, error: {str(e)}")
        return False, flow_hash
    return False, None
