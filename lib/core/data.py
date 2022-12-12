#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
from sqlalchemy import and_
from sqlalchemy import delete
from sqlalchemy.future import select
from sqlalchemy.dialects.mysql import insert
from lib.core.g import log
from lib.core.g import async_session
from lib.core.model import Base
from lib.core.model import Vul
from lib.core.model import Addon
from lib.core.model import Cache
from lib.core.model import Packet
from lib.core.model import Engine
from lib.core.model import DNSLog
from lib.core.model import ScanWhite
from lib.core.model import ScanBlack
from lib.core.model import VulFilter
from lib.core.model import DictPassword
from lib.core.model import DictUsername
from lib.core.model import CollectParam
from lib.core.model import CollectEmail
from lib.core.model import CollectPath
from lib.core.model import CollectCORS
from lib.core.model import CollectJsonp
from lib.core.model import ScanTime
from lib.util.util import get_time
from lib.util.util import get_timestamp


async def sql_query(model: Base, parser='to_json', condition=None, all_flag=True):
    """通用查询函数"""
    try:
        async with async_session.begin() as session:
            if condition is not None:
                stmt = select(model).where(condition)
            else:
                stmt = select(model)

            result = await session.execute(stmt)
            if all_flag:
                result = result.scalars().all()
                if result:
                    return [getattr(x, parser)() for x in result]
            else:
                result = result.scalars().first()
                if result:
                    return getattr(result, parser)()

    except Exception as e:
        msg = str(e)
        log.error(f"Error query, model: {model.__tablename__}, condition: {condition}, parser: {parser}, error: {msg}")
    return None


async def sql_delete(model: Base, condition=None):
    """通用删除函数"""
    try:
        async with async_session.begin() as session:
            if condition is not None:
                stmt = delete(model).where(condition)
            else:
                stmt = select(model)
            await session.execute(stmt)
            return True
    except Exception as e:
        msg = str(e)
        log.error(f"Error delete, model: {model.__tablename__}, condition: {condition}, error: {msg}")
    return False


async def sql_save(model: Base, data_list: list, key_update=None):
    """通用保存函数， 已存在则刷新key_update"""

    if key_update is None:
        key_update = {}

    try:
        async with async_session.begin() as session:
            stmt = insert(model).values(data_list)
            stmt = stmt.on_duplicate_key_update(key_update)
            await session.execute(stmt)
            await session.commit()
    except Exception as e:
        msg = str(e)
        log.error(
            f"Error save, model: {model.__tablename__}, data_list: {data_list}, key_update: {key_update,}, error: {msg}")
    return False


async def sql_inject(model: Base, data_list: list):
    """通用插入函数"""

    try:
        async with async_session.begin() as session:
            stmt = insert(model).values(data_list)
            await session.execute(stmt)
            await session.commit()
            return True
    except Exception as e:
        msg = str(e)
        log.error(
            f"Error inject, model: {model.__tablename__}, data_list: {data_list}, error: {msg}")
    return False


async def delete_cache_before_day(day=3):
    """删除几天前的cache记录"""

    condition = (Cache.update_time <= get_time(get_timestamp() - 60 * 60 * 24 * day))
    return await sql_delete(Cache, condition=condition)


async def query_scan_white_list():
    """查询白名单"""

    return await sql_query(model=ScanWhite)


async def query_scan_black_list():
    """查询黑名单"""

    return await sql_query(model=ScanBlack)

async def query_scan_time_list():
    """查询时间"""

    return await sql_query(model=ScanTime)

async def query_dict_password_list():
    """查询密码字典"""

    return await sql_query(model=DictPassword)


async def query_dict_username_list():
    """查询用户名字典"""

    return await sql_query(model=DictUsername)


async def query_engine_info_by_id(id):
    """查询engine信息"""

    condition = (Engine.id == id)
    return await sql_query(model=Engine, condition=condition, all_flag=False)


async def query_addon_info_list():
    """查询addon信息"""

    return await sql_query(model=Addon)


async def query_addon_info_by_addon_path(addon_path):
    """查询addon信息"""

    condition = (Addon.addon_path == addon_path)
    return await sql_query(model=Addon, condition=condition, all_flag=False)


async def query_cache_by_keyword(keyword):
    """查询cache信息"""

    if keyword:
        condition = (Cache.keyword == keyword)
        return await sql_query(model=Cache, parser="all_to_json", condition=condition, all_flag=False)
    return None


async def query_dnslog_list():
    """查询dnslog信息"""

    return await sql_query(model=DNSLog)

async def query_vul_filter_list():
    """查询时间"""

    return await sql_query(model=VulFilter)

async def query_dnslog_by_keyword(keyword):
    """查询dnslog信息"""

    if keyword:
        condition = (DNSLog.keyword == keyword)
        return await sql_query(model=DNSLog, condition=condition, all_flag=False)
    return None


async def save_email_list(email_list, key_update=None):
    """保存email"""

    if key_update is None:
        key_update = dict(update_time=get_time())

    return await sql_save(CollectEmail, email_list, key_update)


async def save_cache_list(cache_list, key_update=None):
    """保存cache"""

    if key_update is None:
        key_update = dict(update_time=get_time())

    return await sql_save(Cache, cache_list, key_update)


async def save_packet_list(packet_list, key_update=None):
    """保存packet"""

    if key_update is None:
        key_update = dict(update_time=get_time())

    return await sql_save(Packet, packet_list, key_update)

async def save_jsonp_list(jsonp_list, key_update=None):
    """保存packet"""

    if key_update is None:
        key_update = dict(update_time=get_time())

    return await sql_save(CollectJsonp, jsonp_list, key_update)


async def save_cors_list(cors_list, key_update=None):
    """保存packet"""

    if key_update is None:
        key_update = dict(update_time=get_time())

    return await sql_save(CollectCORS, cors_list, key_update)


async def save_param_list(param_list, key_update=None):
    """保存param"""

    if key_update is None:
        key_update = dict(update_time=get_time())

    return await sql_save(CollectParam, param_list, key_update)


async def save_path_list(path_list, key_update=None):
    """保存path"""

    if key_update is None:
        key_update = dict(update_time=get_time())

    return await sql_save(CollectPath, path_list, key_update)


async def save_engine(engine: dict, key_update=None):
    """保存engine"""

    if key_update is None:
        ip = engine.get("ip", None)
        status = engine.get("status", None)
        task_num = engine.get("task_num", None)
        queue_num = engine.get("queue_num", None)

        update_time = engine.get("update_time", None)
        key_update = dict(ip=ip, update_time=update_time, status=status, task_num=task_num, queue_num=queue_num)

    engine_list = [engine]
    return await sql_save(Engine, engine_list, key_update)


async def save_addon(addon: dict, key_update=None):
    """保存addon"""

    if key_update is None:
        addon_md5 = addon.get("addon_md5", None)
        addon_name = addon.get("addon_name", None)
        update_time = addon.get("update_time", None)
        file_create_time = addon.get("file_create_time", None)
        file_update_time = addon.get("file_update_time", None)
        key_update = dict(addon_md5=addon_md5, addon_name=addon_name, update_time=update_time,
                          file_update_time=file_update_time, file_create_time=file_create_time)

    addon_list = [addon]
    return await sql_save(Addon, addon_list, key_update)


async def inject_dnslog(dnslog: dict):
    """保存dnslog"""

    dnslog_list = [dnslog]
    return await sql_inject(DNSLog, dnslog_list)


async def query_vul_by_md5(md5=None):
    """查询dnslog信息"""

    condition = and_(Vul.md5 == md5)
    return await sql_query(model=Vul, parser="all_to_json", condition=condition, all_flag=False)


async def save_vul(vul: dict, key_update=None):
    """保存vul"""

    addon_path = vul.get("addon_path", None)
    method = vul.get("method", None)
    url = vul.get("url", None)
    detail = vul.get("detail", None)
    status = vul.get("response_status_code", None)
    request_content = vul.get("request_content", None)
    request_headers = vul.get("request_headers", None)

    if key_update is None:
        response_headers = vul.get("response_headers", None)
        request_content_length = vul.get("request_content_length", None)
        response_http_version = vul.get("response_http_version", None)
        response_content_length = vul.get("response_content_length", None)
        response_status_code = vul.get("response_status_code", None)
        websocket_content = vul.get("websocket_content", None)
        response_content_type = vul.get("response_content_type", None)
        response_reason = vul.get("response_reason", None)
        request_http_version = vul.get("request_http_version", None)
        websocket_type = vul.get("websocket_type", None)
        response_content = vul.get("response_content", None)

        key_update = dict(
            request_headers=request_headers, request_content_length=request_content_length,
            request_content=request_content, response_headers=response_headers,
            response_http_version=response_http_version,
            response_content_length=response_content_length, websocket_type=websocket_type,
            request_http_version=request_http_version, websocket_content=websocket_content,
            response_status_code=response_status_code, response_content_type=response_content_type,
            response_reason=response_reason, response_content=response_content,
            update_time=get_time(), detail=detail
        )

    msg = f"Found vul, vul: {addon_path}, method: {method}, url: {url}, status: {status}, headers: {request_headers}, body: {request_content}"
    log.success(msg)

    vul_list = [vul]
    await sql_save(Vul, vul_list, key_update)



