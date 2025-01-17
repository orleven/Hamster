#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
import json
from lib.core.g import log
from lib.core.g import conf
from lib.core.enums import ApiStatus
from lib.core.data import inject_dnslog
from lib.core.data import query_dnslog_by_keyword
from lib.util.util import get_timestamp
from lib.util.util import get_time
from lib.util.util import get_time_by_str
from lib.core.g import interactsh_client
from lib.util.aiohttputil import ClientSession


async def get_addons_file_content(addon_path, id=""):
    """请求脚本内容"""

    if 'agent' in MAIN_NAME:
        api_url = conf.agent.api_url
        proxy = conf.agent.api_proxy
    elif 'support' in MAIN_NAME:
        api_url = conf.support.api_url
        proxy = conf.support.api_proxy
    elif 'simple' in MAIN_NAME:
        api_url = conf.simple.api_url
        proxy = conf.simple.api_proxy
    else:
        api_url = conf.server.api_url
        proxy = conf.server.api_proxy
    url = api_url + "/api/addon/async?t=" + str(int(get_timestamp()))
    headers = {
        'API-Key': id,
        'User-Agent': conf.basic.user_agent
    }
    json_dic = {"addon_path": addon_path}
    msg = "response is null."
    try:
        async with ClientSession(None) as session:
            async with session.post(url, headers=headers, json=json_dic, proxy=proxy, allow_redirects=False) as res:
                if res and res.status == 200:
                    content = await res.read()
                    if content and 'prove' in str(content):
                        return content
                    else:
                        msg = "response is error."
    except Exception as e:
        msg = str(e)
        if "release" in msg:
            msg = 'timeout'
    log.error(f"Error api request, url: {url}, error: {msg}")
    return None


async def get_addons_file_info(addon_path, id=""):
    """请求脚本信息"""
    if 'agent' in MAIN_NAME:
        api_url = conf.agent.api_url
        proxy = conf.agent.api_proxy
    elif 'support' in MAIN_NAME:
        api_url = conf.support.api_url
        proxy = conf.support.api_proxy
    elif 'simple' in MAIN_NAME:
        api_url = conf.simple.api_url
        proxy = conf.simple.api_proxy
    else:
        api_url = conf.server.api_url
        proxy = conf.server.api_proxy

    url = api_url + "/api/addon/list?t=" + str(int(get_timestamp()))
    user_agent = conf.basic.user_agent
    headers = {
        'API-Key': id,
        'User-Agent': user_agent
    }
    json_dic = {"addon_path": addon_path}

    msg = "response is null."
    try:
        async with ClientSession(None) as session:
            async with session.post(url, json=json_dic, headers=headers, proxy=proxy, allow_redirects=False, ) as res:
                if res and res.status == 200 and 'json' in res.headers.get("Content-Type", ""):
                    text = await res.text()
                    if text:
                        data_json = json.loads(text)
                        if data_json.get("status", 0) == ApiStatus.SUCCESS["status"]:
                            recode_list = data_json.get("data", {}).get("res", [])
                            return recode_list
                    else:
                        msg = "response is error."
    except Exception as e:
        msg = str(e)
        if "release" in msg:
            msg = 'timeout'
    log.error(f"Error api request, url: {url}, error: {msg}")
    return []

async def get_dnslog_recode(domain=None):

    dnslog_api_func = conf.platform.dnslog_api_func
    if dnslog_api_func == 'eyes':
        return await get_dnslog_recode_by_eyes(domain)
    elif dnslog_api_func == 'interactsh':
        return await get_dnslog_recode_by_interactsh(domain)
    elif dnslog_api_func == 'celestion':
        return await get_dnslog_recode_by_celestion(domain)
    else:
        return await get_dnslog_recode_by_interactsh(domain)

async def get_dnslog_recode_by_interactsh(domain=None):
    dnslog_list = []
    if domain is None:
        recode_list = await interactsh_client.poll()
        for recode in recode_list:
            recode_domain = recode.get("full-id", None)
            if recode_domain:
                recode_domain += '.' + interactsh_client.server
            recode_ip = recode.get("remote-address", None)

            time_str = recode.get("timestamp", "2023-08-16T13:40:19.412962501Z")
            if '.' in time_str:
                time_str = time_str.split('.')[0]
            recode_time = get_time_by_str(time_str, fmt="%Y-%m-%dT%H:%M:%S")
            old_time = get_time(get_timestamp() - 36 * 60 * 60)
            if recode_time > old_time and len(recode_domain) > 16 + len(conf.platform.dnslog_top_domain):
                dnslog = await query_dnslog_by_keyword(recode_domain)
                if dnslog is None:
                    dnslog = dict(keyword=recode_domain, ip=recode_ip, create_time=recode_time, update_time=get_time())
                    if await inject_dnslog(dnslog):
                        dnslog_list.append(dnslog)
    return dnslog_list


async def get_dnslog_recode_by_celestion(domain=None):
    """请求dnslog recode"""

    url = conf.platform.dnslog_api_url
    api_key = conf.platform.dnslog_api_key
    user_agent = conf.basic.user_agent

    headers = {'API-Key': api_key, 'Content-Type': "application/json", 'User-Agent': user_agent}
    if domain is None:
        domain = conf.platform.dnslog_top_domain
    data = {"domain": domain, "ip": "", "per_page": 10000, "page": 1}
    dnslog_list = []

    msg = "response is null."
    try:
        async with ClientSession(None) as session:
            async with session.post(url, json=data, headers=headers, allow_redirects=False) as res:
                if res and res.status == 200:
                    content = await res.text()
                    if content:
                        recode_list = json.loads(content).get("data", {}).get("res", [])
                        for recode in recode_list:
                            recode_domain = recode.get("domain", None)
                            recode_ip = recode.get("ip", None)
                            recode_time = get_time_by_str(recode.get("update_time", "1970-01-01 00:00:00"), fmt="%Y-%m-%d %H:%M:%S")
                            old_time = get_time(get_timestamp() - 24 * 60 * 60)
                            if recode_time > old_time and len(recode_domain) > 16 + 1 + len(conf.platform.dnslog_top_domain):
                                dnslog = await query_dnslog_by_keyword(recode_domain)
                                if dnslog is None:
                                    dnslog = dict(keyword=recode_domain, ip=recode_ip, create_time=recode_time, update_time=get_time())
                                    if await inject_dnslog(dnslog):
                                        dnslog_list.append(dnslog)
                        return dnslog_list
                    else:
                        msg = "response is error."
    except Exception as e:
        msg = str(e)
        if "release" in msg:
            msg = 'timeout'
    log.error(f"Error api request, url: {url}, error: {msg}")
    return dnslog_list


async def get_dnslog_recode_by_eyes(domain=None):
    """
    请求dnslog recode,eyes.sh
    """

    url = conf.platform.dnslog_api_url
    dnslog_top_domain = conf.platform.dnslog_top_domain
    api_key = conf.platform.dnslog_api_key
    user_agent = conf.basic.user_agent
    dnslog_list = []
    headers = {'API-Key': api_key, 'Content-Type': "application/json", 'User-Agent': user_agent}

    msg = "response is null."
    try:
        async with ClientSession(None) as session:
            async with session.get(url,  headers=headers, allow_redirects=False) as res:
                if res and res.status == 200:
                    content = await res.text()
                    if content:
                        recode_list = json.loads(content).get("data", [])
                        now_time = get_time()
                        if domain:
                            for recode in recode_list:
                                recode_domain = f'{recode}.{dnslog_top_domain}'
                                now_time = get_time()
                                if recode_domain == domain:
                                    dnslog = dict(keyword=recode_domain, ip=None, create_time=now_time, update_time=now_time)
                                    if await inject_dnslog(dnslog):
                                        dnslog_list.append(dnslog)
                        else:
                            for recode in recode_list:
                                recode_domain = f'{recode}.{dnslog_top_domain}'
                                dnslog = await query_dnslog_by_keyword(recode_domain)
                                if dnslog is None:
                                    dnslog = dict(keyword=recode_domain, ip=None, create_time=now_time, update_time=now_time)
                                    if await inject_dnslog(dnslog):
                                        dnslog_list.append(dnslog)
                        return dnslog_list
                    else:
                        msg = "response is error."
    except Exception as e:
        msg = str(e)
        if "release" in msg:
            msg = 'timeout'
    log.error(f"Error api request, url: {url}, error: {msg}")
    return dnslog_list