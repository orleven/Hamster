#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
import asyncio
from lib.core.g import log
from lib.core.g import conf
from lib.core.g import agent_log
from lib.core.g import cache_log
from lib.core.g import manager_log
from lib.core.enums import CustomLogging
from lib.engine.master.servermaster import ServerMaster
from lib.engine.master.simplemaster import SimpleMaster
from lib.engine.master.supportmaster import SupportMaster
from lib.engine.manager.webmanager import WebManager
from lib.engine.agent.vulagent import VulAgent


def handle_options(args):
    """参数解析与配置"""

    if hasattr(args, "listen_host") and args.listen_host:
        conf.server.listen_host = args.listen_host
        conf.support.listen_host = args.listen_host
        conf.manager.listen_host = args.listen_host
        conf.simple.listen_host = args.listen_host

    if hasattr(args, "listen_port") and args.listen_port:
        conf.server.listen_port = args.listen_port
        conf.support.listen_port = args.listen_port
        conf.manager.listen_port = args.listen_port
        conf.simple.listen_port = args.listen_port

    if hasattr(args, "support_host") and args.support_host:
        conf.agent.support_host = args.support_host

    if hasattr(args, "support_port") and args.support_port:
        conf.agent.support_port = args.support_port

    if hasattr(args, "server_host") and args.server_host:
        conf.agent.server_host = args.server_host
        conf.support.server_host = args.server_host
        conf.simple.server_host = args.server_host

    if hasattr(args, "server_port") and args.server_port:
        conf.agent.server_port = args.server_port
        conf.support.server_port = args.server_port
        conf.simple.server_port = args.server_port

    if hasattr(args, "test") and args.test:
        conf.scan.test = True
    else:
        conf.scan.test = False

    # support 代理
    conf.agent.support_proxy = f"{conf.basic.proxy_mode}://{conf.basic.proxy_auth}@{conf.agent.support_host}:{conf.agent.support_port}"
    conf.support.support_proxy = f"{conf.basic.proxy_mode}://{conf.basic.proxy_auth}@{conf.support.support_host}:{conf.support.support_port}"

    # server api接口
    conf.agent.api_url = f"http://{conf.basic.listen_domain}:80{PREFIX_URL}"
    conf.agent.api_proxy = f"{conf.basic.proxy_mode}://{conf.basic.proxy_auth}@{conf.agent.server_host}:{conf.agent.server_port}"
    conf.support.api_url = f"http://{conf.basic.listen_domain}:80{PREFIX_URL}"
    conf.support.api_proxy = f"{conf.basic.proxy_mode}://{conf.basic.proxy_auth}@{conf.support.server_host}:{conf.support.server_port}"
    conf.simple.api_url = f"http://{conf.basic.listen_domain}:80{PREFIX_URL}"
    conf.simple.api_proxy = f"{conf.basic.proxy_mode}://{conf.basic.proxy_auth}@{conf.simple.listen_host}:{conf.simple.listen_port}"
    conf.server.api_url = f"http://{conf.basic.listen_domain}:80{PREFIX_URL}"
    conf.server.api_proxy = f"{conf.basic.proxy_mode}://{conf.basic.proxy_auth}@{conf.server.listen_host}:{conf.server.listen_port}"

    # 配置代理模式
    if "upstream" not in conf.basic.proxy_mode:
        conf.basic.proxy_mode = "socks5" if conf.basic.proxy_mode == "socks5" else "regular"

    # 补充黑白名单/字典配置
    conf.scan.scan_black = []
    conf.scan.scan_white = []
    conf.scan.scan_time = []
    conf.scan.dict_username = []
    conf.scan.dict_password = []
    conf.scan.vul_filter = []

    # debug 模式
    conf.basic.debug = args.debug
    conf.basic.ssl_insecure = True
    conf.basic.addon_async = True

    if conf.basic.debug:
        log_level = CustomLogging.DEBUG
        log.set_level(log_level)
        cache_log.set_level(log_level)
        agent_log.set_level(log_level)
        manager_log.set_level(log_level)
        log.debug(f"Setting {PROJECT_NAME} debug mode...")


async def run_server():
    """开启server端"""

    ms = None

    try:
        log.info(f"Initing {PROJECT_NAME} server...")
        ms = ServerMaster()

        ms.hook()

        log.info(f"Starting {PROJECT_NAME} server at {conf.server.listen_host}:{conf.server.listen_port}...")
        await ms.run()
    except KeyboardInterrupt:
        ms.shutdown()
        log.info(f"Ctrl C - stopping {PROJECT_NAME} server!")
    except Exception as e:
        log.critical(f"Error run, error: {str(e)}")


async def run_support():
    """开启support端"""

    ms = None

    try:
        log.info(f"Initing {PROJECT_NAME} support...")
        ms = SupportMaster()

        ms.hook()

        log.info(f"Starting {PROJECT_NAME} support at {conf.support.listen_host}:{conf.support.listen_port}...")
        await ms.run()
    except KeyboardInterrupt:
        ms.shutdown()
        log.info(f"Ctrl C - stopping {PROJECT_NAME} support!")
    except Exception as e:
        log.critical(f"Error run, error: {str(e)}")


async def run_simple():
    """开启simple端"""

    ms = None

    try:
        log.info(f"Initing {PROJECT_NAME} simple...")
        ms = SimpleMaster()

        ms.hook()

        log.info(f"Starting {PROJECT_NAME} simple at {conf.simple.listen_host}:{conf.simple.listen_port}...")
        await ms.run()
    except KeyboardInterrupt:
        ms.shutdown()
        log.info(f"Ctrl C - stopping {PROJECT_NAME} simple!")
    except Exception as e:
        log.critical(f"Error run, error: {str(e)}")


def start_server(args):
    """开启server端"""

    handle_options(args)
    asyncio.run(run_server())


def start_simple(args):
    """开启simple端"""

    handle_options(args)
    asyncio.run(run_simple())

def start_support(args):
    """开启support端"""

    handle_options(args)
    asyncio.run(run_support())


def start_agent(args):
    """开启agent端"""

    handle_options(args)

    log.info(f"Initing {PROJECT_NAME} agent...")
    ms = VulAgent()

    try:
        log.info(f"Starting {PROJECT_NAME} agent...")
        ms.run()
    except KeyboardInterrupt:
        log.info(f"Ctrl C - stopping {PROJECT_NAME} agent!")
    except Exception as e:
        log.critical(f"Error run, error: {str(e)}")


def start_manager(args):
    """开启manager端"""

    handle_options(args)

    log.info(f"Initing {PROJECT_NAME} manager...")
    ms = WebManager()

    try:
        log.info(f"Starting {PROJECT_NAME} manager at {conf.manager.listen_host}:{conf.manager.listen_port}...")
        ms.run()
    except KeyboardInterrupt:
        log.info(f"Ctrl C - stopping {PROJECT_NAME} manager!")
    except Exception as e:
        log.critical(f"Error run, error: {str(e)}")

