#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from lib.core.env import *
import asyncio
from mitmproxy import version
from mitmproxy.master import Master
from mitmproxy.addons import disable_h2c
from mitmproxy.addons import next_layer
from mitmproxy.addons import proxyserver
from mitmproxy.addons import proxyauth
from mitmproxy.addons import tlsconfig
from mitmproxy.addons import anticache
from mitmproxy.addons import upstream_auth
from lib.core.g import log
from lib.core.g import conf
from lib.engine import BaseEngine
from lib.core.enums import EngineStatus
from lib.core.enums import EngineType
from lib.util.util import get_time
from lib.util.util import get_time_by_str
from lib.util.util import get_timestamp
from lib.util.util import get_host_ip
from lib.util.addonutil import import_addon_file

proxyauth.REALM = VERSION_STRING
version.MITMPROXY = VERSION_STRING


class BaseMaster(BaseEngine, Master):
    """被动代理核心模块，调用mitmproxy master模块，开启代理监听服务"""

    def __init__(self):
        super().__init__(opts=None)

        # Engine 属性
        self.engine_type = EngineType.BASE_MASTER
        self.id = f'{HOSTNAME}_{self.engine_type}'
        self.ip = get_host_ip()
        self.status = EngineStatus.OK

        # 属性初始化
        self.addon_list = []
        self.addon_top_path_list = []
        self.remaining = 0
        self.scanning = 0
        self.scan_max_task_num = conf.scan.scan_max_task_num
        self.queue_num = 0
        self.max_data_queue_num = conf.basic.max_data_queue_num

        # 加载默认addon
        self.addons.add(*self.default_addons())

        # 加载配置
        self.options.ssl_insecure = conf.basic.ssl_insecure
        self.options.mode = conf.basic.proxy_mode
        self.options.proxyauth = conf.basic.proxy_auth
        self.options.anticache = conf.basic.anticache
        # self.options.stream_large_bodies = conf.basic.stream_large_bodies
        # self.options.body_size_limit = conf.basic.body_size_limit
        self.addon_async = conf.basic.addon_async


    def default_addons(self):
        """默认加载addon"""
        return [
            disable_h2c.DisableH2C(),
            proxyauth.ProxyAuth(),
            proxyserver.Proxyserver(),
            next_layer.NextLayer(),
            tlsconfig.TlsConfig(),
            upstream_auth.UpstreamAuth(),
            anticache.AntiCache(),
        ]

    def print_status(self):
        """打印状态"""

        log.info(f"Engine: {self.id}, Status: {self.status}")

    def configure_addons(self):
        """配置addon"""

        log.debug(f"Configure addons...")
        addon_list = []
        for addon_top_path in self.addon_top_path_list:
            addon_list += import_addon_file(addon_top_path)
        flag = False
        for addon in addon_list:
            addon_path = addon.info().get("addon_path", "")
            try:
                _addon = self.addons.get(addon.name)
                if _addon:
                    if _addon.info().get("addon_md5", "") != addon.info().get("addon_md5", ""):
                        flag = True
                else:
                    self.addons.add(addon)
                    self.addon_list.append(addon)
            except Exception as e:
                log.error(f"Error configure addon, addon: {addon_path}, error: {str(e)}")
        if flag:
            for addon in addon_list:
                self.addons.remove(self.addons.get(addon.name))
                self.addons.add(addon)
            self.addon_list = addon_list

    def hook(self):
        """运行相关伴随线程"""

        # 加载配置
        self.configure_addons()

        # 启动心跳
        asyncio.ensure_future(self.heartbeat())

# 修改代理失败的返回包
import html
import textwrap
from mitmproxy.http import Headers
from mitmproxy.http import Response
from mitmproxy.net.http.http1 import assemble_response
from mitmproxy.proxy.layers import http
def format_error(status_code: int, message: str) -> bytes:
    reason = http.status_codes.RESPONSES.get(status_code, "Unknown")
    return textwrap.dedent(f"""
    <html>
    <head>
        <title>{status_code} {reason}</title>
    </head>
    <body>
        <h1>{status_code} {reason}</h1>
        <p>{html.escape(message)}</p>
    </body>
    </html>
    """).strip().encode("utf8", "replace")

def make_error_response(status_code: int, message: str = "") -> bytes:
    resp = Response.make(
        status_code,
        format_error(status_code, message),
        Headers(
            Server=VERSION_STRING,
            Connection="close",
            Content_Type="text/html",
        )
    )
    return assemble_response(resp)
http._http1.make_error_response = make_error_response