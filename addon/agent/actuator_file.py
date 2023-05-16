#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# @author: orleven

from mitmproxy.http import HTTPFlow
from lib.core.enums import AddonType
from lib.core.enums import VulType
from lib.core.enums import VulLevel
from addon.agent import AgentAddon
from lib.util.aiohttputil import ClientSession

class Addon(AgentAddon):
    """
    ActuratorFile
    """

    def __init__(self):
        AgentAddon.__init__(self)
        self.name = 'ActuratorFile'
        self.addon_type = AddonType.DIR_ALL
        self.vul_name = "Actuator接口文件"
        self.level = VulLevel.MEDIUM
        self.vul_type = VulType.INFO_FILE
        self.description = "网站存在Aactuator文件及接口，会泄露相关敏感信息。"
        self.scopen = ""
        self.impact = "1. 攻击者可以通过此类接口获取接口相关信息甚至获取服务器权限。"
        self.suggestions = "1. 对敏感文件进行访问权限控制或者删除处理。"
        self.scopen = ""
        self.mark = ""

        self.dir_list = [
            "",
            "api/",
            "actuator/",
            ";/actuator/",
            "api/actuator/",
            "api/;/actuator/",
            "v2/",
            "v1/",
            "web/",
            "swagger/",
            "gateway/actuator/",
            "..;/"
            # "%61%63%74%75%61%74%6f%72/",  # aiohttp 目前版本户会自动解码url编码
        ]
        self.file_dic = {
            "consul": "servicestags",
            "swagger-ui.html": 'swaggerui',
            "swagger.json": "\"swagger\"",
            "metrics": "\"names\"",
            "info": "\"names\"",
            "env": "spring",
            "routes": "\"route_",
            "mappings": "springframework",
            "loggers": "\"configuredLevel\":\"INFO\"",
            "hystrix.stream": "hystrixcommand",
            "auditevents": "\"events\":",
            "httptrace": "\"headers\":{",
            "features": "springframework",
            "caches": "cachemanagers",
            "beans": "springframework",
            "conditions": "springframework",
            "configprops": "spring",
            "threaddump": "springframework",
            "scheduledtasks": "\"cron\":",
            "api-docs": "\"swagger\"",
            "mappings.json": "{\"bean\":",
            "trace": "\"headers\":{",
            "dump": "threadname",
            "gateway/routes": "\"predicate\":",
            "gateway/globalfilters": "cloud.gateway.filter",
            "gateway/routefilters": "gatewayfilter",
        }

    async def prove(self, flow: HTTPFlow):
        url_no_query = self.get_url_no_query(flow)
        method = self.get_method(flow)
        if method in ['GET']:
            if url_no_query[-1] == '/':
                async with ClientSession(self.addon_path) as session:
                    headers = self.get_request_headers(flow)
                    for dir_path in self.dir_list:
                        for file_path, file_keyword in self.file_dic.items():
                            url = url_no_query + dir_path + file_path
                            async with session.get(url=url, headers=headers, allow_redirects=False) as res:
                                if res and res.status == 200:
                                    text = await res.text()
                                    if text and file_keyword in text.lower():
                                        detail = text
                                        await self.save_vul(res, detail)

                        url = url_no_query + dir_path + "heapdump"
                        async with session.head(url=url, headers=headers, allow_redirects=False) as res:
                            if res and res.status == 200:
                                if res.headers.get("Content-Type", "text/html") == "application/octet-stream" and res.content_length > 1024 * 1024 * 4:
                                    detail = "Content-Type: " + str(res.content_length)
                                    await self.save_vul(res, detail)
